#!/usr/bin/python
# -*- coding: utf-8 -*-

# thumbor imaging service
# https://github.com/globocom/thumbor/wiki

# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license
# Copyright (c) 2011 globo.com timehome@corp.globo.com
import logging
from thumbor.handlers.favicon import FaviconHandler
from tornado.web import *
from tornado.web import _UIModuleNamespace
from thumbor.handlers.blacklist import BlacklistHandler
from thumbor.handlers.healthcheck import HealthcheckHandler
from thumbor.handlers.legacy_upload import LegacyImageUploadHandler
from thumbor.handlers.upload import ImageUploadHandler
from thumbor.handlers.image_resource import ImageResourceHandler
from thumbor.url import Url
from thumbor.handlers.imaging import ImagingHandler
from Crypto.Cipher import AES


START_INDEX_WITH_NEED_DECODE_URI = 30
END_INDEX_WITH_NEED_DECODE_URI = -4


class ThumborServiceApp(tornado.web.Application):

    def __init__(self, context):
        self.context = context
        super(ThumborServiceApp, self).__init__(self.get_handlers())

    def get_handlers(self):
        handlers = [
            (r'/', HealthcheckHandler),
            (r'/favicon.ico', FaviconHandler),
        ]

        if self.context.config.UPLOAD_ENABLED:
            # TODO: Old handler to upload images. Will be deprecated soon.
            handlers.append(
                (r'/upload', LegacyImageUploadHandler, {'context': self.context})
            )

            # Handler to upload images (POST).
            handlers.append(
                (r'/image', ImageUploadHandler, {'context': self.context})
            )

            # Handler to retrieve or modify existing images  (GET, PUT, DELETE)
            handlers.append(
                (r'/image/(.*)', ImageResourceHandler, {'context': self.context})
            )

        if self.context.config.USE_BLACKLIST:
            handlers.append(
                (r'/blacklist', BlacklistHandler, {'context': self.context})
            )

        # Imaging handler (GET)
        handlers.append(
            (Url.regex(), ImagingHandlerMine, {'context': self.context})
        )

        return handlers


class ImagingHandlerMine(ImagingHandler):

    def __init__(self, application, request, **kwargs):

        super(RequestHandler, self).__init__()

        self.application = application
        self.request = request
        self._headers_written = False
        self._finished = False
        self._auto_finish = True
        self._transforms = None  # will be set in _execute
        self._prepared_future = None
        self.path_args = None
        self.path_kwargs = None
        self.ui = ObjectDict((n, self._ui_method(m)) for n, m in
                             application.ui_methods.items())
        self.ui["_tt_modules"] = _UIModuleNamespace(self,
                                                    application.ui_modules)
        self.ui["modules"] = self.ui["_tt_modules"]
        self.clear()
        self.request.connection.set_close_callback(self.on_connection_close)
        self.initialize(**kwargs)

        self.cipher = AES.new((self.context.server.security_key * 32)[:32])
        try:
            self.request.uri = decode_uri(self.request.uri, self.cipher, is_encrypted=True)
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(u"InitError: %s" % str(e))

    @tornado.web.asynchronous
    def get(self, **kw):
        hash = kw['hash']
        url = kw['image']
        unsafe = kw['unsafe']

        try:
            decrypted = decode_uri(url, self.cipher, is_decrypted=True)
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(u"GetError: %s" % str(e))
            return self.check_image(kw)
        kwargs = Url.parse_decrypted(decrypted)
        kwargs['hash'] = hash
        kwargs['unsafe'] = unsafe

        crop = kwargs.pop("crop", {})
        kwargs.update({"crop_{0}".format(key): crop[key] for key in ["bottom", "left", "right", "top"] if crop.has_key(key)})
        self.check_image(kwargs)


def decode_uri(uri, cipher, is_encrypted=False, is_decrypted=False):
    if is_encrypted:
        encrypted = uri[START_INDEX_WITH_NEED_DECODE_URI:END_INDEX_WITH_NEED_DECODE_URI]
    else:
        encrypted = uri[:END_INDEX_WITH_NEED_DECODE_URI]
    debased = base64.urlsafe_b64decode(unicode(encrypted).encode("utf-8"))
    decrypted = cipher.decrypt(debased).rstrip('$')
    if is_decrypted:
        return decrypted
    return u"%s%s" % (uri[:START_INDEX_WITH_NEED_DECODE_URI], decrypted)
