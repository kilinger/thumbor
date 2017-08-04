#!/usr/bin/python
# -*- coding: utf-8 -*-

# thumbor imaging service
# https://github.com/globocom/thumbor/wiki

# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license
# Copyright (c) 2011 globo.com timehome@corp.globo.com

import os
from thumbor.handlers import BaseHandler


class FaviconHandler(BaseHandler):
    def get(self):
        self.set_header("Content-Type", "image/vnd.microsoft.icon")
        path = os.path.split(os.path.realpath(__file__))[0] + "/../static/favicon.ico"
        with open(path, 'rb') as f:
            self.write(f.read())
        return self.flush()

    def head(self, *args, **kwargs):
        self.set_status(200)