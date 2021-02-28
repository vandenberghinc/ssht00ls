#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
import os
os.environ["SSHT00LS_WEBSERVER_IMPORT"] = "True"
from ssht00ls.classes.config import *
os.environ["SSHT00LS_WEBSERVER_IMPORT"] = "False"

# the ssync object class.
class WebServer(syst3m.cache.WebServer):
	def __init__(self):
		syst3m.cache.WebServer.__init__(self, serialized={
			"id":"ssht00ls-agent",
			"path":f"{DATABASE}/.cache/",
			"host":"127.0.0.1",
			"default":{},
			"port":52379,
		})
	# could be expanded.
