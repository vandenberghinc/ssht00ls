#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils

# the ssh connections object class.
class Connections(Traceback):
	def __init__(self):
		
		# docs.
		DOCS = {
			"module":"ssht00ls.connections", 
			"initialized":True,
			"description":[], 
			"chapter": "Connections", }
			
		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.connections", raw_traceback="ssht00ls.classes.connections.Connections")

		#
	def list(self, filter="ssh"):
		if dev0s.defaults.vars.os not in ["linux"]:
			return dev0s.response.error(f"Unsupported operating system [{dev0s.defauls.vars.os}].")
		output = dev0s.utils.__execute_script__("""ss | grep ssh | awk '{print $1","$2","$3","$4","$5","$6}' """)
		connections = {}
		for line in output.split("\n"):
			if line not in [""]:
				net_id,state,recvq, sendq,local_address,remote_address = line.split(",")
				if state == "ESTAB":
					connections[remote_address] = {
						"remote_address":remote_address,
						"local_address":local_address,
						"recvq":recvq,
						"sendq":sendq,
						"net_id":net_id,
					}
		return dev0s.response.success(f"Successfully listed {len(connections)} ssh connection(s).", {
			"connections":connections,
		})

# Initialized objects.
connections = Connections()

