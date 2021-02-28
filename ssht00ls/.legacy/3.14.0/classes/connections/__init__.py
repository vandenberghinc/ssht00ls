#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils

# the ssh connections object class.
class Connections(object):
	def __init__(self):
		a=1
	def list(self, filter="ssh"):
		output = syst3m.utils.__execute_script__("""ss | grep ssh | awk '{print $1","$2","$3","$4","$5","$6}' """)
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
		return r3sponse.success(f"Successfully listed {len(connections)} ssh connection(s).", {
			"connections":connections,
		})

# Initialized objects.
connections = Connections()

