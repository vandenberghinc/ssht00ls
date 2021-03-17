#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes.aliases import aliases
from ssht00ls.classes.ssh.tunnel import Tunnel
import ssht00ls.classes.ssh.utils as ssh_utils 

# the ssh object class.
class SSH(Traceback):
	def __init__(self,
		# initialize as specific not global (optional).
		# 	the alias.
		alias=None,
	):


		# docs.
		DOCS = {
			"module":"ssht00ls.ssh", 
			"initialized":True,
			"description":[], 
			"chapter": "Protocols", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.ssh", raw_traceback="ssht00ls.classes.ssh.SSH")	

		# modules.
		self.utils = ssh_utils

		# objects.
		self.tunnel = Tunnel(
			alias=alias,)

		# specific args.
		self.specific = alias != None
		self.alias = alias

		#
	def session(self, 
		alias=None,
	):

		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# checks.
		response = dev0s.response.parameters.check(
			traceback=self.__traceback__(function="session"),
			parameters={
				"alias":alias,
			})
		if not response.success: return response

		# session.
		os.system(f"ssh {DEFAULT_SSH_OPTIONS} {alias}")

		# handler.
		return dev0s.response.success(f"Successfully started ssh session [{alias}].")

		#
	def command(self,
		# Alias:
		#   the alias.
		alias=None,
		# 
		# Command:
		#   the command in str.
		command="ls",
		#
		# Options:
		#   asynchronous process.
		async_=False,
		#	await asynchronous child (sync process always awaits).
		wait=False,
		#	kill process when finished (async that is not awaited is never killed).
		kill=True,
		#   the subprocess shell parameter.
		shell=False,
		#   serialize output to dict (expect literal dictionary / json output).
		serialize=False,
		# accept new host keys.
		accept_new_host_keys=True,
		#
		# Input (sync only):
		#   send input to the command.
		#	  undefined: send no input & automatically await the process since input is always sync.
		#	  dict instance: selects "and" mode ; send expected inputs and their value & return error when one of them is missing.
		#	  list[dict] instance: send all dictionaries in the list (default dict behaviour so one of the keys in each dict is expected).
		input=None,
		#   the input timeout (float) (list with floats by index from input)
		timeout=2.0,
		#   do not throw an error when the input is missing or not expected when optional is disabled (bool).
		optional=False, 
		#	apped default accept host keys input.
		append_default_input=True,
		#
		# Logging.
		# the success message (leave None to use the default).
		message=None,
		#   loader message.
		loader=None,
		#   the log level.
		log_level=dev0s.defaults.log_level(default=0),
		#
		# System functions.
		#   add additional attributes to the spawn object.
		__spawn_attributes__={},
	):
		
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# parse alias.
		response = aliases.info(alias=alias)
		if not response.success: return response
		info = response.info

		# add __spawn_attributes__.
		for key,value in {
			"alias":alias,
			"ip":info["ip"],
			"port":info["port"],
		}.items():
			try: __spawn_attributes__[str(key)]
			except KeyError: __spawn_attributes__[str(key)] = value

		# checks.
		response = dev0s.response.parameters.check(
			traceback=self.__traceback__(function="command"),
			parameters={
				"alias":alias,
				"command":command,
			})
		if not response.success: return response

		# command.
		response = self.utils.execute(
			command=f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ' {command} ' """,
			async_=async_,
			wait=wait,
			kill=kill,
			shell=shell,
			serialize=serialize,
			accept_new_host_keys=accept_new_host_keys,
			input=input,
			timeout=timeout,
			optional=optional,
			message=message,
			loader=loader,
			log_level=log_level,)

		# handler.
		if log_level >= 1:
			if response.success: print(response.output)
			else: print(response.error)
		return response
	
		
# initialized objects.
ssh = SSH()