#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes.ssh.tunnel import Tunnel
import ssht00ls.classes.ssh.utils as ssh_utils 

# the ssh object class.
class SSH(syst3m.objects.Traceback):
	def __init__(self,
		# initialize as specific not global (optional).
		# 	the alias.
		alias=None,
	):

		# defaults.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.ssh", raw_traceback="ssht00ls.classes.ssh.SSH")	

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
		response = r3sponse.parameters.check(
			traceback=self.__traceback__(function="session"),
			parameters={
				"alias":alias,
			})
		if not response.success: return response

		# session.
		os.system(f"ssh {DEFAULT_SSH_OPTIONS} {alias}")

		# handler.
		return r3sponse.success(f"Successfully started ssh session [{alias}].")

		#
	def command(self,
		# Alias:
		#   the alias.
		alias=None,
		# 
		# Command:
		#   the command in str.
		command="ssh <alias> ' ls ' ",
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
		log_level=syst3m.defaults.log_level,
		#
		# System functions.
		#   add additional attributes to the spawn object.
		__spawn_attributes__={},

		# the command to execute.
		command=None,
		# serialize the output to json.
		serialize=False,
		# the log level.
		log_level=0,
		# accept new host keys.
		accept_new_host_keys=True,
	):
		
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# checks.
		response = r3sponse.parameters.check(
			traceback=self.__traceback__(function="command"),
			parameters={
				"alias":alias,
				"command":command,
			})
		if not response.success: return response

		# command.
		response = self.utils.execute(
			command=f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ' {command} ' """,
			log_level=log_level,
			serialize=serialize,
			accept_new_host_keys=accept_new_host_keys,)

		# handler.
		if log_level >= 0:
			if response.success: print(response.output)
			else: print(response.error)
		return response
	
		
# initialized objects.
ssh = SSH()