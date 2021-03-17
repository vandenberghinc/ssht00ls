#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.smartcards import smartcards

# the scp object class.
class SCP(Traceback):
	def __init__(self,
	):


		# docs.
		DOCS = {
			"module":"ssht00ls.scp", 
			"initialized":True,
			"description":[], 
			"chapter": "Protocols", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.scp", raw_traceback="ssht00ls.classes.scp.SCP")

		#
	def download(self, 
		# the file paths.
		server_path=None, 
		client_path=None,
		directory=False, 
		# the ssh params.
		# option 1:
		alias=None,
		# option 2:
		username=None, 
		ip=None, 
		port=22,
		key_path=None,
	):

		# checks.
		if alias == None:
			response = dev0s.response.parameters.check(default=None, parameters={
				"username":username,
				"ip":ip,
				"server_path":server_path,
				"client_path":client_path,
				"key_path":key_path,
				"port":port,
			}, traceback=self.__traceback__(function="download"))
			if not response["success"]: return response
		else:
			response = dev0s.response.parameters.check(default=None, parameters={
				"alias":alias,
				"server_path":server_path,
				"client_path":client_path,
			}, traceback=self.__traceback__(function="download"))
			if not response["success"]: return response

		# check client path.
		if Files.exists(client_path):
			return dev0s.response.error(f"Client path [{client_path}] already exists.")

		# do.
		command = self.__build__(
			alias=alias,
			port=port,
			key_path=key_path,)
		if directory: command += ["-r"]
		if alias == None: alias = f'{username}@{ip}'
		output = utils.__execute__(command + [f'{alias}:{server_path}', client_path], shell=False)
		#output = utils.__execute_script__(utils.__array_to_string__(command + [f'{alias}:{server_path}', client_path], joiner="\n"), shell=False)
		
		# check fails.
		if "No such file or directory" in output:
			return dev0s.response.error(f"Server path [{server_path}] does not exist.")
		elif "not a regular file" in output:
			return dev0s.response.error(f"Server path [{server_path}] is a directory.")
		elif "" == output:
			if not Files.exists(client_path):
				return dev0s.response.error(f"Failed to download [{server_path}].")
			# check success.	
			else:
				return dev0s.response.success(f"Successfully downloaded [{server_path}].")
		# unknown.
		else:
			l = f"Failed to download [{client_path}]"
			return dev0s.response.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		
		#
	def upload(self, 
		# the file paths.
		server_path=None, 
		client_path=None,
		directory=False, 
		# the ssh params.
		# option 1:
		alias=None,
		# option 2:
		username=None, 
		ip=None, 
		port=22,
		key_path=None,
	):

		# checks.
		if alias == None:
			response = dev0s.response.parameters.check(default=None, parameters={
				"username":username,
				"ip":ip,
				"server_path":server_path,
				"client_path":client_path,
				"key_path":key_path,
				"port":port,
			}, traceback=self.__traceback__(function="upload"))
			if not response["success"]: return response
		else:
			response = dev0s.response.parameters.check(default=None, parameters={
				"alias":alias,
				"server_path":server_path,
				"client_path":client_path,
			}, traceback=self.__traceback__(function="upload"))
			if not response["success"]: return response

		# check client path.
		if not Files.exists(client_path):
			return dev0s.response.error(f"Client path [{client_path}] does not exist.")

		# do.
		command = self.__build__(
			alias=alias,
			port=port,
			key_path=key_path,)
		if directory: command += ["-r"]
		if alias == None: alias = f'{username}@{ip}'
		output = utils.__execute__(command + [client_path, f'{alias}:{server_path}'], shell=False)
		#output = utils.__execute_script__(utils.__array_to_string__(command + [client_path, f'{alias}:{server_path}'], joiner="\n"), shell=False)

		# check fails.
		if "No such file or directory" in output:
			return dev0s.response.error(f"The base path [{FilePath(server_path).base()}] of the specified file does not exist on the server.")
		elif "not a regular file" in output:
			return dev0s.response.error(f"Client path [{client_path}] is a directory.")
		elif "" == output:
			return dev0s.response.success(f"Successfully uploaded [{client_path}].")
		# unknown.
		else:
			l = f"Failed to upload [{client_path}]"
			return dev0s.response.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		
		#
	# system functions.
	def __build__(self,
		# option 1:
		alias=None,
		# option 2:
		port=22,
		key_path=None,
	):	
		base = []
		if alias != None:
			return base + ['scp']
		else:
			base += ['scp']
			if key_path != None: base += ['-i', key_path,]
			if port != None: base += ['-P', port,]
			return base
	
# Initialized classes.
scp = SCP()


"""

# --------------------
# SCP.
scp = SCP()

# download a server file or directory from a server.
response = scp.download(
	# the file paths.
	server_path="/path/to/directory/", 
	client_path="/path/to/directory/",
	directory=True, 
	# the ssh params.
	username="administrator", 
	ip="0.0.0.0", 
	port=22,
	key_path="/path/to/mykey/private_key",)

# upload a file or directory to a server.
response = scp.upload(
	# the file paths.
	server_path="/path/to/directory/", 
	client_path="/path/to/directory/",
	directory=True, 
	# the ssh params.
	username="administrator", 
	ip="0.0.0.0", 
	port=22,
	key_path="/path/to/mykey/private_key",)


"""






