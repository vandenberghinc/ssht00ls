#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.smartcards import smartcards

# the sshfs object class.
class SSHFS(Traceback):
	def __init__(self,
	):

		# docs.
		DOCS = {
			"module":"ssht00ls.sshfs", 
			"initialized":True,
			"description":[], 
			"chapter": "Protocols", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.sshfs", raw_traceback="ssht00ls.classes.sshfs.SSHFS")	

		#
	def mount(self, 
		# the directory paths.
		remote=None, 
		path=None, 
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
		base = ""
		if alias == None:
			response = dev0s.response.parameters.check(
				traceback=self.__traceback__(function="mount"), 
				parameters={
					"username":username,
					"ip":ip,
					"remote":remote,
					"path":path,
					"key_path":key_path,
					"port":port,
				})
			if not response["success"]: return response
			base += f"sshfs -p {port} -o IdentityFile={key_path} {username}@{ip}"
		else:
			response = dev0s.response.parameters.check(
				traceback=self.__traceback__(function="mount"), 
				parameters={
					"alias":alias,
					"remote":remote,
					"path":path,
				})
			if not response["success"]: return response
			base += f'sshfs {alias}'

		# do.
		command = f'{base}:{remote} {path}'
		print(f"COMMAND: [{command}]")
		output = utils.__execute_script__(command)
		#output = utils.__execute__(base + [f'{alias}:{remote}', path])
		#output = utils.__execute_script__(utils.__array_to_string__(base + [f'{alias}:{remote}', path], joiner="\n"))

		# check fails.
		if "mount_osxfuse: mount point " in output and "is itself" in output:
			return dev0s.response.error(f"Client path [{path}] is already mounted.")
		elif "No such file or directory" in output:
			return dev0s.response.error(f"Server path [{remote}] does not exist.")
		elif "" == output:
			if not Files.exists(path):
				return dev0s.response.error(f"Could not connect with server [{alias}].")
			# check success.	
			else:
				return dev0s.response.success(f"Successfully mounted directory [{path}].")

		# unknown.
		else:
			l = f"Failed to mount directory [{path}]"
			return dev0s.response.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		
		#		
	def unmount(self, 
		# the client path.
		path=None, 
		# the forced umount option.
		forced=False, 
		# forced option may require sudo.
		sudo=False,
	):

		# checks.
		response = dev0s.response.parameters.check(
			traceback=self.__traceback__(function="unmount"),
			parameters={
				"path":path
			})
		if not response["success"]: return response
		command = []
		if sudo: command.append("sudo")
		command += ["umount"]
		if forced: command.append("-f")
		command += [path]
		output = utils.__execute__(command=command)
		if output != "":
			l = f"Failed to unmount directory [{path}]."
			return dev0s.response.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		else:
			return dev0s.response.success(f"Successfully unmounted directory [{path}].")
		#
	
# Initialized classes.
sshfs = SSHFS()

"""

# --------------------
# SSHFS.
sshfs = SSHFS()

# mount a remote server directory.
response = sshfs.mount(
	# the directory paths.
	remote="/path/to/directory/", 
	path="/path/to/directory/", 
	# the ssh params.
	alias="administrator.myserver",)
	
# or without a created alias.
response = sshfs.mount(
	# the directory paths.
	remote="/path/to/directory/", 
	path="/path/to/directory/", 
	# the ssh params.
	username="administrator", 
	ip="0.0.0.0", 
	port=22,
	key_path="/path/to/mykey/private_key",)

# unmount a mounted directory.
response = sshfs.unmount(
	path="/path/to/directory/", 
	forced=False,
	sudo=False,)

"""






