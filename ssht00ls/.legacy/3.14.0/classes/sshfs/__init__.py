#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.smartcards import smartcards

# the sshfs object class.
class SSHFS(object):
	def __init__(self):

		# variables.
		a = 1

		#
	def mount(self, 
		# the directory paths.
		server_path=None, 
		client_path=None, 
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
			response = r3sponse.check_parameters(empty_value=None, parameters={
				"username":username,
				"ip":ip,
				"server_path":server_path,
				"client_path":client_path,
				"key_path":key_path,
				"port":port,
			})
			if not response["success"]: return response
			base += f"sshfs -p {port} -o IdentityFile={key_path} {username}@{ip}"
		else:
			response = r3sponse.check_parameters(empty_value=None, parameters={
				"alias":alias,
				"server_path":server_path,
				"client_path":client_path,
			})
			if not response["success"]: return response
			base += f'sshfs {alias}'

		# do.
		command = f'{base}:{server_path} {client_path}'
		print(f"COMMAND: [{command}]")
		output = utils.__execute_script__(command)
		#output = utils.__execute__(base + [f'{alias}:{server_path}', client_path])
		#output = utils.__execute_script__(utils.__array_to_string__(base + [f'{alias}:{server_path}', client_path], joiner="\n"))

		# check fails.
		if "mount_osxfuse: mount point " in output and "is itself" in output:
			return r3sponse.error(f"Client path [{client_path}] is already mounted.")
		elif "No such file or directory" in output:
			return r3sponse.error(f"Server path [{server_path}] does not exist.")
		elif "" == output:
			if not Files.exists(client_path):
				return r3sponse.error(f"Could not connect with server [{alias}].")
			# check success.	
			else:
				return r3sponse.success(f"Successfully mounted directory [{client_path}].")

		# unknown.
		else:
			l = f"Failed to mount directory [{client_path}]"
			return r3sponse.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		
		#		
	def unmount(self, 
		# the client path.
		client_path=None, 
		# the forced umount option.
		forced=False, 
		# forced option may require sudo.
		sudo=False,
	):

		# checks.
		response = r3sponse.check_parameters(client_path, "client_path", None)
		if not response["success"]: return response
		command = []
		if sudo: command.append("sudo")
		command += ["umount"]
		if forced: command.append("-f")
		command += [client_path]
		output = utils.__execute__(command=command)
		if output != "":
			l = f"Failed to unmount directory [{client_path}]."
			return r3sponse.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		else:
			return r3sponse.success(f"Successfully unmounted directory [{client_path}].")
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
	server_path="/path/to/directory/", 
	client_path="/path/to/directory/", 
	# the ssh params.
	alias="administrator.myserver",)
	
# or without a created alias.
response = sshfs.mount(
	# the directory paths.
	server_path="/path/to/directory/", 
	client_path="/path/to/directory/", 
	# the ssh params.
	username="administrator", 
	ip="0.0.0.0", 
	port=22,
	key_path="/path/to/mykey/private_key",)

# unmount a mounted directory.
response = sshfs.unmount(
	client_path="/path/to/directory/", 
	forced=False,
	sudo=False,)

"""






