#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
import os
from fil3s import *
from r3sponse import r3sponse
from ssht00ls.classes.config import * 
from ssht00ls.classes.ssh import ssh
from ssht00ls.classes.ssync.index import index
from ssht00ls.classes.ssh.utils import execute

# settings.
INCLUDE = []# '.git', 'dist', "'*.egg-info'"
EXCLUDE = ['__pycache__', '.DS_Store']

# serialize path.
def serialize_path(path, append_last_slash=False):
	# keep in mind the file is saved by python and then executed.
	array = []
	for i in [" ","!","?","@","#","$","&","(",")","[","]","{","}"]:
		array.append([i, f"\\{i}"],)
	for x,y in array+[
		#[" ", "\\ "],
	]:
		path = path.replace(x,y)
	while True:
		if append_last_slash and len(path) > 0 and path[len(path)-1] != "/": path = path+"/"
		else: break
	return path

# get the size of a dir.
def size(path, alias=None, log_level=0):
	if alias == None:
		return r3sponse.success(f"Successfully retrieved the size of {path}.", {
			"size":FilePath(path).size(mode="MB"),
		})
	else:
		return execute(
			command=f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ' python3 /usr/local/lib/ssht00ls/classes/utils/size.py {path} ' '""",
			message=f"Successfully retrieved the size of {alias}:{path}.",
			error=f"Failed to retrieve the size of {alias}:{path}.",
			log_level=log_level,
			serialize=True,)

# pull.
def pull(
	# the local path.
	path=None, 
	# the ssht00ls alias.
	alias=None, 
	# the remote path.
	remote=None, 
	# exlude subpaths (list) (leave None to use default).
	exclude=None,
	# include subpaths (list) (leave None to use default).
	include=None,
	# path is directory boolean (leave None to parse automatically).
	directory=True,
	empty_directory=False,
	# update deleted files.
	delete=False,
	# forced mode.
	forced=False,
	# version control.
	safe=False,
	# accept new hosts keys.
	accept_new_host_keys=True,
	# checks.
	checks=True,
	# log level.
	log_level=syst3m.defaults.options.log_level,
	# get the command in str.
	command=False,
):	
	# checks.
	if exclude == None: exclude = EXCLUDE
	if include == None: include = INCLUDE
	if checks:

		# check alias.
		path = serialize_path(gfp.clean(path))
		remote = serialize_path(gfp.clean(remote))
		#response = aliases.check(alias)
		#if not response.success: return response
		
		# check encryption activated.
		#if not encryption.activated:
		#	return r3sponse.error("The encryption requires to be activated.")

		# check passphrase.
		#if CONFIG["aliases"][alias]["smartcard"] in [True, "true", "True"]:
		#	response = encryption.encryption.decrypt(CONFIG["aliases"][alias]["passphrase"])
		#else:
		#	response = encryption.encryption.decrypt(CONFIG["aliases"][alias]["passphrase"])
		#if not response.success: return response
		#passphrase = response.decrypted.decode()
		
		# tests.
		#response = agent.add(private_key=CONFIG["aliases"][alias]["private_key"], passphrase=passphrase)
		#if not response["success"]: return response
		response = ssh.utils.test_ssht00ls(alias=alias, accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response
		response = ssh.utils.test_path(alias=alias, path=remote, accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response

		# dir.
		if directory == None: 
			response = ssh.utils.test_dir(alias=alias, path=remote, accept_new_host_keys=accept_new_host_keys)
			if not response.success and "not a directory" not in response.error: return response
			elif response.success:
				directory = True
			else: directory = False
			tested = True
		elif directory:
			response = ssh.utils.test_dir(alias=alias, path=remote, accept_new_host_keys=accept_new_host_keys)
			if not response.success: return response
			tested = True

	# check base.
	base = FilePath(path).base(back=1)
	if not Files.exists(base): 
		os.system(f"mkdir -p {base}")
		if not Files.exists(base): 
			return r3sponse.error(f"Failed to create pull base {base}.")
		if log_level >= 3:
			print(f"Created directory {base}.")

	# fix rsync timestamp bug.
	if empty_directory and directory and not Files.exists(path):
		os.system(f"mkdir -p {path}")

	# options.
	exclude_str = Array(array=exclude).string(joiner=" --exclude ", sum_first=True)
	include_str = Array(array=include).string(joiner=" --include ", sum_first=True)
	delete_str = Boolean(delete).convert(true="--delete", false="")
	lremote = serialize_path(gfp.clean(remote), append_last_slash=directory)
	lpath = serialize_path(gfp.clean(path), append_last_slash=directory)
	_command_ = f"rsync -{Boolean(directory).convert(true='a', false='')}zqt '{alias}:{lremote}' '{lpath}' {exclude_str} {include_str} {delete_str} --timeout={SSH_TIMEOUT}"
	#_command_ = f"rsync -azqtr '{alias}:{lremote}' '{lpath}' {exclude_str} {include_str} {delete_str}"

	# execute.
	if command: return _command_
	else:
		return execute(
			command=_command_,
			message=f"Successfully pulled [{alias}:{remote}] to [{path}].",
			error=f"Failed to pull [{alias}:{remote}] to [{path}].",
			loader=f"Pulling [{alias}:{remote}] to [{path}]",
			log_level=log_level,
		)

	#

# push.
def push(
	# the local path.
	path=None, 
	# the ssht00ls alias.
	alias=None, 
	# the remote path.
	remote=None, 
	# exlude subpaths (list) (leave None to use default).
	exclude=None,
	# include subpaths (list) (leave None to use default).
	include=None,
	# path is directory boolean (leave None to parse automatically).
	directory=True,
	empty_directory=False,
	# update deleted files.
	delete=False,
	# forced mode.
	forced=False,
	# version control.
	safe=False,
	# accept new hosts keys.
	accept_new_host_keys=True,
	# checks.
	checks=True,
	check_base=True,
	# log level.
	log_level=syst3m.defaults.options.log_level,
	# get the command in str.
	command=False,
):
	# checks.
	if exclude == None: exclude = EXCLUDE
	if include == None: include = INCLUDE
	if checks:

		# check alias.
		path = serialize_path(gfp.clean(path))
		remote = serialize_path(gfp.clean(remote))
		#response = aliases.check(alias)
		#if not response.success: return response
		
		# check encryption activated.
		#if not encryption.activated:
		#	return r3sponse.error("The encryption requires to be activated.")
		
		# check passphrase.
		#if CONFIG["aliases"][alias]["smartcard"] in [True, "true", "True"]:
		#	response = encrypion.encryption.decrypt(CONFIG["aliases"][alias]["passphrase"])
		#else:
		#	response = encrypion.encryption.decrypt(CONFIG["aliases"][alias]["passphrase"])
		#if not response.success: return response
		#passphrase = response.decrypted.decode()
		
		# tests.
		#response = agent.add(private_key=CONFIG["aliases"][alias]["private_key"], passphrase=passphrase)
		#if not response["success"]: return response
		response = ssh.utils.test_ssht00ls(alias=alias, accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response
		response = ssh.utils.test_path(alias=alias, path=FilePath(remote).base(), accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response

		# dir.
		if directory == None: directory = os.path.isdir(path)
		elif directory and not os.path.isdir(path):
			return r3sponse.error(f"Path {path} is not a directory.")

	# check remote base.
	# must be excluded from the checks == False.
	base = FilePath(remote).base(back=1)
	if check_base:
		response = ssh.utils.test_dir(alias=alias, path=base, accept_new_host_keys=accept_new_host_keys, create=True, checks=False)
		if not response.success: return response
		if response.created and log_level >= 3: print(f"Created remote directory {base}.")

	# options.
	exclude_str = Array(array=exclude).string(joiner=" --exclude ", sum_first=True)
	include_str = Array(array=include).string(joiner=" --include ", sum_first=True)
	delete_str = Boolean(delete).convert(true="--delete", false="")
	lremote = serialize_path(gfp.clean(remote), append_last_slash=directory)
	lpath = serialize_path(gfp.clean(path), append_last_slash=directory)
	_command_ = f"rsync -{Boolean(directory).convert(true='a', false='')}zqt '{lpath}' '{alias}:{lremote}' {exclude_str} {include_str} {delete_str} --timeout={SSH_TIMEOUT}"
	#_command_ = f"rsync -azqtr --rsh=ssh '{lpath}' '{alias}:{lremote}' {exclude_str} {include_str} {delete_str}"
	
	# execute.
	if command: return _command_
	else:
		return execute(
			command=_command_,
			message=f"Successfully pushed [{path}] to [{alias}:{remote}].",
			error=f"Failed to push [{path}] to [{alias}:{remote}].",
			loader=f"Pushing [{path}] to [{alias}:{remote}].",
			log_level=log_level,
		)

	#

# main.
if __name__ == "__main__":
	a=1

#
	