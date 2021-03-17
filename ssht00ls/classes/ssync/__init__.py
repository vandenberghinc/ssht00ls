#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes.aliases import aliases
from ssht00ls.classes.agent import agent
import ssht00ls.classes.ssync.utils as ssync_utils 
from ssht00ls.classes.ssync import daemons
from ssht00ls.classes.ssh import ssh
from ssht00ls.classes import utils

# the ssync object class.
class SSync(Traceback):
	def __init__(self,
		# initialize as specific not global (optional).
		#	the username.
		alias=None,
	):

		# docs.
		DOCS = {
			"module":"ssht00ls.ssync", 
			"initialized":True,
			"description":[], 
			"chapter": "Protocols", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.ssync", raw_traceback="ssht00ls.classes.ssync.SSync")

		# specific args.
		self.specific = alias != None
		self.alias = alias

		# defaults.
		self.utils = ssync_utils
		self.daemons = daemons
		
		#
	def index(self, path=None, alias=None, log_level=dev0s.defaults.options.log_level, checks=True, accept_new_host_keys=True):

		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# checks.
		if path == None:
			return dev0s.response.error(f"Define parameter: path.")
		path = gfp.clean(path)

		# check encryption activated.
		if not ssht00ls_agent.activated:
			return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")

		# remote.
		if alias != None:

			# checks.
			if checks:
				
				# check alias.
				response = aliases.check(alias)
				if not response["success"]: return response

				# check passphrase.
				if CONFIG["aliases"][alias]["smartcard"] in [True, "true", "True"]:
					passphrase = CONFIG["aliases"][alias]["pin"]
				else:
					passphrase = CONFIG["aliases"][alias]["passphrase"]
				if passphrase not in ["", "none", "None", None]:
					response = ssht00ls_agent.encryption.decrypt()
					if not response["success"]: return response
					passphrase = response.decrypted.decode()
				else:
					passphrase = None
					
				# tests.
				response = agent.add(private_key=CONFIG["aliases"][alias]["private_key"], passphrase=passphrase)
				if not response["success"]: return response
				response = ssh.utils.test_ssht00ls(alias=alias, accept_new_host_keys=accept_new_host_keys)
				if not response["success"]: return response
				response = ssh.utils.test_path(alias=alias, path=path, accept_new_host_keys=accept_new_host_keys)
				if not response["success"]: return response

			# index.
			response = self.utils.execute(
				command=f"""printf 'yes' | ssh {DEFAULT_SSH_OPTIONS} {alias} ' export IPINFO_API_KEY="{IPINFO_API_KEY}" && python3 /usr/local/lib/ssht00ls/classes/ssync/index.py --path {path} --json --non-interactive --no-checks ' """,
				serialize=True,
				log_level=log_level,
				input={
					"Are you sure you want to continue connecting":Boolean(accept_new_host_keys).string(true="yes", false="no"),
				},
				optional=True,)
			if not response.success:
				return dev0s.response.error(f"Failed to connect with {alias}, error: {response.error}")
			else:
				return response

		# local.
		else:
			if checks:
				if not Files.exists(path):
					return dev0s.response.error(f"Path [{path}] does not exist.")
				elif not os.path.isdir(path):
					return dev0s.response.error(f"Path [{path}] is not a directory.")

			# handler.
			dict = self.utils.index(path)
			return dev0s.response.success(f"Successfully indexed {len(dict)} files from directory [{path}].", {
				"index":dict,
			})

			#
	def set_mounted_icon(self, path):
		if dev0s.defaults.vars.os in ["osx", "macos"]:
			#os.system(f"cp '{SOURCE_PATH}/static/media/icons/Icon\r' '{path}/Icon\r'")
			icon = f'{SOURCE_PATH}/static/media/icons/mounted.png'
			dev0s.utils.__execute_script__(f"""
				
				#!/bin/bash
				# Set Icon to a File / Folder on macOS

				icon="{icon}"
				dest="{path}"

				# Check inputs

				if [ ! -f $icon ]; then 
					echo "ERROR: File $1 does not exists"
					exit 1
				elif [[ ! $icon =~ .*\.(png|PNG|jpg|JPG) ]]; then
					echo "ERROR: Icon must be a .png|.jpg file"
					exit 1
				elif [ -f $dest ]; then
					folder=false
				elif [ -d $dest ]; then
					folder=true
				else
					echo 'ERROR: File|Folder destination does not exists'
					exit 1
				fi

				# Create icns icon

				sips -i $icon > /dev/null
				DeRez -only icns $icon > /tmp/tmpicns.rsrc

				# Set Icon

				if [ "$folder" = true ]; then
					Rez -append /tmp/tmpicns.rsrc -o $dest$'/Icon\r'
					SetFile -a C $dest
					SetFile -a V $dest$'/Icon\r'
				else
					Rez -append /tmp/tmpicns.rsrc -o $dest
					SetFile -a C $dest
				fi

				# Clean up

				rm /tmp/tmpicns.rsrc
				exit 0

				""")
	# pull & push.
	def pull(self,
		# the local path.
		path=None, 
		# the ssht00ls alias.
		alias=None, 
		# the remote path.
		remote=None, 
		# exlude subpaths (list) (leave None to exclude none).
		exclude=[],
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
		log_level=dev0s.defaults.options.log_level,
		# get the command in str.
		command=False,
	):	

		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# check encryption activated.
		if not ssht00ls_agent.activated:
			return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")
		if checks:
			if self.specific:
				try: self.activated
				except: self.activated = False
			if not self.specific or not self.activated:
				response = aliases.check(alias)
				if not response["success"]: return response
				response = agent.check(public_key=CONFIG["aliases"][alias]["public_key"])
				if not response.success:
					if "is not added to the" not in response.error: return response
					else:
						if CONFIG["aliases"][alias]["smartcard"] in [True, "true", "True"]:
							passphrase = CONFIG["aliases"][alias]["pin"]
						else:
							passphrase = CONFIG["aliases"][alias]["passphrase"]
						if passphrase not in [None, "None", "none", "", False]:
							response = ssht00ls_agent.encryption.decrypt(passphrase)
							if not response["success"]: return response
							passphrase = response.decrypted.decode()
						else:
							passphrase = None
						response = agent.add(private_key=CONFIG["aliases"][alias]["private_key"], passphrase=passphrase)
						if not response["success"]: return response
				if self.specific: self.activated = True
		return self.utils.pull(
			# the local path.
			path=path, 
			# the ssht00ls alias.
			alias=alias, 
			# the remote path.
			remote=remote, 
			# exlude subpaths (list) (leave None to use default).
			exclude=exclude,
			# path is directory boolean (leave None to parse automatically).
			directory=directory,
			empty_directory=empty_directory,
			# update deleted files.
			delete=delete,
			# forced mode.
			forced=forced,
			# version control.
			safe=safe,
			# accept new hosts keys.
			accept_new_host_keys=accept_new_host_keys,
			# checks.
			checks=checks,
			# log level.
			log_level=log_level,
			# get the command in str.
			command=command,)
	def push(self,
		# the local path.
		path=None, 
		# the ssht00ls alias.
		alias=None, 
		# the remote path.
		remote=None, 
		# exlude subpaths (list) (leave None to exclude none).
		exclude=[],
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
		log_level=dev0s.defaults.options.log_level,
		# get the command in str.
		command=False,
	):

		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# check encryption activated.
		if not ssht00ls_agent.activated:
			return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")
		if checks:
			if self.specific:
				try: self.activated
				except: self.activated = False
			if not self.specific or not self.activated:
				response = aliases.check(alias)
				if not response["success"]: return response
				response = agent.check(public_key=CONFIG["aliases"][alias]["public_key"])
				if not response.success:
					if "is not added to the" not in response.error: return response
					else:
						if CONFIG["aliases"][alias]["smartcard"] in [True, "true", "True"]:
							passphrase = CONFIG["aliases"][alias]["pin"]
						else:
							passphrase = CONFIG["aliases"][alias]["passphrase"]
						if passphrase not in [None, "None", "none", "", False]:
							response = ssht00ls_agent.encryption.decrypt(passphrase)
							if not response["success"]: return response
							passphrase = response.decrypted.decode()
						else:
							passphrase = None
						response = agent.add(private_key=CONFIG["aliases"][alias]["private_key"], passphrase=passphrase)
						if not response["success"]: return response
				if self.specific: self.activated = True
		return self.utils.push(
			# the local path.
			path=path, 
			# the ssht00ls alias.
			alias=alias, 
			# the remote path.
			remote=remote, 
			# exlude subpaths (list) (leave None to use default).
			exclude=exclude,
			# path is directory boolean (leave None to parse automatically).
			directory=directory,
			empty_directory=empty_directory,
			# update deleted files.
			delete=delete,
			# forced mode.
			forced=forced,
			# version control.
			safe=safe,
			# accept new hosts keys.
			accept_new_host_keys=accept_new_host_keys,
			# checks.
			checks=checks,
			check_base=check_base,
			# log level.
			log_level=log_level,
			# get the command in str.
			command=command,)
	# depricated.
	def mount(self, 
		# the local path.
		path=None, 
		# the remote path.
		remote=None, 
		# ssh alias.
		alias=None,
		# forced.
		forced=False,
		# exclude.
		exclude=['__pycache__', '.DS_Store'],
		# accept new host verification keys.
		accept_new_host_keys=True,
		# log level.
		log_level=dev0s.defaults.options.log_level,
		# the daemon mode.
		mode="mount",
	):

		# depricated.
		return dev0s.response.error("DEPRICATED.")
		
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# checks.
		response = dev0s.response.parameters.check(
			traceback=self.__traceback__(function="mount"), 
			parameters={
				"path:str":path,
				"remote:str":remote,
				"alias:str":alias,
				"exclude:list":exclude,
				"forced:bool":forced,
				"mode:str":mode,
				"accept_new_host_keys:bool":accept_new_host_keys, 
			})
		if not response["success"]: return response
		if mode in ["synchronize", "sync", "synch"]: mode = "sync"
		if mode not in ["mount", "sync"]:
			return dev0s.response.error(f"Specified an invalid mode: [{mode}], options: [mount, sync].")
		cache_path = gfp.absolute(path=gfp.clean(path.split(" (d)")[0], remove_last_slash=True))
		if mode in ["mount"] and not forced and Files.exists(path):
			return dev0s.response.error(f"Path [{path}] already exists.")
		elif self.daemons.running(cache_path):
			return dev0s.response.error(f"Path [{path}] is already mounted.")
		path = gfp.clean(path=path)
		remote = gfp.clean(path=remote)

		# pull.
		if mode in ["mount"]:
			response = self.pull(
				path=path, 
				alias=alias, 
				remote=remote, 
				exclude=exclude,
				forced=forced,
				delete=True,
				safe=False,
				log_level=log_level,)
			if not response["success"]: return response
		else:
			# make sure both dirs exist in the end.
			# raise error when both dirs do not exist at start.
			response = ssh.utils.test_dir(path=remote, alias=alias)
			remote_exists, local_exists = True, Files.exists(path)
			if not response["success"]: 
				if "does not exist" in response["error"]:
					remote_exists = False
				else:
					return response
			if not remote_exists and not local_exists:
				return dev0s.response.error(f"Both local and remote directories {path} & {alias}:{remote} do not exist.")
			if not local_exists:
				os.system(f"mkdir -p {path}")
				if not Files.exists(path): 
					return dev0s.response.error(f"Failed to create directory {path}.")
			if not remote_exists:
				response = ssh.utils.test_dir(path=remote, alias=alias, create=True)
				if not response["success"]: 
					return dev0s.response.error(f"Failed to create directory {alias}:{remote}, error: {response['error']}")

		# start daemon.
		cache.set(id=cache_path, group="daemons", data=f"*running* (timestamp={Date().seconds_timestamp})")
		self.set_mounted_icon(path)
		if not self.daemons.running(cache_path):
			return dev0s.response.error(f"Failed to set the {path} daemon status.")
		response =  self.daemon(alias=alias, path=path, remote=remote, start=True, mode=mode)
		if not response.success: return response

		# handler.
		if mode == "sync":
			return dev0s.response.success(f"Successfully synchronized {alias}:{remote} to {path}.")
		else:
			return dev0s.response.success(f"Successfully mounted {alias}:{remote} to {path}.")

		#
	def unmount(self, 
		# the local path.
		path=None, 
		# forced required.
		forced=False,
		# sudo required.
		sudo=False,
		# log level.
		log_level=dev0s.defaults.options.log_level,
	):

		# depricated.
		return dev0s.response.error("DEPRICATED.")

		# checks.
		response = dev0s.response.parameters.check(
			traceback=self.__traceback__(function="unmount"), 
			parameters={
				"path:str":path,
				"forced:bool":forced,
				"sudo:bool":sudo, 
			})
		if not response["success"]: return response
		path = gfp.clean(path)
		cache_path = gfp.absolute(gfp.clean(path.split(" (d)")[0], remove_last_slash=True))
		if not self.daemons.running(cache_path):
			if not Files.exists(path):
				return dev0s.response.error(f"Path [{path}] does not exist.")
			elif not os.path.isdir(path):
				return dev0s.response.error(f"Path [{path}] is not a directory.")
			status = str(cache.get(id=cache_path, group="daemons"))
			if not self.daemons.running(cache_path):
				return dev0s.response.error(f"Path [{path}] is not mounted (status: {status}).")

		# wait for daemon stop.
		response = self.daemons.stop(path=path)
		if not success: return response

		# handler.
		return dev0s.response.success(f"Successfully unmounted [{path}].")

		#
	def daemon(self, 
		# the ssh alias.
		alias=None, 
		# the remote path.
		remote=None, 
		# thel local path.
		path=None, 
		# settings.
		start=True,
		# the daemon mode.
		mode="mount",
		# the daemons log level.
		log_level=dev0s.defaults.log_level(default=-1),
		# sandbox (do not delete any files).
		sandbox=False,
		# overwrite sleeptime.
		sleeptime=SSYNC_DAEMON_SLEEPTIME,
		# serialized.
		serialized={},
	):
		# depricated.
		return dev0s.response.error("DEPRICATED.")

		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# serialzied.
		if serialized != {}:
			alias, remote, path, start, mode, log_level, sandbox, sleeptime = Dictionary(path=False, dictionary=serialized).unpack({
				"alias":None,
				"remote":None,
				"path":None,
				"start":True,
				"mode":"mount",
				"log_level":dev0s.defaults.log_level(default=-1),
				"sandbox":False,
				"sleeptime":SSYNC_DAEMON_SLEEPTIME,
			})
		if mode in ["synchronize", "sync", "synch"]: mode = "sync"
		if mode not in ["mount", "sync"]:
			return dev0s.response.error(f"Specified an invalid mode: [{mode}], options: [mount, sync].")
		path = gfp.clean(path)
		remote = gfp.clean(remote)
		_daemon_ = daemons.Daemon({
			"alias":alias,
			"remote":remote,
			"path":path,
			"mode":mode,
			"log_level":log_level,
			"sandbox":sandbox,
			"ssync":self,
			"utils":self.utils,
			"sleeptime":sleeptime,
		})
		if start: ssht00ls_agent.webserver.start_thread(_daemon_, group="daemons", id=_daemon_.id)
		return dev0s.response.success("Successfully initialized the daemon", {
			"daemon":_daemon_,
		})
	
# initialized objects.
ssync = SSync()
if CHECKS and dev0s.defaults.options.interactive and not dev0s.cli.argument_present("--reset-cache"):
	daemons.sync()
	