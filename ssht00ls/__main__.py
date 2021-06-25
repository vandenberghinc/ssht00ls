#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from dev0s.shortcuts import *
dev0s.defaults.insert(dev0s.defaults.source_path(__file__, back=2))
dev0s.env["dev0s.defaults.options.interactive"] = True
dev0s.env["CLI"] = True
dev0s.defaults.options.interactive = True
from ssht00ls.classes.config import *
import ssht00ls

# the cli object class.
class CLI(dev0s.cli.CLI):
	def __init__(self):
		
		# defaults.
		dev0s.cli.CLI.__init__(self,
			modes={
				"Keys:":"*chapter*",
				"    --generate":"Generate a ssh key.",
				"        --path /keys/mykey/":"Specify the keys directory path.",
				"        --passphrase Passphrase123":"Specify the keys passphrase.",
				"        --comment 'My Key'":"Specify the keys comment.",
				"Aliases:":"*chapter*",
				"    --list-aliases":"List all aliases.",
				"        --joiner ','":"Optionally specify the joiner.",
				"    --alias example.com":"Select one or multiple aliases (example: x,y,z) (or use all to select all aliases).",
				"        --info":"Show the aliases info.",
				"        --delete  ":"Delete an alias.",
				"            -f / --forced":"Ignore the are you sure prompt.",
				"        --create":"Create an alias.",
				"            --server example.com":"Specify the server's name.",
				"            --username myuser":"Specify the username.",
				"            --public-ip 0.0.0.0":"Specify the server's ip.",
				"            --private-ip 0.0.0.0":"Specify the server's ip.",
				"            --public-port 22":"Specify the server's port.",
				"            --private-port 22":"Specify the server's port.",
				"            for ssh keys:":"",
				"            --private-key /path/to/key/private_key":"Specify the path to the private key.",
				"            --public-key /path/to/key/private_key":"Specify the path to the private key.",
				"            --passphrase 'MyPassphrase123'":"Specify the keys pasphrase (optional).",
				"            for smart cards:":"",
				"            --smartcard":"Enable the smartcard boolean.",
				"            --pin 123456":"Specify the smartcards pin code (optional).",
				"        --edit":"Edit the alias config.",
				"            *** same options as --create ***":"",
				"            --alias newalias":"Rename the alias.",
				"    --dump-passphrases":"Dump the encrypted passphrases.",
				"Sessions:":"*chapter*",
				"    --command <alias> 'ls .'":"Execute a command over ssh.",
				"    --session <alias>":"Start a ssh session.",
				"        --options '' ":"Specify additional ssh options (optional).",
				"Push & pull:":"*chapter*",
				"    --pull <path> <alias>:<remote>":"Pull a file / directory.",
				"        --delete":"Also update the deleted files (optional).",
				"        --safe":"Enable version control.",
				"        --forced":"Enable forced mode.",
				"    --push <alias>:<remote> <path>":"Push a file / directory.",
				"        --delete ":"Also update the deleted files (optional).",
				"        --safe ":"Enable version control.",
				"        --forced ":"Enable forced mode.",
				"        --exclude .git,.gitignore ":"Exclude additional subpaths (optioal).",
				"        --no-exclude":"Skip the default excludes and exlude nothing.",
				"Mounts:":"*chapter*",
				"    --mount <alias>:<id> <path>":"Mount a remote share.",
				"        --smb":"Select smb mode (default).",
				"        --sshfs":"Select sshfs mode (when enabled parameter id becomes remote).",
				"        *** smb options: ***":"SMB --mount options.",
				"        --reconnect":"Attempt to reconnect the mount when the connection is lost.",
				"        --tunnel":"Mount the smb share through a ssh tunnel (overwrites options --port & --ip).",
				"        --username administrator":"Overwrite the smb user (default is retrieved from alias).",
				"        --password 'SomePassphrase123'":"Set the password of the smb user login (default is no password '').",
				"        --port 445":"Select a specific smb port (default is 445).",
				"        --ip 127.0.0.1":"Select a specific ip (default is retrieved from alias).",
				"    --unmount <path>":"Unmount a mounted share.",
				"        --sudo  ":"Root permission required.",
				"        --forced  ":"Enable forced mode.",
				"Tunnels:":"*chapter*",
				"    --list-tunnels [optional: <alias>]":"List all tunnels, optionally pass an alias filter.",
				"        --joiner ',' ":"Optionally specify the joiner.",
				"    --tunnel <port>:<ip>:<remote_port>:<alias>":"Select a ssh tunnel.",
				"        --establish":"Establish the selected ssh tunnel.",
				"            --reconnect":"Attempt to reconnect the tunnel when the connection is lost.",
				"            --sleeptime 60":"Set the sleeptime value (default is 60) (only when --reconnect is enabled).",
				"            --reattempts 15":"Set the reattempts value (default is 15) (only when --reconnect is enabled).",
				"        --kill":"Kill the selected ssh tunnel.",
				#"SSync:":"*chapter*",
				#"    --index <path> / <alias>:<remote>":"Index the specified path / alias:remote.",
				#"    --sync <alias>:<remote> <path>":"Synchronize a remote & local directory (similair to --mount except it never unmounts on neither sides).",
				#"Daemons:":"*chapter*",
				#"    --start-daemon <alias>:<remote> <path>":"Start a ssync daemon manually.",
				#"    --stop-daemon <path>":"Stop a ssync daemon.",
				#"    --list-daemons":"List all daemons & their status.",
				"Agent:":"*chapter*",
				"    --sync":"Manually synchronize the aliases & add the keys to the agent.",
				"    --stop-agent":"Stop the ssht00ls agent.",
				"Basic:":"*chapter*",
				"    --kill <identifier>":"Kill all ssh processes that include the identifier.",
				"    --config":"Edit the ssht00ls configuration file (nano).",
				"    --reset-cache":"Reset the cache directory.",
				"    --version":"Show the ssht00ls version.",
				"    -h / --help":"Show the documentation.",
			},
			options={
				"-j / --json":"Print the response in json format.",
				"--non-interative":"Disable interactive mode.",
				"--no-checks":"Disable the default checks.",
				"--log-level <int>":"Overwrite the default log levels.",
				"--timeout <int>":"Overwrite the default timeout integer value (10)",
				"--reattempts <int>":"Overwrite the default reconnects integer value (3).",
				"--daemon-sleeptime <float>":"Overwrite the default daemon sleeptime float value (0.25).",
			},
			notes={
				"Include config file":"Specify the $SSHT00LS_CONFIG environment variable to use a different ssht00ls config file.",
			},
			alias="ssht00ls",
			executable=__file__,
		)

		#
	def start(self):
		
		# check arguments.
		self.arguments.check(json=dev0s.defaults.options.json, exceptions=["--log-level", "--version", "--create-alias", "--non-interative"])

		# sync aliases.
		if self.arguments.present(['--sync']) or (ssht00ls_agent.activated and not self.arguments.present(["-h", "--config", "--help", "--version", "--unmount", "--list-tunnels"])):
			str_args = Array(sys.argv).string(joiner=" ")
			aliases = ["*"]
			if not self.arguments.present(["--sync"]):
				aliases = []
				for alias in ssht00ls.aliases:
					if alias in str_args:
						aliases.append(alias)
			else:
				aliases = self.arguments.get("--sync", required=False, default=None)
				if aliases == None: aliases = ["*"]
				else:
					aliases = aliases.replace(" ","").split(",")
			response = ssht00ls.aliases.sync(aliases=aliases)
			if self.arguments.present("--sync"):
				self.stop(response=response)
			if not response["success"]: response.crash(json=dev0s.defaults.options.json)

		#
		# BASICS
		#

		# version.
		if self.arguments.present(['--version']):
			self.stop(message=f"{ALIAS} version:"+Files.load(f"{SOURCE_PATH}/.version").replace("\n",""), json=dev0s.defaults.options.json)

		# config.
		elif self.arguments.present('--config'):
			if dev0s.defaults.options.json:
				print(CONFIG.dictionary)
			else:
				os.system(f"nano {CONFIG.file_path.path}")

		# kill ssh processes.
		elif self.arguments.present('--kill'):
			response = ssht00ls.ssh.utils.kill(
				identifier=self.arguments.get("--kill"), 
				sudo=self.arguments.present("--sudo"),)
			self.stop(response=response, json=dev0s.defaults.options.json)

		# reset cache.
		elif self.arguments.present('--reset-cache'):
			path = cache.path
			os.system(f"rm -fr {path}")
			if Files.exists(path):
				self.stop(error=f"Failed to reset cache {path}.", json=dev0s.defaults.options.json)
			else:
				self.stop(message=f"Successfully resetted cache {path}.", json=dev0s.defaults.options.json)


		#
		# SESSIONS
		#

		# start session.
		elif self.arguments.present("--session"):
			alias = self.arguments.get("--session", chapter="sessions", mode="--session")
			response = ssht00ls.ssh.session(alias=alias)
			sys.exit(0)
			#self.stop(response=response)

		# command.
		elif self.arguments.present("--command"):
			alias = self.arguments.get("--command", chapter="sessions", mode="--command")
			command = self.arguments.get("--command", chapter="sessions", mode="--command", index=2)
			response = ssht00ls.ssh.command(
				alias=alias,
				command=command,
				serialize=dev0s.defaults.options.json,)
			if not response.success:
				self.stop(response=response)
			else:
				sys.exit(0)

		#
		# ALIASES
		#

		# list aliases.
		elif self.arguments.present("--list-aliases"):
			response = ssht00ls.aliases.list()
			if dev0s.defaults.options.json:
				print(response.dictionary)
			else:
				if self.arguments.present("--joiner"):
					print(Array(response.array).string(joiner=self.arguments.get("--joiner", required=False, default="\n")))
				else:
					print("Aliases:") ; c = 1
					for i in response.array: print(f" * {c}: {i}") ; c += 1

		elif self.arguments.present("--dump-passphrases"):
			response = ssht00ls.aliases.dump_passphrases(passphrase=dev0s.console.input("Enter the passphrase of the master encryption:", password=True))
			self.stop(response=response)

		# aliases.
		elif self.arguments.present("--alias"):

			# help.
			if self.arguments.present(['-h', '--help']):
				self.docs(chapter="aliases", success=True, json=dev0s.defaults.options.json)

			# get alias.
			aliases = self.arguments.get("--alias")
			all = ssht00ls.aliases.list()["aliases"]
			all_str = str(all).replace("'","")
			if aliases in ["*", "all"]: aliases = all
			else: aliases = aliases.split(",")
			
			# iterate.
			info = {}
			for alias in aliases:

				# check existance.
				if not self.arguments.present('--create'):
					response = ssht00ls.aliases.info(alias)
					if not response.success: self.stop(response=response)
					alias_info = response.info

				# show info.
				if self.arguments.present('--info'):
					if dev0s.defaults.options.json:
						info[alias] = {alias:alias_info}
					else:
						print(self.__str_representable__({alias:alias_info}, start_indent=0))

				# delete.
				elif self.arguments.present('--delete'):
					if not self.arguments.present(["-f", "--forced"]) and not dev0s.console.input(f"You are deleting alias [{alias}]. Do you wish to proceed?", yes_no=True):
						self.stop(error="Aborted.")
					response = ssht00ls.aliases.delete(alias=alias)
					self.stop(response=response, json=dev0s.defaults.options.json)

				# set passphrase.
				elif self.arguments.present('--delete'):
					passphrase = self.get_passphrase(required=False)
					if passphrase in [False, None, "", "null", "None", "none"]:
						if alias_info["smartcard"]:
							if pin != verify_pin:
								self.stop(error="Passphrases do not match.")
						else:
							passphrase = getpass.getpass(f"Enter a new passphrase for key {alias_info['private_key']}")
							if passphrase != verify_passphrase:
								self.stop(error="Passphrases do not match.")
					response = ssht00ls.aliases.edit(alias=alias, value_exceptions=[None], edits={
						"passphrase":passphrase,
						"pin":pin,
					})
					self.stop(response=response, json=dev0s.defaults.options.json)

				# edit config.
				elif self.arguments.present('--edit'):
					
					# edit alias name.
					if self.arguments.present("--alias", count=2):
						new_alias, success = self.arguments.get("--alias", count=2, chapter="aliases", mode="--edit"), True
						try:
							del CONFIG.dictionary["aliases"][alias]
							CONFIG.dictionary["aliases"][new_alias] = alias_info
							utils.save_config_safely()
						except: success = False
						if success:
							self.stop(message=f"Successfully renamed alias {alias} to {new_alias}.", json=dev0s.defaults.options.json)
						else:
							self.stop(error=f"Failed to rename alias {alias} to {new_alias}.", json=dev0s.defaults.options.json)

					# edit alias config.
					else:
						response = ssht00ls.aliases.edit( 
							# the alias.
							alias=alias,
							# the edits (dict).
							edits={
								"username":self.arguments.get("--username", required=False, default=None),
								"public_ip":self.arguments.get("--public-ip", required=False, default=None),
								"public_port":self.arguments.get("--public_-port", required=False, default=None),
								"private_ip":self.arguments.get("--private-ip", required=False, default=None),
								"private_port":self.arguments.get("--private-port", required=False, default=None),
								"private_key":self.arguments.get("--private-key", required=False, default=None),
								"public_key":self.arguments.get("--public-key", required=False, default=None),
								"passphrase":self.arguments.get("--passphrase", required=False, default=None),
								"smartcard":self.arguments.get("--smartcard", format=bool, required=False, default=None),
								"pin":self.arguments.get("--pin", format=int, required=False, default=None),
							},
							# the key exceptions.
							exceptions=[],
							# the value exceptions.
							value_exceptions=[None],
							# save the edits.
							save=True,)
						self.stop(response=response, json=dev0s.defaults.options.json)

				# create.
				elif self.arguments.present('--create'):
					
					# create an alias for the key.
					if not self.arguments.present('--smartcard'):
						key = self.arguments.get('--private-key')
						response = ssht00ls.aliases.create( 
							# the alias.
							alias=self.arguments.get('--alias', chapter="aliases", mode="--create-alias"), 
							# the username.
							username=self.arguments.get('--username'), chapter="aliases", mode="--create-alias", 
							# the public ip of the server.
							public_ip=self.arguments.get('--public-ip', chapter="aliases", mode="--create-alias"),
							# the public port of the server.
							public_port=self.arguments.get('--public-port', chapter="aliases", mode="--create-alias"),
							# the private ip of the server.
							private_ip=self.arguments.get('--private-ip', chapter="aliases", mode="--create-alias"),
							# the private port of the server.
							private_port=self.arguments.get('--private-port', chapter="aliases", mode="--create-alias"),
							# the path to the private key.
							private_key=private_key,
							# the path to the public key.
							public_key=self.arguments.get('--public-key'),
							# the keys passphrase.
							passphrase=getpass.getpass(f"Enter the passphrase of key [{private_key}]:"),
							# smart card.
							smartcard=False,)

					# create an alias for a smart card.
					else:
						response = ssht00ls.aliases.create( 
							# the alias.
							alias=self.arguments.get('--alias', chapter="aliases", mode="--create-alias"), 
							# the username.
							username=self.arguments.get('--username', chapter="aliases", mode="--create-alias"), 
							# the public ip of the server.
							public_ip=self.arguments.get('--public-ip', chapter="aliases", mode="--create-alias"),
							# the public port of the server.
							public_port=self.arguments.get('--public-port', chapter="aliases", mode="--create-alias"),
							# the private ip of the server.
							private_ip=self.arguments.get('--private-ip', chapter="aliases", mode="--create-alias"),
							# the private port of the server.
							private_port=self.arguments.get('--private-port', chapter="aliases", mode="--create-alias"),
							# the path to the private key.
							private_key=ssht00ls.smartcard.path,
							# smart card.
							smartcard=True,
							pin=self.arguments.get('--pin', required=False, default=None, chapter="aliases", mode="--create-alias"), )

					# log to console.
					self.stop(response=response, json=dev0s.defaults.options.json)

				# invalid.
				else: self.invalid(chapter="aliases", json=dev0s.defaults.options.json)

			# json show info joined.
			if dev0s.defaults.options.json and self.arguments.present('--info'):
				print(info)

		#
		# KEYS
		#

		# generate key.
		elif self.arguments.present('--generate'):
			
			# generate a key.
			passphrase = self.get_passphrase(required=False)
			if passphrase in [False, None, "", "null", "None", "none"]: passphrase = None
			response = ssht00ls.keys.generate(
				path=self.arguments.get("--path", chapter="keys", mode="--generate"), 
				passphrase=passphrase, 
				comment=self.arguments.get("--comment", chapter="keys", mode="--generate"),)
			self.stop(response=response, json=dev0s.defaults.options.json)

		#
		# PULL & PUSH
		#

		# pull.
		elif self.arguments.present('--pull'):
			remote = self.arguments.get("--pull", index=1, chapter="push & pull", mode="--pull")
			path = self.arguments.get("--pull", index=2, chapter="push & pull", mode="--pull")
			if ":" not in remote:
				self.docs(
					error=f"Invalid <alias>:<remote> <path> format.", 
					chapter="push & pull", 
					mode="--pull", 
					notes={
						"<alias>:<path>":"Pack the alias & tuple together as one argument in the following format [<alias>:<path>]."
					},
					json=dev0s.defaults.options.json,)
			alias,remote = remote.split(":")
			remote = dev0s.env.fill(remote)
			path = dev0s.env.fill(path)
			exclude = []
			if self.arguments.present("--exclude"): 
				exclude = self.arguments.get("--exclude", chapter="push & pull", mode="--pull", format=list)
			if self.arguments.present("--no-exclude"): exclude = None
			response = ssht00ls.ssync.pull(
				alias=alias, 
				remote=remote, 
				path=path,
				exclude=exclude, 
				forced=self.arguments.present("--forced"), 
				delete=self.arguments.present("--delete"), 
				safe=self.arguments.present("--safe"), 
				directory=True, )
			self.stop(response=response, json=dev0s.defaults.options.json)

		# push.
		elif self.arguments.present('--push'):
			path = self.arguments.get("--push", index=1, chapter="push & pull", mode="--push")
			remote = self.arguments.get("--push", index=2, chapter="push & pull", mode="--push")
			if ":" not in remote:
				self.docs(
					error=f"Invalid <alias>:<remote> <path>.", 
					chapter="push & pull", 
					mode="--push", 
					notes={
						"<alias>:<path>":"Pack the alias & tuple together as one argument in the following format [<alias>:<path>]."
					},
					json=dev0s.defaults.options.json,)
			alias,remote = remote.split(":")
			remote = dev0s.env.fill(remote)
			path = dev0s.env.fill(path)
			exclude = []
			if self.arguments.present("--exclude"): 
				exclude = self.arguments.get("--exclude", chapter="push & pull", mode="--pull", format=list)
			if self.arguments.present("--no-exclude"): exclude = None
			response = ssht00ls.ssync.push(
				alias=alias, 
				remote=remote, 
				path=path,
				exclude=exclude, 
				forced=self.arguments.present("--forced"), 
				delete=self.arguments.present("--delete"), 
				safe=self.arguments.present("--safe"), 
				directory=None, )
			self.stop(response=response, json=dev0s.defaults.options.json)

		#
		# MOUNTS
		#

		# mount.
		elif self.arguments.present('--mount'):
			if self.arguments.present("--sshfs"):
				remote = self.arguments.get("--mount", index=1, chapter="mounts", mode="--mount", notes={})
				path = self.arguments.get("--mount", index=2, chapter="mounts", mode="--mount", notes={})
				if ":" not in remote:
					self.docs(
						error=f"Invalid <alias>:<remote> <path>.", 
						chapter="mounts", 
						mode="--mount", 
						notes={
							"<alias>:<remote>":"Pack the alias & remote as a tuple together as one argument in the following format [<alias>:<remote>]."
						},
						json=dev0s.defaults.options.json,)
				alias,remote = remote.split(":")
				remote = dev0s.env.fill(remote)
				path = dev0s.env.fill(path)
				response = ssht00ls.sshfs.mount(
					alias=alias, 
					remote=remote, 
					path=path,
				)
			else:
				alias = self.arguments.get("--mount", index=1, chapter="mounts", mode="--mount", notes={})
				path = self.arguments.get("--mount", index=2, chapter="mounts", mode="--mount", notes={})
				if ":" not in alias:
					self.docs(
						error=f"Invalid [<alias>:<id> <path>] argument packing.", 
						chapter="mounts", 
						mode="--mount", 
						notes={
							"<alias>:<id>":"Pack the alias & share id as a tuple together as one argument in the following format [<alias>:<id>]."
						},
						json=dev0s.defaults.options.json,)
				alias,id = alias.split(":")
				path = dev0s.env.fill(path)
				response = ssht00ls.smb.mount(
					id=id, 
					path=path,
					alias=alias, 
					password=self.arguments.get("--password", required=False, default=""),
					username=self.arguments.get("--username", required=False, default=None),
					ip=self.arguments.get("--ip", required=False, default=None),
					port=self.arguments.get("--port", required=False, default=None, format=int),
					tunnel=self.arguments.present("--tunnel"), 
					reconnect=self.arguments.present("--reconnect"), 
				)
			self.stop(response=response, json=dev0s.defaults.options.json)

		# unmount.
		elif self.arguments.present('--unmount'):
			path = self.arguments.get("--unmount", index=1, chapter="mounts", mode="--unmount")
			response = ssht00ls.smb.unmount(
				path=path,
				forced=self.arguments.present("--forced"), 
				sudo=self.arguments.present("--sudo"), )
			self.stop(response=response, json=dev0s.defaults.options.json)

		#
		# SSYNC
		#

		# index.
		elif self.arguments.present('--index'):
			index = self.arguments.get("--index", chapter="ssync", mode="--index")
			if ":" in index:
				alias,remote = index.split(":")
				remote = dev0s.env.fill(remote)
				response = ssht00ls.ssync.index(path=remote, alias=alias)
			else:
				index = dev0s.env.fill(index)
				response = ssht00ls.ssync.index(path=index)
			self.stop(response=response, json=dev0s.defaults.options.json)

		# sync
			"""
			elif self.arguments.present('--sync'):
				self.stop(error="Coming soon.")
				remote = self.arguments.get("--sync", index=1, chapter="ssync", mode="--sync", notes={})
				path = self.arguments.get("--sync", index=2, chapter="ssync", mode="--sync", notes={})
				if ":" not in remote:
					self.docs(
						error=f"Invalid <alias>:<remote> <path>.", 
						chapter="ssync", 
						mode="--sync", 
						notes={
							"<alias>:<remote>":"Pack the alias & remote as a tuple together as one argument in the following format [<alias>:<remote>]."
						},
						json=dev0s.defaults.options.json,)
				alias,remote = remote.split(":")
				remote = dev0s.env.fill(remote)
				path = dev0s.env.fill(path)
				response = ssht00ls.ssync.mount(
					alias=alias, 
					remote=remote, 
					path=path,
					forced=self.arguments.present("--forced"), 
					mode="sync",)
				self.stop(response=response, json=dev0s.defaults.options.json)
			"""

		#
		# TUNNELS
		#

		# list tunnels.
		elif self.arguments.present("--list-tunnels"):
			response = ssht00ls.ssh.tunnel.list(alias=self.arguments.get("--list-tunnels", required=False, default=None))
			if dev0s.defaults.options.json:
				print(response.dictionary)
			else:
				if self.arguments.present("--joiner"):
					print(Array(response.array).string(joiner=self.arguments.get("--joiner", required=False, default="\n")))
				else:
					print("Tunnels:") ; c = 1
					for i in response.array: print(f" * {c}: {i}") ; c += 1

		# tunnel.
		elif self.arguments.present('--tunnel'):

			# help.
			if self.arguments.present(['-h', '--help']):
				self.docs(chapter="tunnels", success=True, json=dev0s.defaults.options.json)

			# tunnel.
			id = self.arguments.get("--tunnel", index=1, chapter="tunnels", notes={})
			failed = False
			try: port,ip,remote_port,alias = alias.split(":")
			except: failed = True
			if failed:
				self.docs(
					error=f"Invalid [<port>:<ip>:<remote_port>:<alias>] argument packing.", 
					chapter="tunnels", 
					mode=None, 
					notes={
						"<port>:<ip>:<remote_port>:<alias>":"Pack the port, ip, remote port & alias as a tuple together as one argument in the following format [<port>:<ip>:<remote_port>:<alias>]."
					},
					json=dev0s.defaults.options.json,)
			tunnel = ssht00ls.ssh.Tunnel(
				alias=alias,
				ip=ip,
				port=port,
				remote_port=remote_port,
				reconnect=self.arguments.present("--reconnect"),
				sleeptime=self.arguments.get("--sleeptime", required=False, default=60, format=int),
				reattemps=self.arguments.get("--reattemps", required=False, default=15, format=int),
				log_level=dev0s.defaults.options.log_level,)

			# establish.
			if self.arguments.present("--establish"):
				response = tunnel.establish()
				self.stop(response=response)

			# kill.
			elif self.arguments.present("--kill"):
				response = tunnel.kill()
				self.stop(response=response)

			# invalid.
			else: self.invalid(chapter="tunnels")

		#
		# DAEMONS
		#
			"""
			# start daemon.
			elif self.arguments.present('--start-daemon'):
				remote = self.arguments.get("--start-daemon", index=1, chapter="daemons", mode="--start-daemon")
				path = self.arguments.get("--start-daemon", index=2, chapter="daemons", mode="--start-daemon")
				if ":" not in remote:
					self.docs(
						error=f"Invalid <alias>:<remote> <path>.", 
						chapter="damons", 
						mode="--start-daemon", 
						notes={
							"<alias>:<path>":"Pack the alias & tuple together as one argument in the following format [<alias>:<path>]."
						},
						json=dev0s.defaults.options.json,)
				alias,remote = remote.split(":")
				remote = dev0s.env.fill(remote)
				path = dev0s.env.fill(path)
				response = ssht00ls.ssync.daemon(alias=alias, remote=remote, path=path)
				self.stop(response=response, json=dev0s.defaults.options.json)

			# stop daemon.
			elif self.arguments.present('--stop-daemon'):
				c = 0
				for path in self.arguments.get("--stop-daemon", index=1, chapter="daemon", mode="--stop-daemon", format=list):
					response = ssht00ls.ssync.daemons.stop(path)
					if not response["success"]:
						self.stop(response=response, json=dev0s.defaults.options.json)
						c += 1
				if c > 0:
					self.stop(message=f"Successfully stopped {c} daemon(s).", json=dev0s.defaults.options.json)
				else:
					self.stop(error="No daemons found.", json=dev0s.defaults.options.json)

			# list daemons.
			elif self.arguments.present('--list-daemons'):
				
				daemons = ssht00ls.ssync.daemons.status()
				if len(daemons) == 0:
					self.stop(message=f"There are no active daemons.", json=dev0s.defaults.options.json)
				print("Daemons:")
				for path, status in daemons.items():
					print(f" * {path}: {status}")
				self.stop(message=f"Successfully listed {len(daemons)} daemon(s).", json=dev0s.defaults.options.json)
			"""

		# 
		# HELP.
		#

		# help.
		elif self.arguments.present(['-h', '--help']):
			self.docs(success=True, json=dev0s.defaults.options.json)

		# invalid.
		else: self.invalid()

		#
	def get_passphrase(self, required=True):
		passphrase = self.arguments.get("--passphrase", required=required)
		if passphrase not in [False, None, "", "null", "None", "none"]: return passphrase.replace("\\", "").replace("\ ", "")
		else: return passphrase

# main.
if __name__ == "__main__":
	cli = CLI()
	cli.start()




