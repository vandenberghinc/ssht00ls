#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# alias.
ALIAS = "ssht00ls"

# updates.
import os, sys
if "--update" in sys.argv:
	os.system(f"curl -s https://raw.githubusercontent.com/vandenberghinc/{ALIAS}/master/{ALIAS}/requirements/installer.remote | bash ")
	sys.exit(0)

# imports.
try: 

	# imports.
	import os, sys, requests, ast, json, pathlib, glob, platform, subprocess, pexpect, random, getpass, time

	# inc imports.
	from fil3s import *
	from r3sponse import r3sponse
	import cl1, syst3m, encrypti0n, netw0rk

# download.
except ImportError as e:
	import os
	if os.path.exists("/usr/bin/pip3"): 
		os.system(f"/usr/bin/pip3 install -r {syst3m.defaults.source_path(__file__, back=3)}/requirements/requirements.pip --user {os.environ.get('syst3m.defaults.vars.user')}")
	else:
		os.system(f"pip3 install -r {syst3m.defaults.source_path(__file__, back=3)}/requirements/requirements.pip")

	# imports.
	import os, sys, requests, ast, json, pathlib, glob, platform, subprocess, pexpect, random, getpass, time

	# inc imports.
	from fil3s import *
	from r3sponse import r3sponse
	import cl1, syst3m, encrypti0n, netw0rk


# source.	
SOURCE_PATH = syst3m.defaults.source_path(__file__, back=3)
BASE = syst3m.defaults.source_path(SOURCE_PATH)
syst3m.defaults.operating_system(supported=["linux", "macos"])
syst3m.defaults.alias(alias=ALIAS, executable=f"{SOURCE_PATH}")
if syst3m.defaults.options.log_level >= 1:
	r3sponse.log(f"{ALIAS} source: {SOURCE_PATH}")
	r3sponse.log(f"{ALIAS} os: {syst3m.defaults.vars.os}")

# universal options.
# interactive must be False by default.
INTERACTIVE = syst3m.env.get("INTERACTIVE", format=bool, default=False)
CLI = syst3m.env.get("CLI", format=bool, default=False)
CHECKS = not cl1.arguments_present(["--no-checks"])
RESET_CACHE = cl1.arguments_present("--reset-cache")
if syst3m.defaults.options.log_level >= 1:
	r3sponse.log(f"{ALIAS} cli: {CLI}")
	r3sponse.log(f"{ALIAS} interactive: {INTERACTIVE}")
	r3sponse.log(f"{ALIAS} checks: {CHECKS}")

# database.
DATABASE = Directory(path=syst3m.env.get_string("SSHT00LS_DATABASE", default=f"{syst3m.defaults.vars.home}/.{ALIAS}"))
if not DATABASE.fp.exists():
	r3sponse.log(f"{syst3m.color.orange}Root permission{syst3m.color.end} required to create ssht00ls database [{DATABASE}].")
	os.system(f" sudo mkdir -p {DATABASE}")
	Files.chown(str(DATABASE), owner=syst3m.defaults.vars.owner, group=syst3m.defaults.vars.group, sudo=True, recursive=True)
	Files.chmod(str(DATABASE), permission=700, sudo=True, recursive=True)

# config.
CONFIG = Dictionary(path=syst3m.env.get_string("SSHT00LS_CONFIG", default=DATABASE.join("config","")), load=True, default={})

# logs.
if syst3m.defaults.options.log_level >= 1:
	r3sponse.log(f"{ALIAS} database: {DATABASE}")
	r3sponse.log(f"{ALIAS} config: {CONFIG.fp}")

# initialize cache.
cache = syst3m.cache.Cache(
	path=gfp.clean(f"{DATABASE}/.cache/"))

# netw0rk settings.
IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY")

# ssh settings.
SSH_TIMEOUT = int(cl1.get_argument("--timeout", required=False, default=10))
SSH_REATTEMPS = int(cl1.get_argument("--reattempts", required=False, default=3))
DEFAULT_SSH_OPTIONS = f"-o ConnectTimeout={SSH_TIMEOUT} -o ConnectionAttempts={SSH_REATTEMPS}"

# daemon settings.
SSYNC_DAEMON_SLEEPTIME = round(float(cl1.get_argument("--daemon-sleeptime", required=False, default=0.25)), 2)

# logs.
if syst3m.defaults.options.log_level >= 2:
	r3sponse.log(f"{ALIAS} ssh timeout: {SSH_TIMEOUT}")
	r3sponse.log(f"{ALIAS} ssh reattempts: {SSH_REATTEMPS}")
	r3sponse.log(f"{ALIAS} daemon sleeptime: {SSYNC_DAEMON_SLEEPTIME}")

# speed up non interactive.
if CHECKS and not RESET_CACHE:

	# network.
	NETWORK_INFO = netw0rk.network.info()
	if not NETWORK_INFO["success"]: 
		r3sponse.log(error=NETWORK_INFO.error, json=cl1.arguments_present(["--json", "-j"]), log_level=0)
		sys.exit(1)
	if syst3m.defaults.options.log_level >= 1:
		r3sponse.log(f"public ip: {NETWORK_INFO['public_ip']}")
		r3sponse.log(f"private ip: {NETWORK_INFO['private_ip']}")

	# check lib.
	if not Files.exists(f"{SOURCE_PATH}/lib"):
		r3sponse.log("Downloading the ssht00ls library.")
		os.system(f"rm -fr /tmp/ssht00ls && git clone https://github.com/vandenberghinc/ssht00ls /tmp/ssht00ls && rsync -azq /tmp/ssht00ls/ssht00ls/lib/ {SOURCE_PATH}/lib/")

	# check usr lib.
	if not Files.exists("/usr/local/lib/ssht00ls"):
		r3sponse.log(f"{syst3m.color.orange}Root permission{syst3m.color.end} required to install the ssht00ls system library.")
		os.system(f" sudo rsync -azq --delete {SOURCE_PATH}/ /usr/local/lib/ssht00ls")
		Files.chown("/usr/local/lib/ssht00ls", owner=syst3m.defaults.vars.owner, group=syst3m.defaults.vars.group, sudo=True, recursive=True)
		Files.chmod("/usr/local/lib/ssht00ls", permission=770, sudo=True, recursive=True)

	# database.
	for dir, permission in [
		[f"{syst3m.defaults.vars.home}/.{ALIAS}", 770],
		[f"{syst3m.defaults.vars.home}/.{ALIAS}/lib", 770],
		[f"{syst3m.defaults.vars.home}/.{ALIAS}/.cache", 770],
	]:
		if not Files.exists(dir): 
			os.system(f"sudo mkdir {dir} && sudo chown {syst3m.defaults.vars.user}:{syst3m.defaults.vars.group} {dir} && sudo chmod {permission} {dir}")

	# files.
	CONFIG.check(save=True, default={
		"aliases":{
			"example.com (key's are optional)":{
				"username":"administrator",
				"public_ip":"192.168.1.100",
				"public_port":22,
				"private_ip":"84.84.123.192",
				"private_port":22,
				"private_key":"~/keys/example.com/administrator/private_key",
				"public_key":"~/keys/example.com/administrator/public_key",
				"passphrase":None,
				"smartcard":False,
				"pin":None,
			}
		},
		"settings": {
			"keep_alive":60,
		},
		"encryption": {
			"public_key":None,
			"private_key":None,
		},
	})

	# database.
	Files.chmod(f"{SOURCE_PATH}/classes/utils/isdir.py", permission=777)
	Files.chmod(f"{SOURCE_PATH}/classes/utils/size.py", permission=777)

	# limit webserver recursive import.
	if syst3m.env.get("SSHT00LS_WEBSERVER_IMPORT", default=False, format=bool) not in ["True", True]:

		# webserver.
		from ssht00ls.classes.webserver import WebServer
		webserver = WebServer()
		if cl1.argument_present("--stop-agent"):
			response = webserver.stop()
			if response.success:
				r3sponse.log(response=response, json=syst3m.defaults.options.json)
				sys.exit(0)
			else:
				r3sponse.log(response=response, json=syst3m.defaults.options.json)
				sys.exit(1)
		elif cl1.argument_present("--start-agent"):
			if not webserver.running: 
				if syst3m.defaults.options.log_level >= 1:
					r3sponse.log(f"{ALIAS}: starting the ssht00ls agent.")
				webserver.start()
				sys.exit(0)
			else:
				r3sponse.log(error=f"The {webserver.id} is already running.", json=syst3m.defaults.options.json)
				sys.exit(1)
		elif INTERACTIVE and not webserver.running: 
			if syst3m.defaults.options.log_level >= 1:
				r3sponse.log(f"{ALIAS}: forking the ssht00ls agent.")
			response = webserver.fork()
			r3sponse.log(response=response, json=syst3m.defaults.options.json)
			if not response.success: sys.exit(1)
		if syst3m.defaults.options.log_level >= 1:
			r3sponse.log(f"{ALIAS} webserver: {webserver}")

		# encryption.
		from ssht00ls.classes import encryption as _encryption_
		encryption = _encryption_.Encryption(
			config=CONFIG,
			webserver=webserver,
			cache=cache.path,
			interactive=INTERACTIVE,)
		if syst3m.defaults.options.log_level >= 1:
			r3sponse.log(f"{ALIAS} encryption: {encryption}")

		# check interactive.
		if INTERACTIVE:

			# generate encryption.
			if None in [CONFIG.dictionary["encryption"]["public_key"], CONFIG.dictionary["encryption"]["private_key"]]:
				if CLI:
					response = encryption.generate()
					r3sponse.log(response=response, json=syst3m.defaults.options.json)
					if not response.success: sys.exit(1)
				else:
					r3sponse.log(error="There is no encryption installed.", json=syst3m.defaults.options.json)
					sys.exit(1)

			# activate encryption.
			else:
				response = encryption.activate()
				r3sponse.log(response=response, json=syst3m.defaults.options.json)
				if not response.success: sys.exit(1)

	elif syst3m.defaults.options.log_level >= 0:
		r3sponse.log(f"{ALIAS}: skip encryption import (#2) due to ssht00ls agent start.")
elif syst3m.defaults.options.log_level >= 0:
	r3sponse.log(f"{ALIAS}: skip encryption import (#1) due to ssht00ls agent start.")

