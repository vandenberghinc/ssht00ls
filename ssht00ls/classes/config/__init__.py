#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# alias.
ALIAS = "ssht00ls"

# updates.
import os, sys
if "--update" in sys.argv and ALIAS in sys.argv[0]:
	os.system(f"curl -s https://raw.githubusercontent.com/vandenberghinc/{ALIAS}/master/{ALIAS}/requirements/installer.remote | bash ")
	sys.exit(0)

# imports.
import os, sys, requests, ast, json, pathlib, glob, platform, subprocess, pexpect, random, getpass, time

# inc imports.
from dev0s import *
import dev0s, syst3m, encrypti0n, netw0rk

# source.	
SOURCE_PATH = Defaults.source_path(__file__, back=3)
BASE = Defaults.source_path(SOURCE_PATH)
Defaults.operating_system(supported=["linux", "macos"])
Defaults.alias(alias=ALIAS, executable=f"{SOURCE_PATH}")
if Defaults.options.log_level >= 1:
	Response.log(f"{ALIAS}:")
	Response.log(f"  * source: {SOURCE_PATH}")

# universal options.
# interactive must be False by default.
INTERACTIVE = Environment.get("INTERACTIVE", format=bool, default=False)
CHECKS = not CLI.arguments_present(["--no-checks"])
RESET_CACHE = CLI.arguments_present("--reset-cache")
if Defaults.options.log_level >= 1:
	Response.log("ssht00ls:")
	Response.log(f"  * cli: {CLI}")
	Response.log(f"  * interactive: {INTERACTIVE}")
	Response.log(f"  * checks: {CHECKS}")

# database.
DATABASE = Directory(path=Environment.get_string("SSHT00LS_DATABASE", default=f"{Defaults.vars.home}/.{ALIAS}"))
if not DATABASE.fp.exists():
	Response.log(f"{color.orange}Root permission{color.end} required to create {ALIAS} database [{DATABASE}].")
	os.system(f" sudo mkdir -p {DATABASE}")
	Files.chown(str(DATABASE), owner=Defaults.vars.owner, group=Defaults.vars.group, sudo=True, recursive=True)
	Files.chmod(str(DATABASE), permission=700, sudo=True, recursive=True)

# config.
CONFIG = Dictionary(path=Environment.get_string("SSHT00LS_CONFIG", default=DATABASE.join("config","")), load=True, default={})

# logs.
if Defaults.options.log_level >= 1:
	Response.log(f"  * database: {DATABASE}")
	Response.log(f"  * config: {CONFIG.fp}")

# initialize cache.
cache = syst3m.cache.Cache(
	path=gfp.clean(f"{DATABASE}/.cache/"))

# netw0rk settings.
IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY")

# ssh settings.
SSH_TIMEOUT = int(CLI.get_argument("--timeout", required=False, default=10))
SSH_REATTEMPS = int(CLI.get_argument("--reattempts", required=False, default=3))
DEFAULT_SSH_OPTIONS = f"-o ConnectTimeout={SSH_TIMEOUT} -o ConnectionAttempts={SSH_REATTEMPS}"

# daemon settings.
SSYNC_DAEMON_SLEEPTIME = round(float(CLI.get_argument("--daemon-sleeptime", required=False, default=0.25)), 2)

# logs.
if Defaults.options.log_level >= 2:
	Response.log(f"  * ssh timeout: {SSH_TIMEOUT}")
	Response.log(f"  * ssh reattempts: {SSH_REATTEMPS}")
	Response.log(f"  * daemon sleeptime: {SSYNC_DAEMON_SLEEPTIME}")

# speed up non interactive.
if CHECKS and not RESET_CACHE:

	# network.
	NETWORK_INFO = netw0rk.network.info()
	if not NETWORK_INFO["success"]: 
		Response.log(error=NETWORK_INFO.error, json=CLI.arguments_present(["--json", "-j"]), log_level=0)
		sys.exit(1)
	if Defaults.options.log_level >= 1:
		Response.log("Network info:")
		Response.log(f"  * public ip: {NETWORK_INFO['public_ip']}")
		Response.log(f"  * private ip: {NETWORK_INFO['private_ip']}")

	# check lib.
	if not Files.exists(f"{SOURCE_PATH}/lib") or CLI.argument_present("--download-lib"):
		Response.log("Downloading the ssht00ls library.")
		os.system(f"rm -fr /tmp/ssht00ls && git clone -q https://github.com/vandenberghinc/ssht00ls /tmp/ssht00ls && rsync -azq /tmp/ssht00ls/ssht00ls/lib/ {Files.join(SOURCE_PATH, 'lib/')}")
		if CLI.argument_present("--download-lib"): sys.exit(0)

	# check usr lib.
	if not Files.exists("/usr/local/lib/ssht00ls"):
		Response.log(f"{color.orange}Root permission{color.end} required to install the ssht00ls system library.")
		os.system(f" sudo rsync -azq --delete {SOURCE_PATH}/ /usr/local/lib/ssht00ls")
		Files.chown("/usr/local/lib/ssht00ls", owner=Defaults.vars.owner, group=Defaults.vars.group, sudo=True, recursive=True)
		Files.chmod("/usr/local/lib/ssht00ls", permission=770, sudo=True, recursive=True)

	# database.
	for dir, permission in [
		[f"{Defaults.vars.home}/.{ALIAS}", 770],
		[f"{Defaults.vars.home}/.{ALIAS}/lib", 770],
		[f"{Defaults.vars.home}/.{ALIAS}/.cache", 770],
	]:
		if not Files.exists(dir): 
			os.system(f"sudo mkdir {dir} && sudo chown {Defaults.vars.user}:{Defaults.vars.group} {dir} && sudo chmod {permission} {dir}")

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
	Files.chmod(f"{SOURCE_PATH}/lib/utils/*", permission="+x")

	# agent.
	ssht00ls_agent = encrypti0n.Agent(
		id="ssht00ls-agent",
		config=CONFIG,
		database=Directory(DATABASE.join(".agent/")),
		passphrase=None, 
		interactive=INTERACTIVE,
		host="127.0.0.1",
		port=2379,
		traceback="ssht00ls_agent"	)

	# webserver.
	if CLI.argument_present("--stop-agent"):
		response = ssht00ls_agent.webserver.stop()
		if response.success:
			Response.log(response=response, json=Defaults.options.json)
			sys.exit(0)
		else:
			Response.log(response=response, json=Defaults.options.json)
			sys.exit(1)
	elif INTERACTIVE and not ssht00ls_agent.webserver.running: # is also automatically done in agent.generate & agent.activate
		if Defaults.options.log_level >= 1:
			Response.log(f"{ALIAS}: forking the ssht00ls agent.")
		response = ssht00ls_agent.webserver.fork()
		Response.log(response=response, json=Defaults.options.json)
		if not response.success: sys.exit(1)
	if Defaults.options.log_level >= 1:
		Response.log(f"{ALIAS} webserver: {ssht00ls_agent.webserver}")

	# check interactive.
	if INTERACTIVE:

		# generate encryption.
		if None in [CONFIG.dictionary["encryption"]["public_key"], CONFIG.dictionary["encryption"]["private_key"]]:
			if CLI:
				response = ssht00ls_agent.generate()
				Response.log(response=response, json=Defaults.options.json)
				if not response.success: sys.exit(1)
			else:
				Response.log(error="There is no encryption installed.", json=Defaults.options.json)
				sys.exit(1)

		# activate encryption.
		else:
			response = ssht00ls_agent.activate()
			Response.log(response=response, json=Defaults.options.json)
			if not response.success: sys.exit(1)

# logs.
elif Defaults.options.log_level >= 0:
	Response.log(f"{ALIAS}: skip encryption import (#1) due to ssht00ls agent start.")

#