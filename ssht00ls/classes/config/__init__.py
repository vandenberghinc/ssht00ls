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
import os, sys, subprocess, pexpect, random, getpass, time

# inc imports.
from dev0s.shortcuts import *

# source.	
SOURCE_PATH = dev0s.defaults.source_path(__file__, back=3)
BASE = dev0s.defaults.source_path(SOURCE_PATH)
dev0s.defaults.operating_system(supported=["linux", "macos"])
dev0s.defaults.alias(alias=ALIAS, executable=f"{SOURCE_PATH}")
if dev0s.defaults.options.log_level >= 2:
	dev0s.response.log(f"{ALIAS}:")
	dev0s.response.log(f"  * source: {SOURCE_PATH}")

# universal options.
# interactive must be False by default.
CHECKS = not dev0s.cli.arguments_present(["--no-checks"])
RESET_CACHE = dev0s.cli.arguments_present("--reset-cache")
if dev0s.defaults.options.log_level >= 2:
	dev0s.response.log(f"  * interactive: {dev0s.defaults.options.interactive}")
	dev0s.response.log(f"  * checks: {CHECKS}")

# database.
DATABASE = Directory(path=dev0s.env.get_string("SSHT00LS_DATABASE", default=f"{dev0s.defaults.vars.home}/.{ALIAS}"))
if not DATABASE.fp.exists():
	dev0s.response.log(f"{color.orange}Root permission{color.end} required to create {ALIAS} database [{DATABASE}].")
	os.system(f" sudo mkdir -p {DATABASE}")
	Files.chown(str(DATABASE), owner=dev0s.defaults.vars.owner, group=dev0s.defaults.vars.group, sudo=True, recursive=True)
	Files.chmod(str(DATABASE), permission=700, sudo=True, recursive=True)

# config.
CONFIG = Dictionary(path=dev0s.env.get_string("SSHT00LS_CONFIG", default=DATABASE.join("config","")), load=True, default={})

# logs.
if dev0s.defaults.options.log_level >= 2:
	dev0s.response.log(f"  * database: {DATABASE}")
	dev0s.response.log(f"  * config: {CONFIG.fp}")

# initialize cache.
cache = dev0s.database.Database(
	path=gfp.clean(f"{DATABASE}/.cache/"))

# dev0s settings.
IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY")

# ssh settings.
SSH_TIMEOUT = int(dev0s.cli.get_argument("--timeout", required=False, default=10))
SSH_REATTEMPS = int(dev0s.cli.get_argument("--reattempts", required=False, default=3))
DEFAULT_SSH_OPTIONS = f"-o ConnectTimeout={SSH_TIMEOUT} -o ConnectionAttempts={SSH_REATTEMPS}"

# daemon settings.
SSYNC_DAEMON_SLEEPTIME = round(float(dev0s.cli.get_argument("--daemon-sleeptime", required=False, default=0.25)), 2)

# logs.
if dev0s.defaults.options.log_level >= 2:
	dev0s.response.log(f"  * ssh timeout: {SSH_TIMEOUT}")
	dev0s.response.log(f"  * ssh reattempts: {SSH_REATTEMPS}")
	dev0s.response.log(f"  * daemon sleeptime: {SSYNC_DAEMON_SLEEPTIME}")

# speed up non interactive.
if CHECKS and not RESET_CACHE:

	# network.
	NETWORK_INFO = dev0s.network.info()
	if not NETWORK_INFO["success"]: 
		dev0s.response.log(error=NETWORK_INFO.error, json=dev0s.cli.arguments_present(["--json", "-j"]), log_level=0)
		sys.exit(1)
	if dev0s.defaults.options.log_level >= 2:
		dev0s.response.log(f"  * public ip: {NETWORK_INFO['public_ip']}")
		dev0s.response.log(f"  * private ip: {NETWORK_INFO['private_ip']}")

	# check lib.
	if not Files.exists(f"{SOURCE_PATH}/lib") or dev0s.cli.argument_present("--download-lib"):
		dev0s.response.log("Downloading the ssht00ls library.")
		os.system(f"rm -fr /tmp/ssht00ls && git clone -q https://github.com/vandenberghinc/ssht00ls /tmp/ssht00ls && rsync -azq /tmp/ssht00ls/ssht00ls/lib/ {Files.join(SOURCE_PATH, 'lib/')}")
		if dev0s.cli.argument_present("--download-lib"): sys.exit(0)

	# check usr lib.
	if not Files.exists("/usr/local/lib/ssht00ls"):
		dev0s.response.log(f"{color.orange}Root permission{color.end} required to install the ssht00ls system library.")
		os.system(f" sudo rsync -azq --delete {SOURCE_PATH}/ /usr/local/lib/ssht00ls")
		Files.chown("/usr/local/lib/ssht00ls", owner=dev0s.defaults.vars.owner, group=dev0s.defaults.vars.group, sudo=True, recursive=True)
		Files.chmod("/usr/local/lib/ssht00ls", permission=770, sudo=True, recursive=True)

	# database.
	for dir, permission in [
		[f"{dev0s.defaults.vars.home}/.{ALIAS}", 770],
		[f"{dev0s.defaults.vars.home}/.{ALIAS}/lib", 770],
		[f"{dev0s.defaults.vars.home}/.{ALIAS}/.cache", 770],
	]:
		if not Files.exists(dir): 
			os.system(f"sudo mkdir {dir} && sudo chown {dev0s.defaults.vars.user}:{dev0s.defaults.vars.group} {dir} && sudo chmod {permission} {dir}")

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
	})

	# database.
	Files.chmod(f"{SOURCE_PATH}/lib/utils/*", permission="+x")

	# agent.
	ssht00ls_agent = dev0s.encryption.Agent(
		# id.
		id="ssht00ls-agent",
		# cache.
		database=DATABASE.join(".agent/"),
		# webserver.
		host="127.0.0.1",
		port=2379,
		# encryption.
		private_key=dev0s.env.get("SSHT00LS_PRIVATE_KEY", default=DATABASE.join("keys/master/private_key")),
		public_key=dev0s.env.get("SSHT00LS_PUBLIC_KEY", default=DATABASE.join("keys/master/public_key")),
		passphrase=None, 
		interactive=dev0s.defaults.options.interactive,
		# traceback.
		traceback="ssht00ls.ssht00ls_agent",
	)

	# webserver.
	if dev0s.cli.argument_present("--stop-agent"):
		response = ssht00ls_agent.webserver.stop()
		if response.success:
			dev0s.response.log(response=response, json=dev0s.defaults.options.json)
			sys.exit(0)
		else:
			dev0s.response.log(response=response, json=dev0s.defaults.options.json)
			sys.exit(1)
	elif dev0s.defaults.options.interactive and not ssht00ls_agent.webserver.running: # is also automatically done in agent.generate & agent.activate
		if dev0s.defaults.options.log_level >= 2:
			dev0s.response.log(f"  * forking the ssht00ls agent.")
		response = ssht00ls_agent.webserver.fork()
		dev0s.response.log(response=response, json=dev0s.defaults.options.json)
		if not response.success: sys.exit(1)
	if dev0s.defaults.options.log_level >= 2:
		dev0s.response.log(f"  * webserver: {ssht00ls_agent.webserver}")

	# check interactive.
	if dev0s.defaults.options.interactive:

		# generate encryption.
		if not ssht00ls_agent.generated:
			response = ssht00ls_agent.generate()
			dev0s.response.log(response=response, json=dev0s.defaults.options.json)
			if not response.success: sys.exit(1)

		# activate encryption.
		else:
			response = ssht00ls_agent.activate()
			dev0s.response.log(response=response, json=dev0s.defaults.options.json)
			if not response.success: sys.exit(1)

#
