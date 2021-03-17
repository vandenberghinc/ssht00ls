#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils

# the installation object class.
class Installation(Traceback):
	def __init__(self,
	):
		
		# docs.
		DOCS = {
			"module":"ssht00ls.installation", 
			"initialized":True,
			"description":[], 
			"chapter": "Setup", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.installation", raw_traceback="ssht00ls.classes.installation.Installation")

		#
	def install(self, 
		# optional define the user (leave None for current user).
		username=None,
	):
		# initialize.
		if username == None: username = dev0s.defaults.vars.user
		home = f"{dev0s.defaults.vars.homes}/{username}/"	
		sudo = True
		
		# users ssh directory.
		fp = FilePath(f"{home}.ssh/")
		if not fp.exists(sudo=sudo):
			fp.create(
				directory=True,
				permission=700,
				owner=username,
				group=None,
				sudo=sudo,)
		else:
			fp.permission.set(permission=700, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)

		# the ssh config.
		fp = FilePath(f"{home}.ssh/config")
		if not fp.exists(sudo=sudo):
			fp.create(
				directory=False,
				data="",
				permission=644,
				owner=username,
				group=None,
				sudo=sudo,)
		else:
			fp.permission.set(permission=644, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)

		# the ssh known hosts.
		fp = FilePath(f"{home}.ssh/known_hosts")
		if not fp.exists(sudo=sudo):
			fp.create(
				directory=False,
				data="",
				permission=644,
				owner=username,
				group=None,
				sudo=sudo,)
		else:
			fp.permission.set(permission=644, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)

		# authorized keys.
		fp = FilePath(f"{home}.ssh/authorized_keys")
		if not fp.exists(sudo=sudo):
			fp.create(
				directory=False,
				data="",
				permission=600,
				owner=username,
				group=None,
				sudo=sudo,)
		else:
			fp.permission.set(permission=600, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)

		# success.
		return dev0s.response.success(f"Successfully installed ssh for user [{username}].")

		#
	def check_installed(self, 
		# optional define the user (leave None for current user).
		username=None,
	):	

		# initialize.
		if username == None: username = dev0s.defaults.vars.user
		home = f"{dev0s.defaults.vars.homes}/{username}/"	
		sudo = True
		
		# users ssh directory.
		fp = FilePath(f"{home}.ssh/")
		if not fp.exists():
			return dev0s.response.error(f"Required ssh configuration file [{fp.path}] for user [{username}] is not installed.")
		else:
			fp.permission.set(permission=700, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)

		# the ssh config.
		fp = FilePath(f"{home}.ssh/config")
		if not fp.exists():
			return dev0s.response.error(f"Required ssh configuration file [{fp.path}] for user [{username}] is not installed.")
		else:
			fp.permission.set(permission=644, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)

		# the ssh known hosts.
		fp = FilePath(f"{home}.ssh/known_hosts")
		if not fp.exists():
			return dev0s.response.error(f"Required ssh configuration file [{fp.path}] for user [{username}] is not installed.")
		else:
			fp.permission.set(permission=644, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)
			
		# authorized keys.
		fp = FilePath(f"{home}.ssh/authorized_keys")
		if not fp.exists():
			return dev0s.response.error(f"Required ssh configuration file [{fp.path}] for user [{username}] is not installed.")
		else:
			fp.permission.set(permission=600, sudo=sudo)
			fp.ownership.set(owner=username, group=None, sudo=sudo)

		# success.
		return dev0s.response.success(f"SSH is successfully installed for user [{username}].")
			
# Initialized objects.
installation = Installation()

"""

# --------------------
# SSH Installation.

# check if ssh is correctly installed.
# (leave the username None to use the current user.)
response = installation.check_installed(username=None)

# install the ssh correctly for the specified user.
if response["error"] != None:
	response = installation.install(username=None)

"""






