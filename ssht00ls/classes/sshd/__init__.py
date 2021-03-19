#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.smartcards import smartcards
from ssht00ls.classes.installation import installation

# the sshd object class.
class SSHD(Traceback):
	def __init__(self,
	):
		

		# docs.
		DOCS = {
			"module":"ssht00ls.sshd", 
			"initialized":True,
			"description":[], 
			"chapter": "Protocols", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.sshd", raw_traceback="ssht00ls.classes.sshd.SSHD")	

		# check downloads.
		if CHECKS:
			response = self.__install_utils__(usernames=[dev0s.defaults.vars.user])
			if not response.success: response.crash()

	def create(self,
		# save the configuration & banner.
		save=False,
		# the ssh port.
		port=22,
		# the listen addresses.
		listen_addresses=[],
		# the server's banner.
		banner="Hello World!",
		# the allowed users & options.
		users={
			# define per user (all keys are optional).
			"administrator": {
				# the user's root permissions.
				"root_permissions":False,
				# authentication by password.
				"password_authentication":False,
				# authentication by keys.
				"key_authentication":True,
				# ip filter.
				"ip_filter":False,
				"allowed_ips":[],
				# sftp server only.
				"sftp_only":False,
				# the chroot directory (leave null to disable).
				"chroot_directory":None,
				# allowed connection options.
				"x11_forwarding":False,
				"tcp_forwarding":False,
				"permit_tunnel":False,
				"allow_stream_local_forwarding":False,
				"gateway_ports":False,
			},
		},
	):

		# check users.
		response = self.__check_user_items__(users)
		if response["error"] != None: return response

		# check utils intalled (must be before __install_banner__).
		response = self.__check_utils_installed__(list(users.keys()))
		if response["error"] != None: return response

		# intall banner.
		if save:
			response = self.__install_banner__(banner=banner, usernames=list(users.keys()))
			if response["error"] != None: return response

		# defaults.
		configuration =  '# SSHD_CONFIG:'
		configuration += '\n# BY VANDENBERGHINC'
		configuration += '\n# MODULE: ssht00ls'
		configuration += '\n# AUTHOR: DAAN VAN DEN BERGH'
		configuration += '\nAcceptEnv LANG LC_*'
		configuration += '\nSubsystem sftp  internal-sftp'
		#configuration += '\nSubsystem sftp  /usr/libexec/sftp-server'
		configuration += '\nLoginGraceTime 60'
		configuration += '\nMaxAuthTries 3'
		configuration += '\nMaxSessions 10'
		configuration += "\nMaxStartups 999"
		configuration += '\nLogLevel VERBOSE'
		configuration += f'\nPort {port}'
		configuration += '\nProtocol 2'

		# defaults.
		configuration += '\nPermitRootLogin {}'.format("no")
		configuration += '\nStrictModes {}'.format("yes")
		configuration += '\nPermitUserEnvironment {}'.format("no")
		configuration += '\nIgnoreRhosts {}'.format("yes")
		configuration += '\nPermitTunnel {}'.format("no")
		configuration += '\nX11Forwarding {}'.format("no")
		configuration += '\nAllowTcpForwarding {}'.format("no")
		configuration += '\nAllowStreamLocalForwarding {}'.format("no")
		configuration += '\nGatewayPorts {}'.format("no")
		configuration += '\nPermitTTY {}'.format("yes")
		for listen_address in listen_addresses:
			configuration += f'\nListenAddress {listen_address}'

		# auth keys.
		configuration += '\nAuthorizedKeysFile {}'.format(".ssh/authorized_keys")

		# banner.
		configuration += '\nBanner .ssh/banner'

		# per users.
		configuration += '\nChallengeResponseAuthentication no'
		for username, info in users.items():
			configuration += f'\n# User: {username}'

			# ip filter.	
			configuration += f'\nMatch User {username}'

			# authentication by password.
			if info["password_authentication"]:
				configuration += '\n    PasswordAuthentication yes'
				configuration += '\n    PermitEmptyPasswords no'
			else:
				configuration += '\n    PasswordAuthentication no'
				configuration += '\n    PermitEmptyPasswords no'

			# authentication by keys.
			if info["key_authentication"]:
				configuration += '\n    PubkeyAuthentication {}'.format('yes')
			else:
				configuration += '\n    PubkeyAuthentication {}'.format('no')


			# chroot directory.
			if isinstance(info["chroot_directory"], str):
				configuration += f'\n    ChrootDirectory {info["chroot_directory"]}'

			# root permission.
			l = "no"
			if info["root_permissions"] and info["key_authentication"]: l = "prohibit-password"
			elif info["root_permissions"]: l = "yes"
			configuration += f'\n    PermitRootLogin {l}'

			# connection options.
			configuration += f'\n    X11Forwarding {self.__convert_boolean__(info["x11_forwarding"])}'
			configuration += f'\n    AllowTcpForwarding {self.__convert_boolean__(info["tcp_forwarding"])}'

			# default options.
			configuration += f'\n    PermitTunnel {self.__convert_boolean__(info["permit_tunnel"])}'
			configuration += f'\n    AllowStreamLocalForwarding {self.__convert_boolean__(info["allow_stream_local_forwarding"])}'
			configuration += f'\n    GatewayPorts {self.__convert_boolean__(info["gateway_ports"])}'
			configuration += f'\n    PermitTTY yes'
			
			# check ip filter.
			if info["ip_filter"]:

				# match verified ips.
				configuration += f'\n    Match User {username} Address {self.__sum_list__(info["allowed_ips"])}'

				# check sftp only.
				if info["sftp_only"]:
					configuration += '\n        ForceCommand internal-sftp'

				# shell access.
				else:
					configuration += '\n        ForceCommand bash .ssht00ls/utils/handler'

				# match unverified ips.
				configuration += f'\n    Match User {username} Address *,!{self.__sum_list__(info["allowed_ips"])}'
				configuration += f'\n        ForceCommand .ssht00ls/utils/log "Your ip address is not authorized." "Authorize your ip address to access user [{username}]."'

			# no ip filter.
			else:

				# check sftp only.
				if info["sftp_only"]:
					configuration += '\n    ForceCommand internal-sftp'

				# shell access.
				else:
					configuration += '\n    ForceCommand bash .ssht00ls/utils/handler'

		# match none authorized users.
		#if '*all*' not in list(users.keys()):
		configuration += f'\nMatch User *,!{self.__sum_list__(list(users.keys()))}'
		configuration += '\n    PasswordAuthentication no'
		configuration += '\n    PermitEmptyPasswords no'
		configuration += '\n    PubkeyAuthentication no'
		configuration += f'\n    ForceCommand .ssht00ls/utils/log "You are not authorized to access user [$USER] over ssh."'
		configuration += "\n"

		# save sshd.
		if save:
			file = File(path='/tmp/sshd_config', data=configuration)
			file.file_path.delete(forced=True, sudo=True)
			file.save()
			fp = FilePath(f"/etc/ssh/sshd_config")
			file.file_path.copy(fp.path, sudo=True)
			fp.permission.set(permission=644, sudo=True)
			fp.ownership.set(owner="root", group=None, sudo=True)
			os.system("sudo systemctl restart ssh")
			if not fp.exists(sudo=True):
				return dev0s.response.error(f"Failed to save the sshd configuration.")

		# success.
		return dev0s.response.success("Successfully created the sshd configuration.", {
				"sshd":configuration,
			})

		#
	# system functions.
	def __sum_list__(self, list):
		return Array(path=False, array=list).string(joiner=',')
	def __convert_boolean__(self, boolean):
		if boolean: return "yes"
		else: return "no"
	def __check_user_items__(self, users):

		# iterate.
		for username, info in users.items():
			
			# check options.
			try: info["root_permissions"]
			except KeyError: info["root_permissions"] = True
			try: info["password_authentication"]
			except KeyError: info["password_authentication"] = False
			try: info["key_authentication"]
			except KeyError: info["key_authentication"] = True
			try: info["ip_filter"]
			except KeyError: info["ip_filter"] = False
			try: 
				info["allowed_ips"]
				if not isinstance(info["allowed_ips"], list):
					return dev0s.response.error(f"Invalid usage, parameter [users.{username}.allowed_ips] is supposed to be a list with allowed ip addresses.")
			except KeyError: info["allowed_ips"] = []
			try: info["sftp_only"]
			except KeyError: info["sftp_only"] = False
			try: info["chroot_directory"]
			except KeyError: info["chroot_directory"] = None
			try: info["x11_forwarding"]
			except KeyError: info["x11_forwarding"] = False
			try: info["tcp_forwarding"]
			except KeyError: info["tcp_forwarding"] = False

		# response.
		return dev0s.response.success("Successfully checked the user items.")

		#
	def __check_utils_installed__(self, usernames=[]):

		# iterate.
		if isinstance(usernames, str): usernames = [usernames]
		to_install = []
		for username in usernames:
			
			# non existant.
			fp = FilePath(f"{dev0s.defaults.vars.homes}{username}/.ssht00ls/utils/.version")
			if not fp.exists(sudo=True): 
				to_install.append(username)

			# check version.
			else: 
				version = utils.__execute__(["sudo", "cat", fp.path])
				github_version = utils.__execute__(["curl", "https://raw.githubusercontent.com/vandenberghinc/ssht00ls/master/.version?raw=true"])
				if str(version) != str(github_version):
					to_install.append(username)

		# install.
		if len(to_install) > 0:
			response = self.__install_utils__(to_install)
			if response["error"] != None: return response

		# success.
		return dev0s.response.success("Successfully verified the ssht00ls utils installation.")

		#
	def __install_utils__(self, usernames=[]):

		# checks.
		if isinstance(usernames, str): usernames = [usernames]
		if len(usernames) == 0: 
			return dev0s.response.error("No usernames specified.")

		# create tmp lib.
		utils_lib = gfp.clean(path=f"{SOURCE_PATH}/lib/utils/")
		Files.copy(f"{SOURCE_PATH}/.version", f"{utils_lib}.version")
		Files.chmod(f"{utils_lib}/*", "+x")
		
		# iterate.
		for username in usernames:

			# check if ssh is correctly installed.
			response = installation.check_installed(username=username)

			# install the ssh correctly for the specified user.
			if response["error"] != None:
				response = installation.install(username=username)
				if response["error"] != None: return response

			# copy.
			fp = FilePath(f"{dev0s.defaults.vars.homes}{username}/.ssht00ls/utils/")
			if not Files.exists(fp.base(), sudo=True):
				Files.create(path=fp.base(), sudo=True, directory=True)
			fp.delete(sudo=True, forced=True)
			Files.copy(utils_lib, fp.path, sudo=True)
			fp.ownership.set(owner=username, group=None, sudo=True, recursive=True)
			fp.permission.set(permission=755, recursive=True, sudo=True)
			if not fp.exists(sudo=True):
				return dev0s.response.error("Failed to install the ssht00ls utils (#3).")

		# success.
		return dev0s.response.success("Successfully installed the ssht00ls utils.")

		#
	def __install_banner__(self, banner="", usernames=[]):

		# checks.
		if isinstance(usernames, str): usernames = [usernames]
		if len(usernames) == 0: 
			return dev0s.response.error("No usernames specified.")

		# save banner.
		file = File(path='/tmp/banner', data=banner)
		file.file_path.delete(forced=True, sudo=True)
		file.save()

		# iterate.
		for username in usernames:
			fp = FilePath(f"/{dev0s.defaults.vars.homes}{username}/.ssh/banner")
			file.file_path.copy(fp.path, sudo=True)
			fp.permission.set(permission=755, sudo=True)
			fp.ownership.set(owner=username, group=None, sudo=True)
			if not fp.exists(sudo=True):
				return dev0s.response.error(f"Failed to install the banner for user [{username}].")

		# success.
		return dev0s.response.success("Successfully installed the banner.")

		#
	#

# Initialized classes.
sshd = SSHD()






