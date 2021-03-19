#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.ssh import ssh, Tunnel
from ssht00ls.classes.aliases import aliases

# the smb client object class.
class SMB(Thread):
	def __init__(self,
		# initialize as specific not global (optional).
		# 	the share id (#1).
		id=None,
		# 	the mountpoint path (#2).
		path=None,
		# 	the alias (#3).
		alias=None,
		# 	the server's ip (leave None to retrieve from alias).
		ip=None,
		# 	the server's port.
		port=445,
		# 	tunnel smb through ssh.
		tunnel=False,
		tunnel_obj=None, # do not use the tunnel_obj parameter.
		# 	the reconnect boolean (only used whe tunnel is enabled).
		reconnect=False,
		# 	the thread's sleeptime.
		sleeptime=60,
		# 	the reconnect reattemps.
		reattemps=15,
		# 	the log level.
		log_level=dev0s.defaults.options.log_level,
	):


		# docs.
		DOCS = {
			"module":"ssht00ls.smb", 
			"initialized":True,
			"description":[], 
			"chapter": "Protocols", }

		# defaults.
		Thread.__init__(self, traceback="ssht00ls.smb", log_level=dev0s.defaults.log_level(default=-1))

		# specific variables.
		self.specific = alias != None and id != None and path != None and ip != None
		self.id_ = id
		self.path = path
		self.alias = alias
		self.ip = ip
		self.port = port
		self.tunnel = tunnel
		self.tunnel_obj = tunnel_obj
		self.reconnect = reconnect
		self.sleeptime = sleeptime
		self.reattemps = reattemps
		self.log_level = log_level

		#
	# functions.
	def mount(self,
		# the share id (leave None to use self.id) (required) (#1).
		id=None,
		# the mountpoint path (leave None to use self.path) (required) (#2).
		path=None,
		# the ssh alias (leave None to use self.alias) (required) (#3).
		alias=None,
		# the username of for the remote server (leave None to use the aliases username).
		username=None,
		# the password of the remote server's user (optional) (leave None to prompt) (use "" for no passphrase).
		password=None,
		# the ip of the remote server (leave None to use the aliases ip).
		ip=None,
		# the port (leave None to use self.port).
		port=None,
		# tunnel over ssh (leave None to use self.tunnel).
		tunnel=None,
		# the reconnect boolean (only used whe tunnel is enabled) (leave None to use self.reconnect).
		reconnect=None,
		# the log level (leave None to use self.log_level).
		log_level=None,
	):
		

		# check specific.
		if id == None: id = self.id_
		if path == None: path = self.path
		if alias == None: alias = self.alias
		if ip == None: ip = self.ip
		if tunnel == None: tunnel = self.tunnel
		if reconnect == None: reconnect = self.reconnect
		if port == None: port = self.port 
		if log_level == None: log_level = self.log_level 

		# loader.
		if log_level >= 0:
			loader = dev0s.console.Loader(f"Mounting smb share [{alias}:{id}] to [{path}]")

		# checks.
		response = dev0s.response.parameters.check({
			"id:str,String":id,
			"path:str,String":path,
			"alias:str,String":alias,
			"port:int,Integer":port,
			"tunnel:bool,Boolean":tunnel,
			"reconnect:bool,Boolean":reconnect,
		}, traceback=self.__traceback__(function="mount"))
		if not response.success: 
			if log_level >= 0: loader.stop(success=False)
			return response

		# check alias.
		response = aliases.info(alias=alias)
		if not response.success: 
			if log_level >= 0: loader.stop(success=False)
			return response
		if username == None: username = response.info["username"]
		if ip == None: ip = response.info["public_ip"]

		# parse smb.
		response = self.parse(path=path)
		if not response.success: 
			if log_level >= 0: loader.stop(success=False)
			return response
		elif response.mounted:
			if log_level >= 0: loader.stop(success=False)
			return dev0s.response.error(f"Path [{path}] is already mounted.")
		elif not response.exists:
			os.system(f"mkdir -p {path} 2> /dev/null && chown {dev0s.defaults.vars.user}:{dev0s.defaults.vars.group} {path}")
			if not os.path.exists(path):
				os.system(f"sudo mkdir -p {path} 2> /dev/null && sudo chown {dev0s.defaults.vars.user}:{dev0s.defaults.vars.group} {path}")

		# check tunnel.
		if tunnel:
			new_tunnel = False
			if not self.specific or (self.specific and self.tunnel_obj == None):
				# check already established tunnel from previous session.
				established_port = None
				response = dev0s.code.processes(includes=f":localhost:445 -f -N {DEFAULT_SSH_OPTIONS} {alias}")
				if not response.success: 
					if log_level >= 0: loader.stop(success=False)
					return response
				elif len(response.processes) > 0:
					command = Dictionary(response.processes)[0]["command"]
					try: 
						s = str(command).split(f":localhost:445 -f -N {DEFAULT_SSH_OPTIONS} {alias}")[0].split(" ")
						established_port = int(s[len(s)-1])
					except: a=1
				# create new tunnel.
				remote_port = int(port)
				if established_port == None:
					response = dev0s.network.free_port(start=6000)
					if not response.success: 
						if log_level >= 0: loader.stop(success=False)
						return response
					port = response.port
				else:
					port = established_port
				ip = "localhost"
				tunnel_ = Tunnel(
					alias=alias,
					ip=ip,
					port=port,
					remote_port=remote_port,
					reconnect=reconnect,)
				if self.specific:
					self.tunnel_obj = tunnel_
				new_tunnel = True
			elif self.specific and self.tunnel_obj != None:
				tunnel_ = self.tunnel_obj
			if not tunnel_.established:
				response = tunnel_.establish()
				if not response.success: 
					if log_level >= 0: loader.stop(success=False)
					return success
				time.sleep(0.5)
				if reconnect and new_tunnel:
					#tunnel_.start()
					response = ssht00ls_agent.webserver.start_thread(tunnel_, group="tunnels", id=tunnel_.id)
					if not response.success: 
						if log_level >= 0: loader.stop(success=False)
						return response

		# command.
		if dev0s.defaults.vars.os in ["macos"]:
			if password == None:
				user_pass = username
			elif password == "":
				user_pass = f"{username}:''"
			else:
				user_pass = f"{username}:{password}"
			command = f"mount_smbfs //{user_pass}@{ip}:{port}/{id} {path}"
		else:
			if log_level >= 0: loader.stop(success=False)
			return dev0s.response.error("Coming soon.")
			command = ""

		# execute.
		try:
			output = dev0s.code.execute(command)
		except KeyboardInterrupt as e:
			if dev0s.defaults.vars.os in ["macos"]:
				dev0s.code.kill(includes=command, log_level=-1)
			raise KeyboardInterrupt(e)
		if not output.success: 
			if log_level >= 0: loader.stop(success=False)
			return output

		# reconnect smb thread.
		if reconnect:
			if self.specific:
				smb = self
			else:
				smb = SMB(
					id=id,
					path=path,
					alias=alias,
					ip=ip,
					port=port,
					tunnel=tunnel,
					tunnel_obj=tunnel_,
					reconnect=reconnect,)
			if reconnect:
				#smb.start()
				response = ssht00ls_agent.webserver.start_thread(smb, group="smb.mounts", id=path)
				if not response.success: 
					if log_level >= 0: loader.stop(success=False)
					return response

		# handlers.
		attributes = {}
		if not self.specific and tunnel: attributes["tunnel"] = tunnel_
		if not self.specific and reconnect: attributes["smb"] = smb
		if log_level >= 0: loader.stop()
		return dev0s.response.success(f"Successfully mounted smb share [{alias}:{id}] to [{path}].", attributes)

		#
	def unmount(self, 
		# the mountpoint path (leave None to use self.path) (required) (#1).
		path=None, 
		# the forced umount option.
		forced=False, 
		# root permission required for force.
		sudo=False,
		# the log level (leave None to use self.log_level).
		log_level=None,
	):

		# specific.
		if path == None: path = self.path
		if log_level == None: log_level = self.log_level 

		# loader.
		if log_level >= 0:
			loader = dev0s.console.Loader(f"Unmounting [{path}]")

		# checks.
		response = dev0s.response.parameters.check({
			"path:str,String":path,
			"forced:bool,Boolean":forced,
			"sudo:bool,Boolean":sudo,
		}, traceback=self.__traceback__(function="unmount"))
		if not response["success"]: 
			if log_level >= 0: loader.stop(success=False)
			return response

		# parse smb.
		response = self.parse(path=path)
		if not response.success: 
			if log_level >= 0: loader.stop(success=False)
			return response
		elif not response.mounted:
			if log_level >= 0: loader.stop(success=False)
			return dev0s.response.error(f"Path [{path}] is not mounted.")

		# check stop thread.
		"""
		smb = None
		response = ssht00ls_agent.webserver.get_thread(group="smb.mounts", id=path)
		print(response)
		if not response.success and "There is no thread cached for" not in response.error:
			return response
		elif response.success:
			smb = response.thread
		if smb != None:
			response = smb.stop()
			dev0s.response.log(response=response)
			if not response.success: return response
		"""

		# exceute.
		command = ""
		if sudo: 
			command += "sudo "
		command += "umount "
		if forced: 
			command += "-f "
		command += path
		output = dev0s.code.execute(command)

		# handlers.
		if not output:
			if log_level >= 0: loader.stop(success=False)
			return dev0s.response.error(f"Failed to unmount [{path}], error: {output}")
		if output != "":
			if log_level >= 0: loader.stop(success=False)
			return dev0s.response.error((f"Failed to unmount [{path}], error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		else:
			if log_level >= 0: loader.stop()
			return dev0s.response.success(f"Successfully unmounted [{path}].")

		#
	def parse(self,
		# the mountpoint path (leave None to use self.path) (required) (#1). 
		path=None,
	):

		# specific.
		if path == None: path = self.path

		# checks.
		response = dev0s.response.parameters.check({
			"path:str,String":path,
		}, traceback=self.__traceback__(function="unmount"))
		if not response["success"]: return response

		# handlers.
		try: mounted = os.path.ismount(path)
		except FileNotFoundError: mounted = False
		try: directory = os.path.isdir(path)
		except FileNotFoundError: directory = False
		return dev0s.response.success(f"Successfully parsed [{path}].", {
			"exists":os.path.exists(path),
			"mounted":mounted,
			"directory":directory,
		})

		#
	# thread.
	def __run__(self):

		# checks.
		if not self.mounted:
			self.send_crash(response=dev0s.response.error_response("The smb share is not mounted yet."))

		# start.
		while self.run_permission:

			# check no longer mounted.
			if not os.path.exists(self.path):
				break

			# check if connection is still active otherwise reconnect.
			if not self.mounted:
				crashed = False
				for attempt in range(self.reattemps):
					response = self.mount()
					if response.success:
						break
					else:
						if attempt >= self.reattemps-1:
							self.send_crash(response=response)
							crashed = True
							break
						else:
							time.sleep(self.sleeptime)
				if crashed: break
					
			# sleep.
			time.sleep(self.sleeptime)

		#
	def __stop__(self):
		# does never needs to be called since the thread auto stops.
		# do not kill the tunnel since it may be used by other mounts.
		response = self.unmount()
		if not response.success and "is not mounted" not in response.error: return response
		return dev0s.response.success(f"Successfully stopped [{self.id}]")
	# properties.
	@property
	def id(self):
		return self.__id__()
	def __id__(self, alias=None, id=None, path=None):
		if alias == None: alias = self.alias
		if id == None: id = self.id_
		if path == None: path = self.path
		return f"{alias}:{id} {path}"
	@property
	def mounted(self):
		return self.__mounted__()
	def __mounted__(self, alias=None, id=None, path=None):
		if alias == None: alias = self.alias
		if id == None: id = self.id_
		if path == None: path = self.path
		id = self.__id__(alias=alias, id=id, path=path)
		if not os.path.exists(path): return False
		return os.path.ismount(path)
	# bool representation.
	def __bool__(self):
		return bool(self.mounted)
	# str representation.
	def __str__(self):
		if self.specific:
			return f"{self.traceback[:-1]} ({self.id}) (mounted: {self.mounted}) >"
		else:
			return self.traceback
	# representation.
	def __repr__(self):
		return str(self)

	#

# initialized objects.
smb = SMB()

# testing.
"""
response = smb.mount(
	id="packages",
	path="/Volumes/packages",
	alias="dev.vandenberghinc.com",
	password="",
	tunnel=True,
	reconnect=True,)
print("response:",response)
time.sleep(5)
response = smb.unmount(
	path="/Volumes/packages",)
print(response)
quit()
quit()
"""
#
	