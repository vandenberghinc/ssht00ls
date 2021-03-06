#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.ssh import ssh, Tunnel
from ssht00ls.classes.aliases import aliases

# the smb client object class.
class SMB(syst3m.objects.Thread):
	def __init__(self,
		# initialize as specific not global (optional).
		# 	the share id.
		id=None,
		# 	the mountpoint path.
		path=None,
		# 	the alias.
		alias=None,
		# 	the server's ip (leave None to retrieve from alias).
		ip=None,
		# 	the server's port.
		port=445,
		# 	tunnel smb through ssh.
		tunnel=False,
		tunnel_obj=None,
		# 	the reconnect boolean (only used whe tunnel is enabled).
		reconnect=False,
		# 	the thread's sleeptime.
		sleeptime=60,
		# 	the reconnect reattemps.
		reattemps=15,
	):

		# defaults.
		syst3m.objects.Thread.__init__(self, traceback="ssht00ls.smb", log_level=syst3m.defaults.log_level(default=-1))

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

		#
	# functions.
	def mount(self,
		# the share id (#1).
		id=None,
		# the mountpoint path (#2).
		path=None,
		# the ssh alias.
		alias=None,
		# the username of for the remote server (leave None to use the aliases username).
		username=None,
		# the password of the remote server's user (optional) (leave None to prompt) (use "" for no passphrase).
		password=None,
		# the ip of the remote server (leave None to use the aliases ip).
		ip=None,
		# the port (leave None to use 445).
		port=None,
		# tunnel over ssh (leave None to use False).
		tunnel=None,
		# the reconnect boolean (only used whe tunnel is enabled) (leave None to use False).
		reconnect=None,
	):
		

		# check specific.
		if id == None: id = self.id_
		if path == None: path = self.path
		if alias == None: alias = self.alias
		if ip == None: ip = self.ip
		if tunnel == None: tunnel = self.tunnel
		if reconnect == None: reconnect = self.reconnect
		if port == None: port = self.port 

		# checks.
		response = r3sponse.check_parameters({
			"id:str,String":id,
			"path:str,String":path,
			"alias:str,String":alias,
			"port:int,Integer":port,
			"tunnel:bool,Boolean":tunnel,
			"reconnect:bool,Boolean":reconnect,
		}, traceback=self.__traceback__(function="mount"))
		if not response.success: return response

		# check alias.
		response = aliases.info(alias=alias)
		if not response.success: return response
		if username == None: username = response.info["username"]
		if ip == None: ip = response.info["public_ip"]

		# parse smb.
		response = self.parse(path=path)
		if not response.success: return response
		elif response.mounted:
			return r3sponse.error(f"Path [{path}] is already mounted.")
		elif not response.exists:
			os.system(f"mkdir -p {path} 2> /dev/null && chown {syst3m.defaults.vars.user}:{syst3m.defaults.vars.group} {path}")
			if not os.path.exists(path):
				os.system(f"sudo mkdir -p {path} 2> /dev/null && sudo chown {syst3m.defaults.vars.user}:{syst3m.defaults.vars.group} {path}")

		# check tunnel.
		if tunnel:
			new_tunnel = False
			if not self.specific or (self.specific and self.tunnel_obj == None):
				# check already established tunnel from previous session.
				established_port = None
				response = syst3m.defaults.processes(includes=f":localhost:445 -f -N {DEFAULT_SSH_OPTIONS} {alias}")
				if not response.success: return response
				elif len(response.processes) > 0:
					pid = list(response.processes.keys())[0]
					output = syst3m.console.execute(f"ps -ax | grep '{pid} ' ")
					if not output.success: return output
					try: 
						s = str(output).split(f":localhost:445 -f -N {DEFAULT_SSH_OPTIONS} {alias}")[0].split(" ")
						established_port = int(s[len(s)-1])
					except: a=1
				# create new tunnel.
				remote_port = int(port)
				if established_port == None:
					response = netw0rk.network.free_port(start=6000)
					if not response.success: return response
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
				if not response.success: return success
				time.sleep(0.5)
				if reconnect and new_tunnel:
					#tunnel_.start()
					response = webserver.start_thread(tunnel_, group="tunnels", id=tunnel_.id)
					if not response.success: return response

		# command.
		if syst3m.defaults.vars.os in ["macos"]:
			if password == None:
				user_pass = username
			elif password == "":
				user_pass = f"{username}:''"
			else:
				user_pass = f"{username}:{password}"
			command = f"mount_smbfs //{user_pass}@{ip}:{port}/{id} {path}"
		else:
			return r3sponse.error("Coming soon.")
			command = ""

		# execute.
		try:
			output = syst3m.console.execute(command)
		except KeyboardInterrupt as e:
			if syst3m.defaults.vars.os in ["macos"]:
				syst3m.defaults.kill(includes=command, log_level=-1)
			raise KeyboardInterrupt(e)
		if not output.success: return output

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
				response = webserver.start_thread(smb, group="smb.mounts", id=path)
				if not response.success: return response

		# handlers.
		attributes = {}
		if not self.specific and tunnel: attributes["tunnel"] = tunnel_
		if not self.specific and reconnect: attributes["smb"] = smb
		return r3sponse.success(f"Successfully mounted smb share [{alias}:{id}] to [{path}].", attributes)

		#
	def unmount(self, 
		# the mountpoint path (#1).
		path=None, 
		# the forced umount option.
		forced=False, 
		# root permission required for force.
		sudo=False,
	):

		# specific.
		if path == None: path = self.path

		# checks.
		response = r3sponse.check_parameters({
			"path:str,String":path,
			"forced:bool,Boolean":forced,
			"sudo:bool,Boolean":sudo,
		}, traceback=self.__traceback__(function="unmount"))
		if not response["success"]: return response

		# parse smb.
		response = self.parse(path=path)
		if not response.success: return response
		elif not response.mounted:
			return r3sponse.error(f"Path [{path}] is not mounted.")

		# check stop thread.
		"""
		smb = None
		response = webserver.get_thread(group="smb.mounts", id=path)
		print(response)
		if not response.success and "There is no thread cached for" not in response.error:
			return response
		elif response.success:
			smb = response.thread
		if smb != None:
			response = smb.stop()
			r3sponse.log(response=response)
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
		output = syst3m.console.execute(command)

		# handlers.
		if not output:
			return r3sponse.error(f"Failed to unmount [{path}], error: {output}")
		if output != "":
			return r3sponse.error((f"Failed to unmount [{path}], error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))
		else:
			return r3sponse.success(f"Successfully unmounted [{path}].")

		#
	def parse(self,
		# the mountpoint path. 
		path=None,
	):

		# specific.
		if path == None: path = self.path

		# checks.
		response = r3sponse.check_parameters({
			"path:str,String":path,
		}, traceback=self.__traceback__(function="unmount"))
		if not response["success"]: return response

		# handlers.
		try: mounted = os.path.ismount(path)
		except FileNotFoundError: mounted = False
		try: directory = os.path.isdir(path)
		except FileNotFoundError: directory = False
		return r3sponse.success(f"Successfully parsed [{path}].", {
			"exists":os.path.exists(path),
			"mounted":mounted,
			"directory":directory,
		})

		#
	# thread.
	def __run__(self):

		# checks.
		if not self.mounted:
			self.send_crash(response=r3sponse.error_response("The smb share is not mounted yet."))

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
		return r3sponse.success(f"Successfully stopped [{self.id}]")
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
	