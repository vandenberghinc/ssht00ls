#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
import ssht00ls.classes.ssh.utils as ssh_utils 

# the ssh tunnel object class.
class Tunnel(syst3m.objects.Thread):
	def __init__(self,
		# initialize as specific not global (optional).
		# 	the alias.
		alias=None,
		# 	the tunnel ip.
		ip=None,
		# 	the local port.
		port=None,
		# 	the remote port.
		remote_port=None,
		# 	the reconnect boolean.
		reconnect=False,
		# 	the thread's sleeptime.
		sleeptime=60,
		# 	the reconnect reattemps.
		reattemps=15,
		# 	the log level.
		log_level=0,
	):

		# defaults.
		syst3m.objects.Thread.__init__(self, traceback="ssht00ls.ssh.tunnel", log_level=syst3m.defaults.log_level(default=-1))
		self.__stop__ = self.stop

		# modules.
		self.utils = ssh_utils

		# specific args.
		self.specific = alias != None and ip != None and port != None and remote_port != None
		self.alias = alias
		self.ip = ip
		self.port = port
		self.remote_port = remote_port
		self.reconnect = reconnect
		self.log_level = log_level
		self.sleeptime = sleeptime
		self.reattemps = reattemps

		#
	# functions.
	def establish(self,
		# the alias.
		alias=None,
		# the tunnel ip.
		ip=None,
		# the local port.
		port=None,
		# the remote port.
		remote_port=None,
		# the reconnect boolean (leave None to use False).
		reconnect=None,
		# the log level (leave None to use 0).
		log_level=None,
	):
		
		# check specific.
		if alias == None: alias = self.alias
		if ip == None: ip = self.ip
		if port == None: port = self.port
		if remote_port == None: remote_port = self.remote_port
		if reconnect == None: reconnect = self.reconnect
		if log_level == None: log_level = self.log_level # keep this one indent back.

		# check parameters.
		response = r3sponse.check_parameters({
			"alias":alias,
			"ip":ip,
			"port":port,
			"remote_port":remote_port,
			"reconnect":reconnect, })
		if not response["success"]: return response

		# id.
		id = self.__id__(alias=alias, ip=ip, port=port, remote_port=remote_port)

		# check already established
		if self.established:
			return r3sponse.success(f"Tunnel [{id}] is already established.")

		# execute.
		output = syst3m.console.execute(f"ssh -L {port}:{ip}:{remote_port} -f -N {DEFAULT_SSH_OPTIONS} {alias}", async_=True)
		if not output.success: return output
		if output != "":
			return r3sponse.error(f"Failed to establish tunnel {id}, error: {output}.")

		# send cached run permission.
		response = webserver.set(group="tunnels.run_permission", id=id, data="True")
		if not response.success: return response

		# tunnel.
		if not self.specific:
			tunnel = Tunnel(
				alias=alias,
				ip=ip,
				port=port,
				remote_port=remote_port,
				reconnect=reconnect,)
			if not tunnel.established:
				return r3sponse.error(f"Failed to establish tunnel {tunnel.id}.")
		elif not self.established:
			return r3sponse.error(f"Failed to establish tunnel {self.id}.")

		# start thread.
		if not self.specific and reconnect:
			#response = tunnel.start()
			response = webserver.start_thread(tunnel, group="tunnels", id=tunnel.id)
			if not response.success: return response

		# handler.
		attributes = {}
		if not self.specific: attributes["tunnel"] = tunnel
		return r3sponse.success(f"Successfully established tunnel [{id}].", attributes)

		#
	def kill(self,
		# the alias.
		alias=None,
		# the tunnel ip.
		ip=None,
		# the local port.
		port=None,
		# the remote port.
		remote_port=None,
		# the log level.
		log_level=None,
	):

		# check specific.
		if alias == None: alias = self.alias
		if ip == None: ip = self.ip
		if port == None: port = self.port
		if remote_port == None: remote_port = self.remote_port
		if log_level == None: log_level = self.log_level

		# check parameters.
		response = r3sponse.check_parameters({
			"alias":alias,
			"port":port, })
		if not response["success"]: return response

		# id.
		id = self.__id__(alias=alias, ip=ip, port=port, remote_port=remote_port)

		# check established.
		if not self.__established__(alias=alias, ip=ip, port=port, remote_port=remote_port):
			return r3sponse.success(f"Tunnel [{id}] was not active.")

		# check stop thread.
		response = webserver.set(group="tunnels.run_permission", id=id, data="False")
		if not response.success: return response

		"""
		tunnel = None
		response = webserver.get_thread(group="tunnels", id=id)
		if not response.success and "There is no thread cached for" not in response.error:
			return response
		elif response.success:
			tunnel = response.thread
		if tunnel != None:
			response = tunnel.stop()
			if not response.success: return response
		"""

		# kill pid(s).
		pid = self.__pid__(alias=alias, ip=ip, port=port, remote_port=remote_port)
		if pid == None:
			return r3sponse.error(f"Unable to determine the pid of tunnel [{id}].")
		elif isinstance(pid, (list, Array)):
			for i in pid:
				response = syst3m.defaults.kill(pid=i, log_level=log_level)
				if not response.success:
					return r3sponse.error(f"Failed to kill pid [{i}] of tunnel [{id}], error: {response.error}")
		else:
			response = syst3m.defaults.kill(pid=pid, log_level=log_level)
			if not response.success:
				return r3sponse.error(f"Failed to kill pid [{pid}] of tunnel [{id}], error: {response.error}")


		# check stopped.
		if self.__established__(alias=alias, ip=ip, port=port, remote_port=remote_port):
			return r3sponse.error(f"Failed to stop tunnel [{id}].")

		# handler.
		return r3sponse.success(f"Successfully stopped tunnel [{id}].")

		#
	# thread.
	def __run__(self):

		# checks.
		if not self.established:
			self.send_crash(response=r3sponse.error_response("The tunnel is not established yet."))

		# start.
		while self.run_permission:

			# check no cached run permission.
			response = webserver.get(group="tunnels.run_permission", id=id)
			if not response.success: 
				self.send_crash(response=response)
				break
			elif not bool(response.data):
				break

			# check no longer mounted.
			if not os.path.exists(self.path):
				break

			# check if connection is still active otherwise reconnect.
			if not self.established:
				crashed = False
				for attempt in range(self.reattemps):
					response = self.establish()
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
		response = self.kill()
		if not response.success: return response
		return r3sponse.success(f"Successfully stopped [{self.id}]")
	# properties.
	@property
	def id(self):
		return self.__id__()
	def __id__(self, alias=None, ip=None, port=None, remote_port=None):
		if alias == None: alias = self.alias
		if port == None: port = self.port
		if remote_port == None: remote_port = self.remote_port
		if ip == None: ip = self.ip
		return f"{port}:{ip}:{remote_port}:{alias}"
	@property
	def established(self):
		return self.__established__()
	def __established__(self, alias=None, ip=None, port=None, remote_port=None):
		if alias == None: alias = self.alias
		if port == None: port = self.port
		if remote_port == None: remote_port = self.remote_port
		if ip == None: ip = self.ip
		id = self.__id__(alias=alias, ip=ip, port=port, remote_port=remote_port)
		response = syst3m.defaults.processes(includes=f"ssh -L {port}:{ip}:{remote_port}")
		if not response.success: raise ValueError(f"Unable to determine if tunnel {id} is active, error: {response.error}")
		return len(response.processes) >= 1
	@property
	def pid(self):
		return self.__pid__()
	def __pid__(self, alias=None, ip=None, port=None, remote_port=None):
		if alias == None: alias = self.alias
		if port == None: port = self.port
		if remote_port == None: remote_port = self.remote_port
		if ip == None: ip = self.ip
		id = self.__id__(alias=alias, ip=ip, port=port, remote_port=remote_port)
		response = syst3m.defaults.processes(includes=f"ssh -L {port}:{ip}:{remote_port}")
		if not response.success: raise ValueError(f"Unable to determine if tunnel {id} is active, error: {response.error}")
		pids = list(response.processes.keys())
		if len(pids) == 0:
			return None
		elif len(pids) == 1:
			return pids[0]
		else:
			return pids
	# bool representation.
	def __bool__(self):
		return bool(self.established)
	# str representation.
	def __str__(self):
		if self.specific:
			return f"{self.traceback[:-1]} ({self.id}) (established: {self.established}) (pid: {self.pid}) >"
		else:
			return self.traceback
	# representation.
	def __repr__(self):
		return str(self)

