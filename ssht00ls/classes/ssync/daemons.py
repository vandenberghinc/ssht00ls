#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes.aliases import aliases
from ssht00ls.classes.agent import agent
import ssht00ls.classes.ssync.utils as ssync_utils 
from ssht00ls.classes.ssh import ssh

# sync daemon cache.
def sync():
	dir = Files.Directory(path=f"{cache.path}/daemons/")
	if not dir.fp.exists(): dir.create()
	for path in dir.paths(recursive=False):
		removed = False
		fp = FilePath(gfp.name(path=path).replace("\\","/"))
		if not fp.exists(): 
			os.system(f"rm -fr {path}")
			removed = True
		if not removed:
			status = str(cache.get(id=fp.path, group="daemons"))
			if "*running*" in status and not running(fp.path): 
				os.system(f"rm -fr {path}")
				removed = True

# check if daemon is running.
def running(path):
	
	# check status.
	cache_path = gfp.absolute(gfp.clean(path.split(" (d)")[0], remove_last_slash=True))
	status = str(cache.get(id=cache_path, group="daemons"))
	if not "*running*" in status: return False
	
	# check stamp.
	if "timestamp=" in status:
		timestamp = status.split("(timestamp=")[1].split(")")[0]
		date = Date()
		decreased = date.decrease(date.seconds_timestamp, seconds=SSYNC_DAEMON_SLEEPTIME*5, format=date.seconds_timestamp_format)
		if date.compare(current=decreased, comparison=timestamp, format=date.seconds_timestamp_format) in ["past", "present"]:
			return False
		else:
			return True
	# should not happen.
	else:
		raise ValueError(f"Should not happen, *running* is in status but no timestamp present, (status: {status}).")

# list daemons.
def status(path=None):
	if path == None:
		dict = {}
		for i in list():
			dict[i] = status(path=i)
		return dict
	else:
		sync()
		cache_path = gfp.absolute(gfp.clean(path.split(" (d)")[0], remove_last_slash=True))
		return cache.get(id=cache_path, group="daemons")

# list daemons.
def list(filter=None):
	sync()
	dir = Files.Directory(path=f"{cache.path}/daemons/")
	listed = []
	for path in dir.paths(recursive=False):
		fp = FilePath(gfp.name(path=path).replace("\\","/"))
		listed.append(fp.path)
	return listed

# stop a daemon.
def stop(path, timeout=SSYNC_DAEMON_SLEEPTIME*10, sleeptime=1):
	if timeout <= 10: timeout = 10
	cache_path = gfp.absolute(gfp.clean(path.split(" (d)")[0], remove_last_slash=True))
	cache.set(id=cache_path, data="*stop*", group="daemons")
	stopped = False
	for i in range(int(timeout/sleeptime)):
		status_ = str(cache.get(id=cache_path, group="daemons"))
		if "*stopped*" in status_ or "*crashed*" in status_:
			stopped = True
			break
		time.sleep(sleeptime)
	if stopped:
		return dev0s.response.success(f"Successfully stopped ssht00ls daemon [{path}].")
	else:
		return dev0s.response.error(f"Failed to stop ssht00ls daemon [{path}].")

# the daemon object class.
class Daemon(Thread):
	def __init__(self, attributes={}):

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.ssync.daemons.Daemon", raw_traceback="ssht00ls.classes.ssync.daemons.Daemon")

		# attributes.
		self.utils = ssync_utils
		Thread.__init__(self)
		self.assign(attributes)
		self.path = gfp.clean(self.path)
		self.id = f"{self.alias}:{self.remote} {self.path}"
		try:self.log_level
		except: self.log_level = -1
		self.last_index = {}
		self.last_remote_index = {}
		self.cache_path = gfp.absolute(gfp.clean(self.path.split(" (d)")[0], remove_last_slash=True))

		#
	def subpath(self, fullpath, remote=False, append_slash=False):
		if remote: path = self.remote
		else: path = self.path
		s = ""
		if append_slash: s = "/"
		return fullpath.replace(path+s, "").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/")
	def fullpath(self, subpath, remote=False, append_slash=False):
		if remote: path = self.remote
		else: path = self.path
		s = ""
		if append_slash: s = "/"
		return f"{path}/{subpath}{s}".replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/").replace("//","/")
	def run(self):

		# logs.
		if self.log_level >= 0: 
			loader = dev0s.console.Loader(f"Checking daemon {self.id}", interactive=dev0s.defaults.options.interactive)

		# checks.
		status = str(cache.get(id=self.cache_path, group="daemons"))
		if not running(self.cache_path):
			if self.log_level >= 0: loader.stop(success=False)
			self.crash(f"ssht00ls daemon ({self.id}): Path [{self.path}] is not running (status: {status}).")
		if self.log_level >= 0: 
			loader.mark(f"Checking mountpoint {self.path}")
		if not Files.exists(self.path):
			if self.log_level >= 0: loader.stop(success=False)
			self.crash(f"ssht00ls daemon ({self.id}): Path [{self.path}] does not exist.")
		if not os.path.isdir(self.path):
			if self.log_level >= 0: loader.stop(success=False)
			self.crash(f"ssht00ls daemon ({self.id}): Path [{self.path}] is not a directory.")

		# check alias.
		if self.log_level >= 0: 
			loader.mark(f"Checking alias {self.alias}")
		response = aliases.check(self.alias)
		if not response["success"]: 
			if self.log_level >= 0: loader.stop(success=False)
			self.crash(response=response)

		# get index.
		if self.log_level >= 0: 
			loader.mark(f"Indexing [{self.path}] & [{self.alias}:{self.remote}].")
		response = self.index(short=True)
		if not response["success"]: 
			if self.log_level >= 0: loader.stop(success=False)
			self.crash(response=response)

		# start success.
		if self.log_level >= 0: 
			loader.mark(f"Starting daemon {self.id}")
			loader.stop()

		# start.
		timestamp_count = 0
		while True:

			# check stop command.
			status = str(cache.get(id=self.cache_path, group="daemons"))
			if "*stop*" in status or "*unmounting*" in status:
				break

			# if file no longer exists stop daemon.
			if status == "none" or not Files.exists(self.path): 
				self.crash(f"ssht00ls daemon ({self.id}): Mounted directory [{self.path}] from [{self.alias}:{self.remote}] no longer exists.")

			# sync.
			response = self.sync(attempts=3, delay=[3, 5, 10])
			if self.log_level >= 1:
				dev0s.response.log(response=response)
			if not response["success"]: 
				self.crash(f"ssht00ls daemon ({self.id}) encountered an error while synchronizing: {response.error}", unmount=False)

			# set timestamp.
			do = False
			if self.sleeptime >= 1: do = True
			elif timestamp_count >= 1 / self.sleeptime:
				do = True
				timestamp_count = 0
			timestamp_count += 1
			if do:
				status = str(cache.get(id=self.cache_path, group="daemons"))
				if "*running*" in status:
					cache.set(id=self.cache_path, group="daemons", data=f"*running* (timestamp={Date().seconds_timestamp})")

			# sleep.
			time.sleep(self.sleeptime)

		# stop.
		self.stop()

		#
	def stop():
		response = self.unmount()
		if not response["success"]: self.crash(f"ssht00ls daemon ({self.id}) error: {response['error']}")
		cache.set(id=self.cache_path, data="*stopped*", group="daemons")
		if self.log_level >= 0: print(f"Stopped daemon {self.id}")
	def crash(self, error=None, response=None, unmount=True):
		if response != None: error = response["error"]
		if unmount:
			response = self.unmount()
			if not response["success"]: 
				cache.set(id=self.cache_path, data="*crashed*", group="daemons")
				raise ValueError(f"ssht00ls daemon ({self.id}) error: {response['error']}")
		cache.set(id=self.cache_path, data="*crashed*", group="daemons")
		raise ValueError(error)
	def unmount(self):
		if self.mode == "mount":
			if Files.exists(self.path):
				response = self.sync(attempts=5, delay=[1, 3, 5, 10, 15])
				if not response["success"]: return response
				cache.set(id=self.cache_path, data="*unmounting*", group="daemons")
				time.sleep(0.5)
				response = self.delete(self.path, remote=False, subpath=False,)
				if not response["success"]: return response
		return dev0s.response.success("Successfully unmounted.")
	def delete(self, path, remote=False, subpath=True):

		# sandbox.
		if isinstance(path, str):
			path = self.utils.serialize_path(gfp.clean(path))
			if subpath: path = self.fullpath(path, remote=remote)
			str_id = path
		else:
			new = []
			for i in path: 
				i = self.utils.serialize_path(gfp.clean(i))
				if subpath: i = self.fullpath(i, remote=remote)
				new.append(i)
			path = new
			str_id = f"{len(path)} path(s)"
		if self.sandbox: 
			if remote:
				msg = f"Sandbox enabled, skip deletion of {self.alias}:{str_id}."
				if self.log_level >= 0: print(msg)
				return dev0s.response.success(msg)
			else:
				msg = f"Sandbox enabled, skip deletion of {str_id}."
				if self.log_level >= 0: print(msg)
				return dev0s.response.success(msg)

		# logs.
		if self.log_level >= 1:
			if remote: print(f"Deleting {self.alias}:{str_id}.")
			else:print(f"Deleting {str_id}.")
		
		# local to remote.
		if remote:
			if isinstance(path, str):
				cmd = f"""ssh {DEFAULT_SSH_OPTIONS} {self.alias} " printf 'y' | rm -fr '{path}' " """
			else:
				c = 0
				cmd = f"""ssh {DEFAULT_SSH_OPTIONS} {self.alias} " """
				for i in path:
					if c == 0:
						cmd += f"""printf 'y' | rm -fr '{i}'"""
					else:
						cmd += f""" && printf 'y' | rm -fr '{i}'"""
					c += 1
				cmd += ' " '
			response = self.utils.execute(command=cmd,)
			if not response["success"]: return response
			#response = ssh.utils.test_path(alias=self.alias, path=path)
			#if response.error != None and f"{path} does not exist" not in response.error:
			#	return dev0s.response.error(f"Failed to delete {self.alias}:{path}, error: {response.error}")
			if response.output != "":
				return dev0s.response.error(f"Failed to delete {self.alias}:{str_id}, error: {output}")
			return dev0s.response.success(f"Successfully deleted {self.alias}:{str_id}")

		# remote to local.
		else:
			if isinstance(path, str):
				cmd = f"""printf 'y' | rm -fr '{path}' """
			else:
				cmd, c = "", 0
				for i in path:
					if c  == 0:
						cmd += f"""printf 'y' | rm -fr '{i}'"""
					else:
						cmd += f""" && printf 'y' | rm -fr '{i}'"""
					c += 1
			response = self.utils.execute(command=cmd)
			if not response["success"]: return response
			if response.output != "":
				return dev0s.response.error(f"Failed to delete {str_id}, error: {output}")
			return dev0s.response.success(f"Successfully deleted {str_id}")
	def index(self, short=False):

		# index.
		remote_response = self.ssync.index(path=self.remote, alias=self.alias, checks=False, log_level=self.log_level)
		if not remote_response["success"]:  return remote_response
		response = self.ssync.index(path=self.path, log_level=self.log_level)
		if not response["success"]:  return response

		# clean indexes.
		index, remote_index, clean_index, remote_clean_index, all_paths = response["index"], remote_response["index"], {}, {}, []
		for path, mtime in index.items():
			subpath = self.subpath(path)
			if subpath not in all_paths: 
				all_paths.append(subpath)
			subpath = subpath.split(" (d)")[0] # unpack after appended to all_paths.
			try:
				clean_index[subpath] = index[path]
			except KeyError:
				return dev0s.response.error(f"Should not happen(#278363). (subpath: {subpath}), (path: {path}), (index: {index}), (remote index: {remote_index}).")
		for path, mtime in remote_index.items():
			subpath = self.subpath(path)
			if subpath not in all_paths: 
				all_paths.append(subpath)
			subpath = subpath.split(" (d)")[0] # unpack after appended to all_paths.
			try:
				remote_clean_index[subpath] = remote_index[path]
			except KeyError:
				return dev0s.response.error(f"Should not happen(#739639). (subpath: {subpath}), (path: {path}), (index: {index}), (remote index: {remote_index}).")

		# mismatches.
		synchronized, mismatches = self.mismatches(clean_index, remote_clean_index, all_paths)

		# short mode.
		if short in ["automatic", "auto"]:
			if not synchronized: short = False
		if short:
			if self.last_index == {}:
				self.last_index["0"] = clean_index
			if self.last_remote_index == {}:
				self.last_remote_index["0"] = remote_clean_index
			return dev0s.response.success(f"Successfully indexed [{self.alias}:{self.path}] & [{self.path}].", {
				"synchronized":synchronized,
				"index":index,
				"remote_index":remote_index,
				"mismatches":mismatches,
			})

		# process mismatches.
		else: return self.process_mismatches(clean_index, remote_clean_index, mismatches)

		#
	def mismatches(self, clean_index, remote_clean_index, all_paths):
		# current version.
		mismatches = {}
		for fullpath in all_paths:
			subpath = fullpath.split(" (d)")[0]
			lmtime, rmtime, synchronized = None, None, True
			try: 
				lmtime = clean_index[subpath]
			except KeyError: a=1
			try:
				rmtime = remote_clean_index[subpath]
			except KeyError: a=1
			if lmtime != None or rmtime != None:
				synchronized = lmtime == rmtime
			# skip dirs with not the same mtime but that do both have a mtime.
			if " (d)" in fullpath and lmtime != None and rmtime != None and lmtime != rmtime:
				if self.log_level >= 3:
					print(f"Revert directory {subpath} from synchronized {synchronized} to True")
				synchronized = True
			if not synchronized: 
				mismatches[subpath] = {
					"path":subpath,
					"directory":" (d)" in fullpath,
					"empty_directory":" (d)" in fullpath and " (e)" in fullpath,
					"local_mtime":lmtime,
					"remote_mtime":rmtime,
				}
		synchronized = len(mismatches) == 0
		if self.log_level >= 3: print(f'synchronized: {synchronized} clean_index: {clean_index}, remote_clean_index: {remote_clean_index} mismatches: {mismatches}.')
		return synchronized, mismatches
		"""
		mismatches, likeys, rikeys = {}, list(index.keys()), list(remote_index.keys())
		for i in likeys:
			if i not in rikeys:
				try: lmtime = clean_index[i]
				except: lmtime = None
				try: rmtime = remote_clean_index[i]
				except: rmtime = None
				if lmtime != rmtime:
					mismatches[i] = {
						"path":i,
						"local_mtime":lmtime,
						"remote_mtime":rmtime,
					}
		for i in rikeys:
			if i not in likeys:
				try: lmtime = clean_index[i]
				except: lmtime = None
				try: rmtime = remote_clean_index[i]
				except: rmtime = None
				if lmtime != rmtime:
					mismatches[i] = {
						"path":i,
						"local_mtime":lmtime,
						"remote_mtime":rmtime,
					}
		return dev0s.response.error(f"Failed to synchronize [{self.alias}:{self.remote}] & [{self.path}], mismatches: {mismatches}].")
		"""
	def process_mismatches(self, clean_index, remote_clean_index, mismatches):

		# iterate.
		updates, deletions = {}, {}
		for subpath, info in mismatches.items():

			# vars.
			directory = info["directory"]
			empty_directory = info["empty_directory"]
			subpath = subpath.split(" (d)")[0] # just to be sure.
			lfullpath, rfullpath = self.fullpath(subpath), self.fullpath(subpath, remote=True)
			try: lmtime = clean_index[subpath]
			except KeyError: lmtime = None
			try: rmtime = remote_clean_index[subpath]
			except KeyError: rmtime = None
			last_lmtime = self.get_last_index(subpath)
			last_rmtime = self.get_last_index(subpath, remote=True)

			# wanted vars.
			local_to_remote, remote_to_local = False, False
			options = []
			
			# should not happen.
			if rmtime == None and lmtime == None: 
				self.set_last_index(clean_index) ; self.set_last_index(remote_clean_index, remote=True)
				return dev0s.response.error(f"No remote & local modification time present. (path: {subpath}), (rmtime: {rmtime}), (lmtime: {lmtime}), (last_rmtime: {last_rmtime}), (last_lmtime: {last_lmtime}), index: {clean_index}, remote index: {remote_clean_index}.")

			# one missing.
			elif rmtime == None or lmtime == None:
				
				# remote deleted a file.
				if rmtime == None and lmtime != None and (last_lmtime != None or last_rmtime != None):
					if self.log_level >= 3:
						print(f"Remote deleted a file (path: {subpath}) (rmtime: {rmtime}), (lmtime: {lmtime}), (last_lmtime: {last_lmtime}).")
					remote_to_local = True
					options.append("delete")

				# local deleted a file.
				elif rmtime != None and lmtime == None and last_lmtime != None:
					if self.log_level >= 3:
						print(f"Local deleted a file (path: {subpath}) (rmtime: {rmtime}), (lmtime: {lmtime}), (last_lmtime: {last_lmtime}).")
					local_to_remote = True
					options.append("delete")

				# local created a file.
				elif rmtime == None and lmtime != None and last_lmtime == None:
					if self.log_level >= 3:
						print(f"Local created a file (path: {subpath}) (rmtime: {rmtime}), (lmtime: {lmtime}), (last_lmtime: {last_lmtime}).")
					local_to_remote = True

				# remote created a file.
				elif rmtime != None and lmtime == None and last_lmtime == None:
					if self.log_level >= 3:
						print(f"Remote created a file (path: {subpath}) (rmtime: {rmtime}), (lmtime: {lmtime}), (last_lmtime: {last_lmtime}).")
					remote_to_local = True

				# should not happen.
				else:
					self.set_last_index(clean_index) ; self.set_last_index(remote_clean_index, remote=True)
					return dev0s.response.error(f"Should not happen (#3243443). (path: {subpath}), (rmtime: {rmtime}), (lmtime: {lmtime}), (last_rmtime: {last_rmtime}), (last_lmtime: {last_lmtime}), index: {clean_index}, remote index: {remote_clean_index}.")

			# both present.
			elif rmtime != None and lmtime != None:

				# same mtime.
				if str(rmtime) == str(lmtime):
					a=1
				
				# # synchronize remote to local.
				elif rmtime > lmtime:
					remote_to_local = True

				# # synchronize local to remote.
				elif rmtime < lmtime:
					local_to_remote = True

				# should not happen.
				else:
					self.set_last_index(clean_index) ; self.set_last_index(remote_clean_index, remote=True)
					return dev0s.response.error(f"Unable to compare rmtime: {rmtime} & lmtime: {lmtime}. (path: {subpath}), (rmtime: {rmtime}), (lmtime: {lmtime}), (last_rmtime: {last_rmtime}), (last_lmtime: {last_lmtime}), index: {clean_index}, remote index: {remote_clean_index}.")

			# exceptions.
			else:
				self.set_last_index(clean_index) ; self.set_last_index(remote_clean_index, remote=True)
				return dev0s.response.error(f"Should not happen (#407294). (path: {subpath}), (rmtime: {rmtime}), (lmtime: {lmtime}), (last_rmtime: {last_rmtime}), (last_lmtime: {last_lmtime}), index: {clean_index}, remote index: {remote_clean_index}.")

			# do not remove this exception.
			# it is required for safe edits, to make sure a dir never gets synced unless it is created / removed.
			# also required by the multiprocessing idexing.
			if directory and local_to_remote != None and remote_to_local != None and "delete" not in options and not empty_directory:
				pass
			else:

				# add to updates.
				if local_to_remote and remote_to_local:
					self.set_last_index(clean_index) ; self.set_last_index(remote_clean_index, remote=True)
					return dev0s.response.error(f"Can not synchronize both remote to local & local to remote (rmtime: {rmtime}) (lmtime: {lmtime}), (last_rmtime: {last_rmtime}) (last_lmtime: {last_lmtime}), index: {clean_index}, remote index: {remote_clean_index}.")
				if "delete" in options: 
					if self.log_level >= 1: 
						if local_to_remote:
							print(f"Deletion required {lfullpath} {self.alias}:{rfullpath} (rmtime: {rmtime}) (lmtime: {lmtime}), (last_rmtime: {last_rmtime}) (last_lmtime: {last_lmtime})")
						else:
							print(f"Deletion required {self.alias}:{rfullpath} {lfullpath} (rmtime: {rmtime}) (lmtime: {lmtime}), (last_rmtime: {last_rmtime}) (last_lmtime: {last_lmtime})")
					deletions[subpath] = {
						"options":options,
						"remote_to_local":remote_to_local,
						"local_to_remote":local_to_remote,
						"directory":directory,
						"empty_directory":empty_directory,}
				elif remote_to_local or local_to_remote:
					if self.log_level >= 1: 
						if local_to_remote:
							print(f"Update required {lfullpath} {self.alias}:{rfullpath} (rmtime: {rmtime}) (lmtime: {lmtime}), (last_rmtime: {last_rmtime}) (last_lmtime: {last_lmtime})")
						else:
							print(f"Update required {self.alias}:{rfullpath} {lfullpath} (rmtime: {rmtime}) (lmtime: {lmtime}), (last_rmtime: {last_rmtime}) (last_lmtime: {last_lmtime})")
					updates[subpath] = {
						"options":options,
						"remote_to_local":remote_to_local,
						"local_to_remote":local_to_remote,
						"directory":directory,
						"empty_directory":empty_directory,}
		# handler.
		self.set_last_index(clean_index) ; self.set_last_index(remote_clean_index, remote=True)
		return dev0s.response.success(f"Successfully indexed [{self.alias}:{rfullpath}] & [{lfullpath}].", {
			"synchronized":len(updates) == 0 and len(deletions) == 0,
			"updates":updates,
			"deletions":deletions,
			"index":clean_index,
			"remote_index":remote_clean_index,
		})
	def local_to_remote(self, path, info, directory=False, empty_directory=False, forced=False, delete=False, command=False):
		lfullpath, rfullpath = self.fullpath(path, append_slash=directory), self.fullpath(path, remote=True, append_slash=directory)
		if self.log_level >= 1: print(f"Synchronizing {lfullpath} to {self.alias}:{rfullpath} (directory: {directory}) (delete: {delete}) (forced: {forced}).")
		return self.ssync.push(
			path=lfullpath, 
			alias=self.alias, 
			remote=rfullpath, 
			directory=directory,
			empty_directory=empty_directory,
			delete=delete,
			forced=forced,
			safe=False,
			accept_new_host_keys=True,
			checks=False,
			command=command,
			log_level=self.log_level,)
	def remote_to_local(self, path, info, directory=False, empty_directory=False, forced=False, delete=False, command=False):
		lfullpath, rfullpath = self.fullpath(path, append_slash=directory), self.fullpath(path, remote=True, append_slash=directory)
		if self.log_level >= 1: print(f"Synchronizing {self.alias}:{rfullpath} to {lfullpath} (directory: {directory}) (delete: {delete}) (forced: {forced}).")
		return self.ssync.pull(
			path=lfullpath, 
			alias=self.alias, 
			remote=rfullpath, 
			directory=directory,
			empty_directory=empty_directory,
			delete=delete,
			forced=forced,
			safe=False,
			accept_new_host_keys=True,
			checks=False,
			command=command,
			log_level=self.log_level,)
	def get_last_index(self, id, remote=False):
		if not remote: indexes = self.last_index
		else: indexes = self.last_remote_index
		value = None
		for _, index in indexes.items():
			try: value = index[id]
			except KeyError: a=1
			if value not in ["None", None, "none"]:
				break
		if self.log_level >= 6:
			print(f"Last index ({id}) {value}) (remote: {remote}), indexes: {indexes}.")
		return value
	def set_last_index(self, index, remote=False, depth=25):
		if not remote: indexes = self.last_index
		else: indexes = self.last_remote_index
		count = len(indexes)
		if count > depth:
			new = {}
			for key,value in indexes.items():
				key = int(key)
				if key > 0:
					new[str(key-1)] = value
			new[str(depth)] = index
			if not remote: self.last_index = new
			else: self.last_remote_index = new
		else:
			indexes[str(len(indexes))] = index
			if not remote: self.last_lmtime = indexes
			else: self.last_rmtime = indexes
	def reset_last_index(self, id, remote=False):
		if remote == "both":
			self.reset_last_index(id, remote=False)
			self.reset_last_index(id, remote=True)
		else:
			if not remote: indexes = self.last_index
			else: indexes = self.last_remote_index
			for depth in list(indexes.keys()):
				try: 
					index = indexes[depth]
					index[id]
					indexes[depth][id] = None
				except KeyError: a=1
			if not remote: self.last_index = indexes
			else: self.last_remote_index = indexes
	def sync(self, attempts=1, delay=3):
		
		# sync.
		response = self.__sync__()
		if not response["success"]:

			# delay.
			attempts -= 1
			if attempts > 0:
				if isinstance(delay, str):
					time.sleep(delay)
				else:
					time.sleep(delay[0])
					delay.pop(0)

				# recusrive.
				return self.sync(attempts=attempts, delay=delay)

				# handle network error.
				#if "Operation timed out" in response["error"]:
				#	return self.sync(attempts=attempts, delay=30)

				# default error.
				#else: return response


			# default error.
			else: return response

		# success.
		return response
		#
	def __sync__(self, multiprocessing=True, max_batch_size=150):
		
		# correct batch size.
		# to high produces ssh-agent errors.
		if max_batch_size >= 150:
			max_batch_size = 150

		# check synced.
		"""
		response = self.synchronized()
		if not response["success"]:  return response
		elif response.synchronized:
			if self.log_level > 0:
				print(f"Directories [{self.alias}:{self.path}] & [{self.path}] are already synchronized.")
			if self.log_level >= 3:
				return dev0s.response.success(f"Directories [{self.alias}:{self.path}] & [{self.path}] are already synchronized, index: {response.index}, remote index: {response.remote_index}.")
			else:
				return dev0s.response.success(f"Directories [{self.alias}:{self.path}] & [{self.path}] are already synchronized.")
		"""

		# get index.
		response = self.index(short="auto")
		if not response["success"]:  return response
		elif response.synchronized:
			if self.log_level >= 1:
				print(f"Directories [{self.alias}:{self.path}] & [{self.path}] are already synchronized.")
			if self.log_level >= 3:
				return dev0s.response.success(f"Directories [{self.alias}:{self.path}] & [{self.path}] are already synchronized, index: {response.index}, remote index: {response.remote_index}.")
			else:
				return dev0s.response.success(f"Directories [{self.alias}:{self.path}] & [{self.path}] are already synchronized.")
		updates,deletions = response.unpack(["updates", "deletions"])
		if multiprocessing and len(updates) < 50:
			if self.log_level >= 0:
				print(f"Disabling multiprocessing due to small batch size ({len(updates)}).")
			multiprocessing = False

		# parallel multiprocessing.
		if multiprocessing:
		
			# order updates by dir depth from deepest to min.
			# create depth index.
			dir_updates, depths, max_depth = {}, {}, 0
			for path, info in updates.items():
				if info["directory"]: dir_updates[path] = info
				else:
					depth = len(gfp.clean(path, remove_double_slash=True, remove_first_slash=True, remove_last_slash=True).split("/"))
					if depth >= max_depth: max_depth = depth
					try: depths[str(depth)]
					except KeyError: depths[str(depth)] = {}
					depths[str(depth)][path] = info
			
			# add batches from highest depth to lowest.
			update_batches, batch_size, inside_batch_size, last_depth = {}, 0, 0, None
			for i in range(max_depth+1):
				depth, found = max_depth-i, True
				try: depths[str(depth)]
				except KeyError: found = False
				if found:
					if (last_depth != None and last_depth != depth) or (inside_batch_size >= max_batch_size): 
						last_depth = depth
						batch_size += 1
						inside_batch_size = 0
					for path, info in depths[str(depth)].items():
						if inside_batch_size >= max_batch_size: 
							last_depth = depth
							batch_size += 1
							inside_batch_size = 0
						try: update_batches[str(batch_size)]
						except KeyError: update_batches[str(batch_size)] = {}
						update_batches[str(batch_size)][path] = info
						inside_batch_size += 1
					del depths[str(depth)]
			if depths != {}:
				return dev0s.response.error(f"Should not happen(#234938). (depths: {depths}), (updates: {updates}).")

			# add directories.
			for path, info in dir_updates.items():
				if inside_batch_size >= max_batch_size: 
					batch_size += 1
					inside_batch_size = 0
				try: update_batches[str(batch_size)]
				except KeyError: update_batches[str(batch_size)] = {}
				update_batches[str(batch_size)][path] = info
				inside_batch_size += 1

			# sum together as one command
			#print("UPDAT BACTHES:",update_batches)
			sum = True

			# iterate updates.
			commands = {}
			for batch_size, batch in update_batches.items():
				commands[batch_size] = []
				for path, info in batch.items():
					if self.log_level >= 1: print(f"Updating {path}.")

					# local to remote.
					if info["local_to_remote"]:
						if info["directory"] in [True, "True", "TRUE", "true"]: 
							commands[batch_size] += [self.local_to_remote(path, info, directory=True, command=sum)]
						else: 
							commands[batch_size] += [self.local_to_remote(path, info, command=sum)]

					# remote to local.
					elif info["remote_to_local"]:
						if info["directory"] in [True, "True", "TRUE", "true"]: 
							commands[batch_size] += [self.remote_to_local(path, info, directory=True, command=sum)]
						else: 
							commands[batch_size] += [self.remote_to_local(path, info, command=sum)]

			# execute commands.
			if sum:
				for batch_size, batch in commands.items():
					loader, c = None, len(batch)
					if self.log_level >= 0: loader = f"Synchronizing {c} file(s)."
					msg = f"Successfully synchronized {c} file(s)."
					error = f"Failed to synchronize {c} file(s)."
					command = Array(array=batch).string(joiner=" & ")
					response = self.utils.execute(command=command, error=error, message=msg, loader=loader)
					if not response.success:
						response = self.utils.execute(command=command, error=error, message=msg, loader=loader)
						if not response.success:
							return response

		# no multiprocessing.
		else:

			# sum together as one command
			sum = False

			# iterate updates.
			dirs, commands, c = {}, [], 0
			for path, info in updates.items():
				if self.log_level >= 0: print(f"Updating {path}.")

				# local to remote.
				if info["local_to_remote"]:
					if info["directory"] in [True, "True", "TRUE", "true"]: dirs[path] = info
					else: 
						commands += [self.local_to_remote(path, info, command=sum)]
						c += 1

				# remote to local.
				elif info["remote_to_local"]:
					if info["directory"] in [True, "True", "TRUE", "true"]: dirs[path] = info
					else: 
						commands += [self.remote_to_local(path, info, command=sum)]
						c += 1

			# iterate excepted dirs.
			for path, info in dirs.items():

				# local to remote.
				if info["local_to_remote"]:
					commands += [self.local_to_remote(path, info, directory=True, command=sum)]
					c += 1

				# remote to local.
				elif info["remote_to_local"]:
					commands += [self.remote_to_local(path, info, directory=True, command=sum)]
					c += 1

			# execute commands.
			if sum:
				loader = None
				if self.log_level >= 0: loader = f"Synchronizing {c} file(s)."
				msg = f"Successfully synchronized {c} file(s)."
				error = f"Failed to synchronize {c} file(s)."
				command = Array(array=commands).string(joiner=" && ")
				response = self.utils.execute(command=command, error=error, message=msg, loader=loader)
				if not response.success:
					response = self.utils.execute(command=command, error=error, message=msg, loader=loader)
					if not response.success:
						return response

		# push deletions.
		if multiprocessing:
			local_deletions, remote_deletions = [], []
			for path, info in deletions.items():
				if info["remote_to_local"]:
					local_deletions.append(path)
				else:
					remote_deletions.append(path)
			if local_deletions != []:
				if self.log_level >= 0: loader = dev0s.console.Loader(f"Deleting {len(local_deletions)} local file(s).")
				response = self.delete(local_deletions, remote=False)
				if self.log_level >= 0: loader.stop(success=response["success"])
				if not response["success"]: return response
			if remote_deletions != []:
				if self.log_level >= 0: loader = dev0s.console.Loader(f"Deleting {len(remote_deletions)} remote file(s).")
				response = self.delete(remote_deletions, remote=True)
				if self.log_level >= 0: loader.stop(success=response["success"])
				if not response["success"]: return response
			for path, info in deletions.items():
				self.reset_last_index(path, remote="both")
		else:
			for path, info in deletions.items():
				if info["remote_to_local"]:
					response = self.delete(path, remote=False)
				else:
					response = self.delete(path, remote=True)
				if not response["success"]: return response
				self.reset_last_index(path, remote="both")

		# check synchronized index.
		response = self.index(short=True)
		if not response["success"]: return response
		elif not response.synchronized:
			return dev0s.response.error(f"Failed to synchronize [{self.alias}:{self.remote}] & [{self.path}], mismatches: {response.mismatches}].")

		# handler.
		return dev0s.response.success(f"Successfully synchronized [{self.alias}:{self.path}] & [{self.path}].")
	