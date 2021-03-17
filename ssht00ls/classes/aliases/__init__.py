#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.agent import agent

# the aliases object class.
class Aliases(Traceback):
	def __init__(self,
		# initialize as specific not global (optional).
		# 	the alias.
		alias=None,
		# 	the username.
		username=None,
		# 	the public ip.
		public_ip=None,
		# 	the private ip.
		private_ip=None,
		# 	the public port.
		public_port=None,
		# 	the private port.
		private_port=None,
		# 	the path to the public key.
		public_key=None,
		# 	the path to the private key.
		private_key=None,
		# 	the smart card boolean.
		smartcard=False,
		#	the smart card serial numbers.
		serial_numbers=[],
		# 	the log level.
		log_level=dev0s.defaults.options.log_level,
	):
		
		# docs.
		DOCS = {
			"module":"ssht00ls.aliases", 
			"initialized":True,
			"description":[], 
			"chapter": "Aliases", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.aliases", raw_traceback="ssht00ls.classes.aliaes.Aliases")

		# specific variables.
		self.specific = alias != None
		self.alias = alias
		self.username = username
		self.public_ip = public_ip
		self.private_ip = private_ip
		self.public_port = public_port
		self.private_port = private_port
		self.private_key = private_key
		self.public_key = public_key
		self.smartcard = smartcard
		self.serial_numbers = serial_numbers
		self.log_level = log_level

		# sync non interactive.
		#self.sync()

		#
	def list(self):
		CONFIG.load()
		array, dictionary = [], {}
		for i in list(CONFIG["aliases"].keys()):
			if len(i) >= len("example.com ") and i[:len("example.com ")] == "example.com ":
				a=1 # skip
			elif i in ["None", None]:
				a=1 # skip
			else:
				array.append(i)
				dictionary[i] = dict(CONFIG["aliases"][i])
		return dev0s.response.success(f"Successfully listed {len(array)} aliases.", {
			"aliases":array,
			"array":array,
			"dictionary":dictionary,
		})
	def iterate(self):
		items = []
		for key in self.list()["aliases"]: items.append([key, CONFIG["aliases"][key]])
		return items
	def check(self, 
		# the alias to check.
		alias=None, 
		# the info to check.
		# 	adds / replaces the current (except the exceptions).
		info={},
		# the info key exceptions.
		exceptions=[],
		# the info value exceptions.
		value_exceptions=[],
		# create if not present (must also specify all required info when enabled).
		create=False,
	):

		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# get info.
		current_info, exists, edits = {}, True, 0
		try: current_info = CONFIG["aliases"][alias]
		except KeyError:
			exists = False
			if not create:
				return dev0s.response.error(f"Alias [{alias}] does not exist.")


		# check existing config.
		if exists:
			edits, current_info_keys = 0, list(current_info.keys())
			for info_key, info_value in info.items():
				do = False
				if info_key not in exceptions and info_key not in current_info_keys: do = True
				elif info_value not in value_exceptions and info_key in current_info_keys and info_value != current_info[info_key]: do = True
				if do:
					current_info[info_key] = info_value
					edits += 1

		# create non existant.
		elif not exists and create:
			username,public_ip,private_ip,public_port,private_port,private_key,public_key,passphrase,smartcard,serial_numbers,pin,save,checks = Dictionary(info).unpack({
				"username":None, 
				"public_ip":None,
				"private_ip":None,
				"public_port":None,
				"private_port":None,
				"private_key":None,
				"public_key":None,
				"passphrase":None,
				"smartcard":None,
				"serial_numbers":None,
				"pin":None,
				"save":True,
				"checks":True, })
			return self.create(
				alias=alias,
				# the users.
				username=username, 
				# the ip of the server.
				public_ip=public_ip,
				private_ip=private_ip,
				# the port of the server.
				public_port=public_port,
				private_port=private_port,
				# the path to the private & public key.
				private_key=private_key,
				public_key=public_key,
				# the keys passphrase.
				passphrase=passphrase,
				# smart card.
				smartcard=smartcard,
				# the smartcards serial numbers.
				serial_numbers=serial_numbers,
				# the smart cards pincode.
				pin=pin,
				# save to configuration.
				save=save,
				# do checks.
				checks=checks, )

		# save edits.
		if edits > 0:
			CONFIG["aliases"][alias] = current_info
			utils.save_config_safely()

		# handler.
		return dev0s.response.success(f"Successfully checked alias {alias}.")

		#
	def check_duplicate(self, alias=None):
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias
		# check.
		try: CONFIG["aliases"][alias]
		except KeyError:
			return dev0s.response.success(f"Alias {alias} does not exist.")
		return dev0s.response.error(f"Alias {alias} already exists.")
	def info(self, alias=None):
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias
		# check.
		response = self.check(alias)
		if not response["success"]: return response
		info = dict(CONFIG["aliases"][alias])
		if self.public(info["public_ip"], info["private_ip"]):
			info["ip"], info["port"] = info["public_ip"], info["public_port"]
		else:
			info["ip"], info["port"] = info["private_ip"], info["private_port"]
		return dev0s.response.success(f"Successfully listed the info of alias {alias}.", {
			"info":info,
		})
	def delete(self, alias=None):
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias
		# check.
		response = self.check(alias)
		if not response["success"]: return response
		del CONFIG["aliases"][alias]
		utils.save_config_safely()
		return dev0s.response.success(f"Successfully deleted alias {alias}.")
	def edit(self, 
		# the alias.
		alias=None,
		# the edits (dict).
		# 	adds / replaces the current (except the exceptions).
		edits={},
		# the edits key exceptions.
		exceptions=[],
		# the edits value exceptions.
		value_exceptions=[None],
		# save the edits.
		save=True,
		# the log level.
		log_level=dev0s.defaults.options.log_level,
	):
		def edit_dict(dictionary={}, edits={}):
			c = 0
			for key, value in edits.items():
				if isinstance(value, (list, Array)):
					found = True
					try: dictionary[key]
					except KeyError: found = False
					if not found:
						dictionary[key] = value
					else:
						for i in value:
							if value not in dictionary[key]:
								dictionary[key].append(value)
				elif isinstance(value, (dict, Dictionary)):
					if isinstance(value, (Dictionary)):
						value = value.dictionary
					found = True
					try: dictionary[key]
					except KeyError: found = False
					if found:
						dictionary[key], lc = edit_dict(dictionary=dictionary[key], edits=value)
						c += lc
					else:
						if log_level >= 0:
							print(f"Editing {alias} config {key}: {value}.")
						dictionary[key] = value
						c += 1
				elif key not in exceptions and value not in value_exceptions:
					if log_level >= 0:
						print(f"Editing {alias} config {key}: {value}.")
					dictionary[key] = value
					c += 1
			return dictionary, c
		
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias
		
		# passphrase.
		edit_count = 0
		if "passphrase" in list(edits.keys()) and edits["passphrase"] not in value_exceptions:
			# check encryption activated.
			if edits["passphrase"] not in [False, "", "none", "None"]:
				if not ssht00ls_agent.activated:
					return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")
				response = ssht00ls_agent.encryption.encrypt(edits["passphrase"])
				if not response["success"]: return response
				CONFIG["aliases"][alias]["smartcard"] = False
				CONFIG["aliases"][alias]["passphrase"] = response.encrypted.decode()
			else:
				CONFIG["aliases"][alias]["smartcard"] = True
				CONFIG["aliases"][alias]["passphrase"] = ""
			edit_count += 1
			del edits["passphrase"]
		
		# pin.
		if "pin" in list(edits.keys()) and edits["pin"] not in value_exceptions:
			# check encryption activated.
			if edits["pin"] not in [False, "", "none", "None"]:
				if not ssht00ls_agent.activated:
					return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")
				response = ssht00ls_agent.encryption.encrypt(edits["pin"])
				if not response["success"]: return response
				CONFIG["aliases"][alias]["smartcard"] = True
				CONFIG["aliases"][alias]["pin"] = response.encrypted.decode()
			else:
				CONFIG["aliases"][alias]["pin"] = ""
			del edits["pin"]

		# check.
		response = self.check(alias)
		if not response["success"]: return response
		dictionary, c = edit_dict(dictionary=CONFIG["aliases"][alias], edits=edits)
		if (edit_count > 0 or c > 0) and save:
			CONFIG["aliases"][alias] = dictionary
			utils.save_config_safely()
		if edit_count > 0 or c > 0:
			return dev0s.response.success(f"Successfully saved {c} edits for alias {alias}.")
		else:
			return dev0s.response.error(f"No edits were specified.")
	def create(self, 
		# the alias.
		alias=None,
		# the users.
		username=None, 
		# the ip of the server.
		public_ip=None,
		private_ip=None,
		# the port of the server.
		public_port=None,
		private_port=None,
		# the path to the private & public key.
		private_key=None,
		public_key=None,
		# the keys passphrase.
		passphrase=None,
		# smart card.
		smartcard=None,
		# the smart card serial numbers (list).
		serial_numbers=None,
		# the smart cards pincode.
		pin=None,
		# save to configuration.
		save=True,
		# do checks.
		checks=True,
		# serialized all parameters as dict, except: [save].
		serialized={},
	):

		# serialized
		if serialized != {}:
			username, public_ip, private_ip, public_port, private_port, private_key, public_key, passphrase, smartcard, serial_numbers, pin, alias = Dictionary(serialized).unpack({
				"username":None,
				"public_ip":None,
				"private_ip":None,
				"public_port":None,
				"private_port":None,
				"private_key":None,
				"public_key":None,
				"passphrase":None,
				"smartcard":None,
				"serial_numbers":None,
				"pin":None,
				"alias":None,
			})
		
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias
			if username == None: username = self.username
			if public_ip == None: public_ip = self.public_ip
			if private_ip == None: private_ip = self.private_ip
			if public_port == None: public_port = self.public_port
			if private_port == None: private_port = self.private_port
			if private_key == None: private_key = self.private_key
			if public_key == None: public_key = self.public_key
			if smartcard == None: smartcard = self.smartcard
			if serial_numbers == None: serial_numbers = self.serial_numbers


		# checks.
		response = dev0s.response.parameters.check(
			traceback=self.__traceback__(function="create"),
			parameters={
				"alias":alias,
				"username":username,
				"public_ip":public_ip,
				"private_ip":private_ip,
				"public_port":public_port,
				"private_port":private_port,
				"private_key":private_key,
				"public_key":public_key,
				"smartcard:bool":smartcard,
				"serial_numbers:list,Array":serial_numbers,
			})
		if not response["success"]: return response
		has_passphrase = True
		if smartcard:
			response = dev0s.response.parameters.check({
				"pin":pin,
			}, default=None, traceback=self.__traceback__(function="create"))
			if not response["success"]: return response
		else:
			if passphrase in [None, "", "None", "none"]:
				has_passphrase = False
			#response = dev0s.response.parameters.check({
			#	"passphrase":passphrase,
			#}, default=None, traceback=self.__traceback__(function="create"))
			#if not response["success"]: return response

		# check encryption activated.
		if has_passphrase and checks and not ssht00ls_agent.activated:
			return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")

		# duplicate.
		if checks:
			response = self.check_duplicate(alias)
			if not response["success"]: return response

		# keys.
		private_key = dev0s.env.fill(private_key)
		public_key = dev0s.env.fill(public_key)
		if not Files.exists(private_key):
			return dev0s.response.error(f"Private key {private_key} does not exist.")
		if not Files.exists(public_key):
			return dev0s.response.error(f"Public key {public_key} does not exist.")

		# info.
		json_config, config = {}, ""
		if not self.public(public_ip=public_ip, private_ip=private_ip):
			ip = private_ip
			port = private_port
		else:
			ip = public_ip
			port = public_port
		
		# create config.
		config += f"\nHost {alias}"
		json_config["public_ip"] = public_ip
		json_config["private_ip"] = private_ip
		config += "\n    HostName {}".format(ip)
		json_config["public_port"] = public_port
		json_config["private_port"] = private_port
		config += "\n    Port {}".format(port)
		json_config["username"] = username
		config += "\n    User {}".format(username)
		config += "\n    ForwardAgent yes"
		config += "\n    PubKeyAuthentication yes"
		#config += "\n    IdentitiesOnly yes"
		json_config["public_key"] = public_key
		if not smartcard:
			json_config["private_key"] = private_key
			json_config["smartcard"] = False
			config += "\n    IdentityFile {}".format(private_key)
		else:
			json_config["private_key"] = smartcards.path
			json_config["smartcard"] = True
			config += "\n    PKCS11Provider {}".format(smartcards.path)

		# passphrase.
		if has_passphrase:
			if smartcard:
				response = ssht00ls_agent.encryption.encrypt(str(pin))
				if not response["success"]: return response
				json_config["pin"] = response["encrypted"].decode()
			else:
				response = ssht00ls_agent.encryption.encrypt(str(passphrase))
				if not response["success"]: return response
				json_config["passphrase"] = response["encrypted"].decode()
		else:
			json_config["passphrase"] = ""
			json_config["pin"] = ""

		# serial numbers.
		json_config["serial_numbers"] = serial_numbers

		# save.
		if save:
			CONFIG["aliases"][alias] = json_config
			utils.save_config_safely()

		# response.
		return dev0s.response.success(f"Successfully created alias [{alias}].", {
			"json":json_config,
			"str":config,
		})
	def sync(self, aliases=["*"], interactive=None, log_level=None):
		if interactive == None: interactive = dev0s.defaults.options.interactive
		if log_level == None: log_level = self.log_level

		# all aliases.
		if "*" in aliases or "all" in aliases:
			if self.specific:
				aliases = [self.alias]
			else:
				aliases = self.list()["array"]
		_aliases_ = list(aliases)
		
		# loader.
		if log_level >= 0:
			loader = dev0s.console.Loader(f"Synchronizing {len(_aliases_)} aliases.")

		# check ssh dir.
		if not Files.exists(f"{dev0s.defaults.vars.home}/.ssh"): os.system(f"mkdir {dev0s.defaults.vars.home}/.ssh && chown -R {dev0s.defaults.vars.user}:{dev0s.defaults.vars.group} {dev0s.defaults.vars.home}/.ssh && chmod 700 {dev0s.defaults.vars.home}/.ssh")
		
		# check include.
		include = f"include ~/.ssht00ls/lib/aliases"
		if not Files.exists(f"{dev0s.defaults.vars.home}/.ssh/config"): 
			Files.save(f"{dev0s.defaults.vars.home}/.ssh/config", include)
			os.system(f"chown {dev0s.defaults.vars.user}:{dev0s.defaults.vars.group} {dev0s.defaults.vars.home}/.ssh/config && chmod 770 {dev0s.defaults.vars.home}/.ssh/config")
		if include not in Files.load(f"{dev0s.defaults.vars.home}/.ssh/config"):
			data = Files.load(f"{dev0s.defaults.vars.home}/.ssh/config")
			new, included = "", False
			for line in data.split("\n"):
				if len(line) > 0 and line[0] == "#":
					a=1
				elif not included:
					new += include+"\n"
					included = True
				new += line+"\n"
			Files.save(f"{dev0s.defaults.vars.home}/.ssh/config", new)

		# iterate.
		aliases, c = "", 0
		for alias in _aliases_:
			info = CONFIG["aliases"][alias]
			if "example.com " not in alias:

				# check existance.
				response = self.check(alias=alias)
				if not response.success: 
					if log_level >= 0: loader.stop(success=False)
					return response

				# proceed.
				checked = Dictionary(path=False, dictionary=info).check(default={
					"username":None,
					"public_ip":None,
					"private_ip":None,
					"public_port":None,
					"private_port":None,
					"private_key":None,
					"public_key":None,
					"passphrase":None,
					"smartcard":None,
					"serial_numbers":[],
					"pin":None,
				})
				if checked["smartcard"] not in [True, False]:
					checked["smartcard"] = False
				if Dictionary(checked) != Dictionary(CONFIG["aliases"][alias]):
					CONFIG["aliases"][alias] = checked
					utils.save_config_safely()
				if isinstance(checked["private_key"], str):
					checked["private_key"] = dev0s.env.fill(checked["private_key"])
					Files.chmod(checked["private_key"], permission=700)
				if isinstance(checked["public_key"], str):
					checked["public_key"] = dev0s.env.fill(checked["public_key"])
					Files.chmod(checked["public_key"], permission=700)
				if interactive:
					passphrase, has_passphrase, new_passphrase = None, True, True
					if checked["smartcard"] == True:
						if checked["pin"] in [False, None, "", "none", "None"]:
							if checked["pin"] in [False, "", "none", "None"]:
								has_passphrase = False
							else:
								if log_level >= 0: loader.hold()
								passphrase =  getpass.getpass(f"Enter the pin of smartcard [{gfp.clean(checked['private_key'])}]:")
								if log_level >= 0: loader.release()
						else:
							# check encryption activated.
							if not ssht00ls_agent.activated:
								
								if log_level >= 0: loader.stop(success=False)
								return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")
							new_passphrase = False
							response = ssht00ls_agent.encryption.decrypt(checked["pin"])
							if not response.success: 
								if log_level >= 0: loader.stop(success=False)
								return response
							passphrase = response.decrypted.decode()
					else:	
						if checked["passphrase"] in [False, None, "", "none", "None"]:
							if checked["passphrase"] in [False, "", "none", "None"]:
								has_passphrase = False
							else:
								if log_level >= 0: loader.hold()
								passphrase =  getpass.getpass(f"Enter the passphrase of key [{gfp.clean(checked['private_key'])}] (leave '' for no passphrase):")
								if log_level >= 0: loader.release()
								if checked["passphrase"] in [False, "", "none", "None"]:
									has_passphrase = False
									CONFIG["aliases"][alias]["passphrase"] = ""
									utils.save_config_safely()
						else:
							# check encryption activated.
							if not ssht00ls_agent.activated:
								
								if log_level >= 0: loader.stop(success=False)
								return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")
							new_passphrase = False
							response = ssht00ls_agent.encryption.decrypt(checked["passphrase"])
							if not response.success: 
								if log_level >= 0: loader.stop(success=False)
								return response
							passphrase = response.decrypted.decode()
					if has_passphrase:
						if checked["smartcard"] == True:
							response = agent.check(public_key=checked["public_key"], raw=True)
						else:
							response = agent.check(public_key=checked["public_key"], raw=False)
						if not response["success"]:
							if "is not added" not in response["error"]: 
								if log_level >= 0: loader.stop(success=False)
								return response
							elif "is not added" in response["error"]:
								if checked["smartcard"]:
									response = agent.add(private_key=checked["private_key"], smartcard=True, pin=passphrase)
									if not response["success"]: 
										if log_level >= 0: loader.stop(success=False)
										return response
								else:
									response = agent.add(private_key=checked["private_key"], passphrase=passphrase)
									if not response["success"]: 
										if log_level >= 0: loader.stop(success=False)
										return response
						if new_passphrase:
							# check encryption activated.
							if not ssht00ls_agent.activated:
								
								if log_level >= 0: loader.stop(success=False)
								return dev0s.response.error(f"The {ssht00ls_agent.id} encryption requires to be activated.")
							response = ssht00ls_agent.encryption.encrypt(passphrase)
							if not response.success: 
								if log_level >= 0: loader.stop(success=False)
								return response
							if checked["smartcard"] == True:
								CONFIG["aliases"][alias]["pin"] = response.encrypted.decode()
							else:
								CONFIG["aliases"][alias]["passphrase"] = response.encrypted.decode()
							utils.save_config_safely()
				response = self.create(save=False, checks=False, serialized=Dictionary(dictionary=checked).append({"alias":alias}))
				if not response["success"]: 
					if log_level >= 0: loader.stop(success=False)
					return response
				self.__edit_alias_lib__(alias, response["str"])
				aliases += response["str"]
				c += 1

		# handler.
		if log_level >= 0: loader.stop()
		return dev0s.response.success(f"Successfully synchronized {c} alias(es).")
	def public(self, public_ip=None, private_ip=None):

		# cache.
		response = cache.load(f"ping/{public_ip}/{private_ip}")

		# get.
		response = dev0s.network.ping(private_ip, timeout=0.5)
		if not response.success: response.crash()
		public = not (NETWORK_INFO["public_ip"] == public_ip and response.up == True)
		return public
	# edit aliases lib.
	def __edit_alias_lib__(self, alias, data):


		# load lib & get lib depth from the aliases.
		try:
			lib = Files.load(f"{dev0s.defaults.vars.home}/.ssht00ls/lib/aliases")
		except FileNotFoundError:
			lib = ""

		# normalize.
		lib = lib.replace("\n\n","\n").replace("\n\n","\n").replace("\n\n","\n").replace("\n\n","\n")
		while True:
			if " \n" in lib: lib = lib.replace(" \n","\n")
			if "Host  " in lib: lib = lib.replace("Host  ","Host ")
			else: break

		# add.
		string = String()
		if f"Host {alias}" not in lib:
			lib = lib + "\n" + data
		else:
			before, after, status = "", "", "before"
			for line in lib.split("\n"):
				if f"Host {alias}" in line:
					status = "detected"
				elif string.line_indent(line=line) == 0 and status == "detected":
					status = "after"
				if status in ["before"]:
					before += line+"\n"
				elif status in ["after"]:
					after += line+"\n"
			lib = before + "\n" + data + "\n" + after

		# normalize.
		lib = lib.replace("\n\n","\n").replace("\n\n","\n").replace("\n\n","\n").replace("\n\n","\n")
		while True:
			if len(lib) > 0 and lib[0] == "\n": lib = lib[1:]
			elif len(lib) >= len("\n\n") and lib[:len("\n\n")] == "\n\n": lib = lib[2:]
			else: break

		# save.
		Files.save(f"{dev0s.defaults.vars.home}/.ssht00ls/lib/aliases", lib)

	# iterate.
	def __iter__(self):
		return iter(self.list()["array"])

	# representation.
	def __str__(self):
		# always keep as str alias when filled fix to the frequent mistake by calling X.alias instead of X.alias_
		if self.alias != None:
			return self.alias
		else:
			return self.traceback
	def __repr__(self):
		return str(self)
		#
	#
	
# initialized objects.
aliases = Aliases()

"""


# --------------------
# SSH Config.

# create an ssh alias for the key.
response = aliases.create(self, 
	# the servers name.
	server="myserver", 
	# the username.
	username="administrator", 
	# the ip of the server.
	ip="0.0.0.0",
	# the port of the server.
	port=22,
	# the path to the private key.
	key="/path/to/mykey/private_key",
	# smart card.
	smartcard=False,)
# if successfull you can use the ssh alias <username>.<server>
# $ ssh <username>.<server>

# create an ssh alias for a smart card.
response = aliases.create(self, 
	# the servers name.
	server="myserver", 
	# the username.
	username="administrator", 
	# the ip of the server.
	ip="0.0.0.0",
	# the port of the server.
	port=22,
	# the path to the private key.
	key=smartcard.path,
	# smart card.
	smartcard=True,)

```


"""
