#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.agent import agent

# the aliases object class.
class Aliases(syst3m.objects.Traceback):
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
		# 	the log level.
		log_level=syst3m.defaults.options.log_level,
	):
		
		# defaults.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.aliases", raw_traceback="ssht00ls.classes.aliaes.Aliases")

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
		self.log_level = log_level

		# sync non interactive.
		#self.sync(interactive=False)

		#
	def list(self):
		CONFIG.load()
		array, dictionary = [], {}
		for i in list(CONFIG["aliases"].keys()):
			if len(i) >= len("example.com ") and i[:len("example.com ")] == "example.com ":
				a=1
			else:
				array.append(i)
				dictionary[i] = dict(CONFIG["aliases"][i])
		return r3sponse.success(f"Successfully listed {len(array)} aliases.", {
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
				return r3sponse.error(f"Alias [{alias}] does not exist.")


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
			username,public_ip,private_ip,public_port,private_port,private_key,public_key,passphrase,smartcard,pin,save,checks = Dictionary(info).unpack({
				"username":None, 
				"public_ip":None,
				"private_ip":None,
				"public_port":None,
				"private_port":None,
				"private_key":None,
				"public_key":None,
				"passphrase":None,
				"smartcard":None,
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
		return r3sponse.success(f"Successfully checked alias {alias}.")

		#
	def check_duplicate(self, alias=None):
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias
		# check.
		try: CONFIG["aliases"][alias]
		except KeyError:
			return r3sponse.success(f"Alias {alias} does not exist.")
		return r3sponse.error(f"Alias {alias} already exists.")
	def info(self, alias=None):
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias
		# check.
		response = self.check(alias)
		if not response["success"]: return response
		return r3sponse.success(f"Successfully listed the info of alias {alias}.", {
			"info":CONFIG["aliases"][alias],
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
		return r3sponse.success(f"Successfully deleted alias {alias}.")
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
		log_level=syst3m.defaults.options.log_level,
	):
		def edit_dict(dictionary={}, edits={}):
			c = 0
			for key, value in edits.items():
				if isinstance(value, dict):
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
		edits = 0
		if "passphrase" in list(edits.keys()) and edits["passphrase"] not in value_exceptions:
			# check encryption activated.
			if edits["passphrase"] not in [False, "", "none", "None"]:
				if not encryption.activated:
					return r3sponse.error("The encryption requires to be activated.")
				response = encryption.encryption.encrypt(edits["passphrase"])
				if not response["success"]: return response
				CONFIG["aliases"][alias]["smartcard"] = False
				CONFIG["aliases"][alias]["passphrase"] = response.encrypted.decode()
			else:
				CONFIG["aliases"][alias]["smartcard"] = True
				CONFIG["aliases"][alias]["passphrase"] = ""
			edits += 1
			del edits["passphrase"]
		
		# pin.
		if "pin" in list(edits.keys()) and edits["pin"] not in value_exceptions:
			# check encryption activated.
			if edits["pin"] not in [False, "", "none", "None"]:
				if not encryption.activated:
					return r3sponse.error("The encryption requires to be activated.")
				response = encryption.encryption.encrypt(edits["pin"])
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
		if (edits > 0 or c > 0) and save:
			CONFIG["aliases"][alias] = dictionary
			utils.save_config_safely()
		if edits > 0 or c > 0:
			return r3sponse.success(f"Successfully saved {c} edits for alias {alias}.")
		else:
			return r3sponse.error(f"No edits were specified.")
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
		# the smart cards pincode.
		pin=None,
		# save to configuration.
		save=True,
		# do checks.
		checks=True,
		# serialized all parameters as dict, except: [save].
		serialized={},
	):

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

		# serialized
		if serialized != {}:
			username, public_ip, private_ip, public_port, private_port, private_key, public_key, passphrase, smartcard, pin, alias = Dictionary(serialized).unpack({
				"username":None,
				"public_ip":None,
				"private_ip":None,
				"public_port":None,
				"private_port":None,
				"private_key":None,
				"public_key":None,
				"passphrase":None,
				"smartcard":None,
				"pin":None,
				"alias":None,
			})
		
		# check specific.
		if self.specific:
			if alias == None: alias = self.alias

		# checks.
		response = r3sponse.check_parameters({
			"alias":alias,
			"username":username,
			"public_ip":public_ip,
			"private_ip":private_ip,
			"public_port":public_port,
			"private_port":private_port,
			"private_key":private_key,
			"public_key":public_key,
			#"smartcard:bool":smartcard,
		}, empty_value=None, traceback=self.__traceback__(function="create"))
		if not response["success"]: return response
		if smartcard:
			response = r3sponse.check_parameters({
				"pin":pin,
			}, empty_value=None, traceback=self.__traceback__(function="create"))
			if not response["success"]: return response
		else:
			response = r3sponse.check_parameters({
				"passphrase":passphrase,
			}, empty_value=None, traceback=self.__traceback__(function="create"))
			if not response["success"]: return response

		# check encryption activated.
		if checks and not encryption.activated:
			return r3sponse.error("The encryption requires to be activated.")

		# duplicate.
		if checks:
			response = self.check_duplicate(alias)
			if not response["success"]: return response

		# keys.
		private_key = syst3m.env.fill(private_key)
		public_key = syst3m.env.fill(public_key)
		if not Files.exists(private_key):
			return r3sponse.error(f"Private key {private_key} does not exist.")
		if not Files.exists(public_key):
			return r3sponse.error(f"Public key {public_key} does not exist.")

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
		if save:
			if passphrase not in [False, "", "none", None, "None"]:
				if smartcard:
					response = encryption.encryption.encrypt(str(pin))
					if not response["success"]: return response
					json_config["pin"] = response["encrypted"].decode()
				else:
					response = encryption.encryption.encrypt(str(passphrase))
					if not response["success"]: return response
					json_config["passphrase"] = response["encrypted"].decode()
			else:
				json_config["passphrase"] = ""
				json_config["pin"] = ""

		# save.
		if save:
			CONFIG["aliases"][alias] = json_config
			utils.save_config_safely()

		# response.
		return r3sponse.success(f"Successfully created alias [{alias}].", {
			"json":json_config,
			"str":config,
		})
	def sync(self, aliases=["*"], interactive=None, log_level=None):
		if interactive == None: interactive = INTERACTIVE
		if log_level == None: log_level = self.log_level

		# all aliases.
		if "*" in aliases or "all" in aliases:
			if self.specific:
				aliases = [self.alias]
			else:
				aliases = list(CONFIG["aliases"].keys())
		_aliases_ = list(aliases)
		
		# loader.
		if log_level >= 0:
			loader = syst3m.console.Loader(f"Synchronizing {len(_aliases_)} aliases.")

		# check ssh dir.
		if not Files.exists(f"{syst3m.defaults.vars.home}/.ssh"): os.system(f"mkdir {syst3m.defaults.vars.home}/.ssh && chown -R {syst3m.defaults.vars.user}:{syst3m.defaults.vars.group} {syst3m.defaults.vars.home}/.ssh && chmod 700 {syst3m.defaults.vars.home}/.ssh")
		
		# check include.
		include = f"include ~/.ssht00ls/lib/aliases"
		if not Files.exists(f"{syst3m.defaults.vars.home}/.ssh/config"): 
			Files.save(f"{syst3m.defaults.vars.home}/.ssh/config", include)
			os.system(f"chown {syst3m.defaults.vars.user}:{syst3m.defaults.vars.group} {syst3m.defaults.vars.home}/.ssh/config && chmod 770 {syst3m.defaults.vars.home}/.ssh/config")
		if include not in Files.load(f"{syst3m.defaults.vars.home}/.ssh/config"):
			data = Files.load(f"{syst3m.defaults.vars.home}/.ssh/config")
			new, included = "", False
			for line in data.split("\n"):
				if len(line) > 0 and line[0] == "#":
					a=1
				elif not included:
					new += include+"\n"
					included = True
				new += line+"\n"
			Files.save(f"{syst3m.defaults.vars.home}/.ssh/config", new)

		# iterate.
		aliases, c = "", 0
		for alias in _aliases_:
			info = CONFIG["aliases"][alias]
			if "example.com " not in alias:
				
				# deprications.
				if "user" in info:
					user = info["user"]
					del info["user"]
					info["username"] = user
					CONFIG["aliases"][alias]["user"] = user
					utils.save_config_safely()
				
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
					"pin":None,
				})
				if Dictionary(checked) != Dictionary(CONFIG["aliases"][alias]):
					CONFIG["aliases"][alias] = checked
					utils.save_config_safely()
				if isinstance(checked["private_key"], str):
					checked["private_key"] = syst3m.env.fill(checked["private_key"])
					Files.chmod(checked["private_key"], permission=700)
				if isinstance(checked["public_key"], str):
					checked["public_key"] = syst3m.env.fill(checked["public_key"])
					Files.chmod(checked["public_key"], permission=700)
				if interactive:
					passphrase, has_passphrase, new_passphrase = None, True, True
					if checked["smartcard"] == True:
						if checked["pin"] in [False, None, "", "none", "None"]:
							if checked["pin"] in [False, "", "none", "None"]:
								has_passphrase = False
							else:
								passphrase =  getpass.getpass(f"Enter the passphrase of key {checked['private_key']}:")
						else:
							# check encryption activated.
							if not encryption.activated:
								
								if log_level >= 0: loader.stop(success=False)
								return r3sponse.error("The encryption requires to be activated.")
							new_passphrase = False
							response = encryption.encryption.decrypt(checked["pin"])
							if not response.success: 
								if log_level >= 0: loader.stop(success=False)
								return response
							passphrase = response.decrypted.decode()
					else:	
						if checked["passphrase"] in [False, None, "", "none", "None"]:
							if checked["passphrase"] in [False, "", "none", "None"]:
								has_passphrase = False
							else:
								passphrase =  getpass.getpass(f"Enter the passphrase of key {checked['private_key']}:")
						else:
							# check encryption activated.
							if not encryption.activated:
								
								if log_level >= 0: loader.stop(success=False)
								return r3sponse.error("The encryption requires to be activated.")
							new_passphrase = False
							response = encryption.encryption.decrypt(checked["passphrase"])
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
							if not encryption.activated:
								
								if log_level >= 0: loader.stop(success=False)
								return r3sponse.error("The encryption requires to be activated.")
							response = encryption.encryption.encrypt(passphrase)
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
				aliases += response["str"]
				c += 1

		# save lib.
		Files.save(f"{syst3m.defaults.vars.home}/.ssht00ls/lib/aliases", aliases)

		# handler.
		if log_level >= 0: loader.stop()
		return r3sponse.success(f"Successfully synchronized {c} alias(es).")
	def public(self, public_ip=None, private_ip=None):
		return not (NETWORK_INFO["public_ip"] == public_ip and netw0rk.network.ping(private_ip, timeout=0.5).up == True)

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
