#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
import syst3m, encrypti0n
from fil3s import *
from r3sponse import r3sponse
import getpass

# the encryption object class.
class Encryption(syst3m.objects.Traceback):
	def __init__(self,
		# the configuration file (Dictionary).
		config=Dictionary,
		# the webserver cache (syst3m.cache.WebServer).
		webserver=syst3m.cache.WebServer, 
		# encrypted cache path.
		cache=None,
		# the passphrase (optional to prompt) (str).
		passphrase=None,
		# the interactive mode (prompt for password) (bool).
		interactive=True,
	):

		# traceback.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.encryption", raw_traceback="ssht00ls.classes.encryption.Encryption")

		# init.
		self.config = config
		self.webserver = webserver
		self.passphrase = passphrase
		self.interactive = interactive
		self.cache = cache

		# vars.
		self._activated = False

		# checks.
		if webserver == None:
			raise ValueError(self.__traceback__(function="", attribute="webserver")+": Define parameter [webserver].")
		elif not isinstance(webserver, syst3m.cache.WebServer):
			raise ValueError(self.__traceback__(function="", attribute="webserver")+": Parameter [webserver] requires to be instance syst3m.cache.WebServer.")
		elif config == None:
			raise ValueError(self.__traceback__(function="", attribute="config")+": Define parameter [config].")
		elif not isinstance(config, Dictionary):
			raise ValueError(self.__traceback__(function="", attribute="config")+": Parameter [config] requires to be instance Dictionary.")

		# initialize.
		self.encryption = encrypti0n.aes.AsymmetricAES(
			public_key=self.config["encryption"]["public_key"],
			private_key=self.config["encryption"]["private_key"],
			passphrase=self.passphrase,
			memory=True,)
		self.database = encrypti0n.aes.Database(path=self.cache, aes=self.encryption)

	# generate encryption.
	def generate(self,
		# the passphrase (optional to prompt) (str).
		passphrase=None,
		# the verify passphrase (optional).
		verify_passphrase=None,
		# interactive (optional).
		interactive=None
	):
		if passphrase == None: passphrase = self.passphrase
		if interactive == None: interactive = self.interactive
		if passphrase == None:
			if not interactive:
				return r3sponse.error(self.__traceback__(function="generate")+": Define parameter [passphrase].")
			else:
				passphrase = getpass.getpass("Enter the passphrase of the ssht00ls encryption:")
		elif len(passphrase) < 8: 
			return r3sponse.error("The passphrase must contain at least 8 characters.")
		elif passphrase.lower() == passphrase: 
			return r3sponse.error("The passphrase must contain capital characters.")
		elif (interactive and passphrase != getpass.getpass("Enter the same passphrase:")) or (verify_passphrase != None and passphrase != verify_passphrase): 
			return r3sponse.error("The passphrase must contain at least 8 characters.")
		self.encryption.rsa.passphrase = passphrase
		response = self.encryption.generate_keys()
		if not response["success"]: 
			return r3sponse.error(f"Encoutered an error while generating the master encryption key: {response['error']}")
		self.passphrase = passphrase
		self.encryption.rsa.private_key = response.private_key
		self.encryption.rsa.public_key = response.public_key
		try: self.config["encryption"]
		except KeyError: self.config["encryption"] = {}
		self.config["encryption"]["public_key"] = self.encryption.rsa.public_key
		self.config["encryption"]["private_key"] = self.encryption.rsa.private_key
		self.config.save()
		response = self.encryption.load_keys()
		if not response["success"]: 
			return r3sponse.error(f"Encoutered an error while activating the ssht00ls encryption: {response['error']}")
		response = self.webserver.set(group="passphrases", id="master", data=passphrase)
		if not response["success"]: 
			return r3sponse.error(f"Encoutered an error while caching the passphrase (#1): {response['error']}")
		self.database = encrypti0n.aes.Database(path=self.cache, aes=self.encryption)
		response = self.database.activate()
		if not response["success"]: 
			return r3sponse.error(f"Encoutered an error while activating the encrypted cache: {response['error']}")
		return r3sponse.success("Successfully generated the encryption.")

	# activate encryption.
	def activate(self,
		# the key's passphrase (optional to retrieve from webserver) (str).
		passphrase=None,
		# interactive (optional) 
		interactive=None,
	):
		if passphrase == None: passphrase = self.passphrase
		if interactive == None: interactive = self.interactive
		new = False
		if passphrase in [False, None, "", "null", "None", "none"]:
			response, passphrase = self.webserver.get(group="passphrases", id="master"), None
			if not response.success and "There is no data cached for" not in response["error"]: return response
			elif response["success"]: passphrase = response["data"]
			if passphrase in [False, None, "", "null", "None", "none"]:
				if not interactive:
					return r3sponse.error(self.__traceback__(function="activate")+": Define parameter [passphrase].")
				else:
					new = True
					passphrase = getpass.getpass("Enter the passphrase of the ssht00ls encryption:")
		self.encryption.rsa.passphrase = passphrase
		response = self.encryption.load_keys()
		if not response["success"]: 
			return r3sponse.error(f"Encoutered an error while activating the ssht00ls encryption: {response['error']}")
		self.passphrase = passphrase
		self.database.aes.rsa.passphrase = passphrase
		response = self.database.activate()
		if not response["success"]: 
			return r3sponse.error(f"Encoutered an error while activating the encrypted cache: {response['error']}")
		if new:
			response = self.webserver.set(group="passphrases", id="master", data=passphrase)
			if not response["success"]: 
				return r3sponse.error(f"Encoutered an error while caching the passphrase (#2): {response['error']}")
		return r3sponse.success("Successfully activated the encryption.")

	# properties.
	@property
	def activated(self):
		return self.encryption.activated and self.database.aes.activated
	@property
	def public_key_activated(self):
		return self.encryption.public_key_activated and self.database.aes.public_key_activated
	@property
	def private_key_activated(self):
		return self.encryption.private_key_activated and self.database.aes.private_key_activated
	@property
	def generated(self):
		return self.encryption.rsa.private_key != None and self.encryption.rsa.public_key != None
	# repr.
	def __repr__(self):
		return f"<ssht00ls.classes.encryption (activated: {self.activated}) (generated: {self.generated}) >"
	
