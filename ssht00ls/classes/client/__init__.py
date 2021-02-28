#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes import agent, keys, aliases, ssh, smartcards, ssync, smb

# the client object class.
class Client(syst3m.objects.Traceback):
	def __init__(self,
		# the alias (required) (param #1).
		alias=None,
		# the username (optional if client already exists).
		username=None,
		# the public ip (optional if client already exists).
		public_ip=None,
		# the private ip (optional if client already exists).
		private_ip=None,
		# the public port (optional if client already exists).
		public_port=None,
		# the private port (optional if client already exists).
		private_port=None,
		# the path to the public key (optional if client already exists).
		public_key=None,
		# the path to the private key (optional if client already exists).
		private_key=None,
		# the smart card boolean (optional if client already exists).
		smartcard=False,
		# pass parameters by dict.
		parameters={},
	):

		# defaults.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.Client", raw_traceback="ssht00ls.classes.client.Client")

		# parameters by dict.
		if parameters != {}:
			alias, username, public_ip, private_ip, public_port, private_port, public_key, private_key, smartcard = Dictionary(parameters).unpack({
				"alias":None,
				"username":None,
				"public_ip":None,
				"private_ip":None,
				"public_port":None,
				"private_port":None,
				"public_key":None,
				"private_key":None,
				"smartcard":False,
			})

		# auto fill none & alias exists.
		response = aliases.aliases.info(alias)
		if response.success:
			if username == None: username = response.info["username"]
			if public_ip == None: public_ip = response.info["public_ip"]
			if private_ip == None: private_ip = response.info["private_ip"]
			if public_port == None: public_port = response.info["public_port"]
			if private_port == None: private_port = response.info["private_port"]
			if public_key == None: public_key = response.info["public_key"]
			if private_key == None: private_key = response.info["private_key"]
			if smartcard == None: smartcard = response.info["smartcard"]

		# objects.
		self.alias = aliases.Aliases(
			alias=alias,
			username=username,
			public_ip=public_ip,
			private_ip=private_ip,
			public_port=public_port,
			private_port=private_port,
			private_key=private_key,
			public_key=public_key,
			smartcard=smartcard, )
		self.agent = agent.Agent(
			private_key=private_key,
			public_key=public_key,
			smartcard=smartcard, )
		self.key = keys.Keys(
			private_key=private_key,
			public_key=public_key,
			username=username, )
		self.ssh = ssh.SSH(
			alias=alias, )
		self.ssync = ssync.SSync(
			alias=alias, )
		self.smartcard = None
		if smartcard: self.smartcard = smartcard.SmartCard()
		self.smb = smb.SMB(
			alias=alias,)

		# vars.
		try: 	self.public_key_data = Files.load(public_key)
		except: self.public_key_data = None
		try: 	self.public_key_id = self.public_key_data.split("[#id:")[1].split("]")[0]
		except: self.public_key_id = None

		#
	# functions.
	def generate(self, 
		# the new passphrase.
		passphrase=None,
		# the new smartcard pin.
		pin=None,
	):

		# generate key.
		response = self.key.generate(passphrase=passphrase)
		if not response.success: return response

		# create alias.
		response = self.create(
			passphrase=passphrase,
			pin=pin,)
		if not response.success: return response

		# handler.
		return r3sponse.success(f"Successfully generated client {self.alias_}.")

		#
	def create(self, 
		# the new passphrase.
		passphrase=None,
		# the new smartcard pin.
		pin=None,
	):

		# create alias.
		response = self.alias.create(
			passphrase=passphrase,
			pin=pin,
			checks=False,)
		if not response.success: return response

		# check & add.
		response = self.check()
		if not response.success: return response		

		# handler.
		return r3sponse.success(f"Successfully generated client {self.alias_}.")

		#
	def check(self):

		# check alias.
		response = self.alias.check(create=False, info={
			"username":self.username,
			"public_ip":self.public_ip,
			"private_ip":self.private_ip,
			"public_port":self.public_port,
			"private_port":self.private_port,
			"private_key":self.private_key,
			"public_key":self.public_key,
			"smartcard":self.smartcard,
		})
		if not response.success: return response

		# check added to agent.
		response = self.agent.check()
		if not response.success:
			if "is not added to the ssh agent" not in response.error: return response
			else:

				# get passphrase.
				passphrase, pin, no_passphrase = None, None, False
				response = self.alias.info()
				if not response.success: return response
				info = response.info
				if self.is_smartcard:
					if info["pin"] in [False, None, "", "none", "None"]:
						no_passphrase = True
					else:
						response = encryption.encryption.decrypt(info["pin"])
						if not response.success: return response
						pin = response.decrypted.decode()
				else:
					if info["passphrase"] in [False, None, "", "none", "None"]:
						no_passphrase = True
					else:
						response = encryption.encryption.decrypt(info["passphrase"])
						if not response.success: return response
						passphrase = response.decrypted.decode()

				# add agent key.
				if not no_passphrase:
					response = self.agent.add(
						passphrase=passphrase,
						pin=pin,)
					if not response.success: return response

		# sync alias.
		response = self.alias.sync()
		if not response.success: return response

		# handler.
		return r3sponse.success(f"Successfully checked client [{self.alias_}].")

		#
	# properties.
	@property
	def exists(self):
		response = self.alias.check()
		if response.success: return True
		elif "does not exist." in response.error: return False
		else: raise ValueError(f"Unexpected error: {response.error}")
	@property
	def activated(self):
		response = self.agent.check()
		if response.success: return True
		elif "is not added to the ssh agent" in response.error: return False
		else: raise ValueError(f"Unexpected error: {response.error}")
	@property
	def id(self):
		return self.alias_
	@property
	def alias_(self):
		return self.alias.alias
	@property
	def username(self):
		return self.alias.username
	@property
	def public_ip(self):
		return self.alias.public_ip
	@property
	def private_ip(self):
		return self.alias.private_ip
	@property
	def public_port(self):
		return self.alias.public_port
	@property
	def private_port(self):
		return self.alias.private_port
	@property
	def ip(self):
		if self.public:
			return self.private_ip
		else:
			return self.private_ip
	@property
	def port(self):
		if self.public:
			return self.public_port
		else:
			return self.public_port
	@property
	def public(self):
		if None in [self.private_ip, self.public_ip]:
			return None
		try: return self.__public__
		except AttributeError: 
			self.__public__ = self.alias.public(public_ip=self.public_ip, private_ip=private_ip)
			return self.__public__
	@property
	def private_key(self):
		return self.alias.private_key
	@property
	def public_key(self):
		return self.alias.public_key
	@property
	def is_smartcard(self):
		return self.smartcard != None

# the initialized clients.
class Clients(syst3m.objects.Traceback):
	def __init__(self):

		# defaults.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.clients", raw_traceback="ssht00ls.classes.client.Clients")

		# attributes.
		self.__clients__ = {}

		#
	# initialize.
	def initialize(self):
		for alias, info in aliases.aliases.iterate():
			self[alias] = Client(parameters=info)
	# iterate.
	def iterate(self, clients=[]):
		if clients == []:
			clients = list(self.__clients__.keys())
		items = []
		for i in clients:
			items.append([i, self.__clients__[i]])
		return items
	def __iter__(self):
		return iter(self.__clients__)
	# get & set.
	def __setitem__(self, key, value):
		if isinstance(key, (int, Integer)):
			key = list(self.__clients__.keys())[key]
		self.__clients__[key] = value
	def __getitem__(self, key):
		if isinstance(key, (int, Integer)):
			key = list(self.__clients__.keys())[key]
		return self.__clients__[key]
	# len.
	def __len__(self):
		return len(self.__clients__)

# initialized objects.
clients = Clients()
clients.initialize()

