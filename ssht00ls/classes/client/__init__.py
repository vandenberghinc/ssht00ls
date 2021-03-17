#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes import agent, keys, aliases, ssh, smartcards, ssync, smb

# the client object class.
class Client(Traceback):
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
		# the smart card serial numbers (list) (optional if client already exists).
		serial_numbers=[],
		# pass parameters by dict.
		parameters={},
	):


		# docs.
		DOCS = {
			"module":"ssht00ls.Client", 
			"initialized":False,
			"description":[], 
			"chapter": "Clients", }
			

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.Client", raw_traceback="ssht00ls.classes.client.Client")

		# parameters by dict.
		if parameters != {}:
			alias, username, public_ip, private_ip, public_port, private_port, public_key, private_key, smartcard, serial_numbers = Dictionary(parameters).unpack({
				"alias":None,
				"username":None,
				"public_ip":None,
				"private_ip":None,
				"public_port":None,
				"private_port":None,
				"public_key":None,
				"private_key":None,
				"smartcard":False,
				"serial_numbers":[],
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
			if serial_numbers != []: serial_numbers = response.info["serial_numbers"]

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
			smartcard=smartcard, 
			serial_numbers=serial_numbers, )
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
		self.smartcards = smartcards.SmartCards()
		for serial_number in serial_numbers:
			self.smartcards[serial_number] = smartcards.SmartCard(serial_number=serial_number)
		self.smb = smb.SMB(
			alias=alias,)

		# shortcuts.
		self.pull = self.ssync.pull
		self.push = self.ssync.push

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
		return dev0s.response.success(f"Successfully generated client {self.alias_}.")

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
		return dev0s.response.success(f"Successfully generated client {self.alias_}.")

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
			"smartcard:bool,Boolean":self.smartcard,
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
				if self.smartcard:
					if info["pin"] in [False, None, "", "none", "None"]:
						no_passphrase = True
					else:
						response = ssht00ls_agent.encryption.decrypt(info["pin"])
						if not response.success: return response
						pin = response.decrypted.decode()
				else:
					if info["passphrase"] in [False, None, "", "none", "None"]:
						no_passphrase = True
					else:
						response = ssht00ls_agent.encryption.decrypt(info["passphrase"])
						if not response.success: return response
						passphrase = response.decrypted.decode()

				# add agent key.
				if not no_passphrase:
					response = self.agent.add(
						passphrase=passphrase,
						pin=pin,)
					if not response.success: return response
				else:
					response = self.agent.add()
					if not response.success: return response

		# sync alias.
		response = self.alias.sync()
		if not response.success: return response

		# handler.
		return dev0s.response.success(f"Successfully checked client [{self.alias_}].")

		#
	def connect(self):
		return self.ssh.utils.test(alias=self.alias_)
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
	def smartcard(self):
		return self.alias.smartcard
	@property
	def serial_numbers(self):
		return self.alias.serial_numbers

# the initialized clients.
class Clients(Traceback):
	def __init__(self,
		# select a preset of clients (append "*" to preset to use all).
		preset=["*"],
	):

		# docs.
		DOCS = {
			"module":"ssht00ls.clients", 
			"initialized":True,
			"description":[], 
			"chapter": "Clients", }
			
		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.clients", raw_traceback="ssht00ls.classes.client.Clients")

		# attributes.
		self.preset = preset
		self.__clients__ = {}

		#
	
	# initialize.
	def initialize(self, preset=None):
		if preset == None: preset = self.preset
		if preset in ["*","all"] or "*" in preset or  "all" in preset: 
			items = aliases.aliases.iterate()
		else:
			items = []
			for alias in preset:
				response = aliases.info(alias=alias)
				if not response.success: return response
				items.append([alias, response.info])
		self.__clients__ = {}
		for alias, info in items:
			self.__clients__[alias] = Client(parameters=info)
		return dev0s.response.success(f"Successfully initialized {len(self.__clients__)} client(s).")

		#

	# iterate.
	def __iter__(self):
		return iter(self.__clients__)
	def list(self):
		return list(self.__clients__.keys())
	def iterate(self, clients=[]):
		if clients == []:
			clients = list(self.__clients__.keys())
		items = []
		for i in clients:
			items.append([i, self.__clients__[i]])
		return items
		
		#

	# get & set client.
	def __setitem__(self, key, value):
		if isinstance(key, (int, Integer)):
			key = list(self.__clients__.keys())[key]
		self.__clients__[key] = value
	def __getitem__(self, key):
		if isinstance(key, (int, Integer)):
			key = list(self.__clients__.keys())[key]
		return self.__clients__[key]
		
		#

	# support [>=, <=, <, >] operators.
	def __gt__(self, clients):
		if isinstance(clients, int):
			a=1
		elif isinstance(clients, self.__class__):
			clients = len(clients.__clients__)
		elif not isinstance(clients, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {clients.__class__}.")
		return len(self.__clients__) > clients
	def __ge__(self, clients):
		if isinstance(clients, int):
			a=1
		elif isinstance(clients, self.__class__):
			clients = len(clients.__clients__)
		elif not isinstance(clients, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {clients.__class__}.")
		return len(self.__clients__) >= clients
	def __lt__(self, clients):
		if isinstance(clients, int):
			a=1
		elif isinstance(clients, self.__class__):
			clients = len(clients.__clients__)
		elif not isinstance(clients, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {clients.__class__}.")
		return len(self.__clients__) < clients
	def __le__(self, clients):
		if isinstance(clients, int):
			a=1
		elif isinstance(clients, self.__class__):
			clients = len(clients.__clients__)
		elif not isinstance(clients, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {clients.__class__}.")
		return len(self.__clients__) <= clients

		#

	# support [==, !=] operators.
	def __eq__(self, clients):
		if isinstance(clients, self.__class__):
			clients = clients.__clients__
		elif not isinstance(clients, self.__class__):
			return False
		return Dictionary(self.__clients__) == Dictionary(clients)
	def __ne__(self, clients):
		if isinstance(clients, self.__class__):
			clients = clients.__clients__
		elif not isinstance(clients, self.__class__):
			return True
		return Dictionary(self.__clients__) != Dictionary(clients)

		#

	# support +.
	def __concat__(self, clients):
		if isinstance(clients, self.__class__):
			clients = clients.__clients__
		elif not isinstance(value, self.__class__):
			raise exceptions.FormatError(f"Can not concat object {self.__class__} & {clients.__class__}.")
		return Dictionary(self.__clients__) + Dictionary(clients)

		#

	# support 'in' operator.
	def __contains__(self, alias):
		# always convert alias fo str client for aliases etc.
		if isinstance(alias, (list, Files.Array)):
			for i in alias:
				if str(i) in list(self.__clients__.keys()):
					return True
			return False
		else:
			return str(alias) in list(self.__clients__.keys())
		
		#
		
	# representations.
	def __repr__(self):
		return str(self)
	def __str__(self):
		return str(self.__clients__)
	def __int__(self):
		return int(self.__clients__)
	def __float__(self):
		return float(self.__clients__)
	def __bool__(self):
		return len(self.__clients__) > 0
	def __len__(self):
		return len(self.__clients__)

		#
	#

# initialized objects.
clients = Clients()
clients.initialize()

