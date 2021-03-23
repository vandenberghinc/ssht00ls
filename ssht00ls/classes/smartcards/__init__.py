#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils

def __check_os__(supported=[]):
	if dev0s.defaults.vars.os not in supported:
		return dev0s.response.error(f"Unsupported operating system [{dev0s.defaults.vars.os}].")
	return dev0s.response.success(f"Supported operating system [{dev0s.defaults.vars.os}].")

# the manager class.
class SmartCards(Traceback):
	def __init__(self, 
	):	

		# docs.
		DOCS = {
			"module":"ssht00ls.smartcards", 
			"initialized":True,
			"description":[], 
			"chapter": "Keys", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.smartcards", raw_traceback="ssht00ls.classes.smartcards.SmartCards")

		# key path.
		if dev0s.defaults.vars.os in ["linux"]: 
			self.path = None
			for path in [
				"/usr/lib/x86_64-linux-gnu//opensc-pkcs11.so",
				"/usr/lib/x86_64-linux-gnu//opensc-pkcs11.so",
				"/usr/lib/arm-linux-gnueabihf/opensc-pkcs11.so",
				"/usr/local/lib/libykcs11",
			]:
				if Files.exists(path):
					self.path = path
					break
			if dev0s.defaults.options.log_level >= 1 and self.original_path == None: dev0s.response.log("Unable to locate opensc-pkcs11.so.", mode="warning")
					
		elif dev0s.defaults.vars.os in ["macos"]: 
			self.original_path = None
			for path in [
				"/usr/local/lib/libykcs11.dylib",
			]:
				if Files.exists(path):
					self.original_path = path
					break
			if dev0s.defaults.options.log_level >= 1 and self.original_path == None: dev0s.response.log("Unable to locate libykcs11.dylib.", mode="warning")

			#self.original_path = "/usr/local/lib/libykcs11.dylib"
			#self.path = "/usr/local/lib/libykcs11_NOTALNK.dylib"
			#self.original_path = "/usr/local/lib/opensc-pkcs11.so"
			#self.original_path = f"{SOURCE_PATH}/lib/opensc/macos/opensc-pkcs11.so"
			#self.path = "/usr/local/lib/opensc-pkcs11_NOTALINK.so"
			self.original_path = path
			self.path = "/usr/local/lib/libykcs11_NOTALNK.dylib"
			#if not Files.exists(self.original_path):
			#	dev0s.response.log("&RED&OpenSC package is not installed&END&, run: [$ brew install yubico-piv-tool opensc].")

		# attributes.
		self.__smartcards__ = {}

		#

	# functions.
	def scan(self, silent=False):

		# list.
		response = dev0s.code.execute("ykman list")
		if not response.success: return response
		output = response.output.split("\n")

		# iterate.
		count, smartcards = 0, {}
		for card in output:
			if card not in [""]:
				try: 
					serial_number = card.split("Serial: ")[1].replace(" ", "")
					text = card.split(" Serial:")[0]
					smartcards[serial_number] = SmartCard(serial_number=serial_number)
				except IndexError: 
					return dev0s.response.error("Unrecognized smart card detected. Remove the smart card and plug it back in.")

		# response.
		return dev0s.response.success(f"Successfully scanned & detected {len(smartcards)} smart card(s).", {
			"smartcards":smartcards
		})

		#
	def find_smartcard(self, serial_number=None):
		
		# scan for connected smart cards.
		response = self.scan()
		if response["error"] != None: return response
		elif str(serial_number) not in list(response["smartcards"].keys()):
			return dev0s.response.error(f"There is no smart card detected  with serial number [{serial_number}].")

		# success.
		smartcard = response["smartcards"][str(serial_number)]
		return dev0s.response.success(f"Successfully initialzed smart card [{serial_number}].", {
			"smartcard":smartcard
		})

		#
	
	# system functions.
	def __single_key_plugged_in__(self):

		# scan.
		l_response = self.scan()
		if l_response["error"] != None: return l_response

		# check one.
		if len(l_response["smartcards"]) > 1:
			return dev0s.response.error("There are multiple smart cards plugged in.")

		# check zero.
		if len(l_response["smartcards"]) == 0:
			return dev0s.response.error("There are no smart cards plugged in / detected.")

		# success.
		return dev0s.response.success("There is only one smart cards plugged in.", {
			"smartcard":l_response["smartcards"][list(l_response["smartcards"].keys())[0]],
		})

	# iterate.
	def __iter__(self):
		return iter(self.__smartcards__)
	def list(self):
		return list(self.__smartcards__.keys())
	def iterate(self):
		return self.__smartcards__.items()	

	# get & set client.
	def __getitem__(self, key):
		return self.__smartcards__[str(key)]
		#
	def __setitem__(self, key, value):
		self.__smartcards__[str(key)] = value
		#

	# support [>=, <=, <, >] operators.
	def __gt__(self, smartcards):
		if isinstance(smartcards, int):
			a=1
		elif isinstance(smartcards, self.__class__):
			smartcards = len(smartcards.__smartcards__)
		elif not isinstance(smartcards, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {smartcards.__class__}.")
		return len(self.__smartcards__) > smartcards
	def __ge__(self, smartcards):
		if isinstance(smartcards, int):
			a=1
		elif isinstance(smartcards, self.__class__):
			smartcards = len(smartcards.__smartcards__)
		elif not isinstance(smartcards, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {smartcards.__class__}.")
		return len(self.__smartcards__) >= smartcards
	def __lt__(self, smartcards):
		if isinstance(smartcards, int):
			a=1
		elif isinstance(smartcards, self.__class__):
			smartcards = len(smartcards.__smartcards__)
		elif not isinstance(smartcards, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {smartcards.__class__}.")
		return len(self.__smartcards__) < smartcards
	def __le__(self, smartcards):
		if isinstance(smartcards, int):
			a=1
		elif isinstance(smartcards, self.__class__):
			smartcards = len(smartcards.__smartcards__)
		elif not isinstance(smartcards, self.__class__):
			raise exceptions.FormatError(f"Can not compare object {self.__class__} & {smartcards.__class__}.")
		return len(self.__smartcards__) <= smartcards

	# support [==, !=] operators.
	def __eq__(self, smartcards):
		if isinstance(smartcards, self.__class__):
			smartcards = smartcards.__smartcards__
		elif not isinstance(smartcards, self.__class__):
			return False
		return Dictionary(self.__smartcards__) == Dictionary(smartcards)
	def __ne__(self, smartcards):
		if isinstance(smartcards, self.__class__):
			smartcards = smartcards.__smartcards__
		elif not isinstance(smartcards, self.__class__):
			return True
		return Dictionary(self.__smartcards__) != Dictionary(smartcards)

	# support +.
	def __concat__(self, smartcards):
		if isinstance(smartcards, self.__class__):
			smartcards = smartcards.__smartcards__
		elif not isinstance(value, self.__class__):
			raise exceptions.FormatError(f"Can not concat object {self.__class__} & {smartcards.__class__}.")
		return Dictionary(self.__smartcards__) + Dictionary(smartcards)

	# support 'in' operator.
	def __contains__(self, smartcard):
		if isinstance(smartcard, (list, Files.Array)):
			for i in smartcard:
				if str(i) in list(self.__smartcards__.keys()):
					return True
			return False
		else:
			return str(smartcard) in list(self.__smartcards__.keys())
		#
	
	# representations.
	def __repr__(self):
		return str(self)
	def __str__(self):
		return str(self.__smartcards__)
	def __int__(self):
		return int(self.__smartcards__)
	def __float__(self):
		return float(self.__smartcards__)
	def __bool__(self):
		return len(self.__smartcards__) > 0
	def __len__(self):
		return len(self.__smartcards__)
	
	#


# the smart card class.
class SmartCard(Traceback):
	# the smart card is by default a YubiKey 5 NFC
	# main docs: https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-manual#ykman_piv_change-management-key1suvy
	# piv: https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html
	# docs : https://support.yubico.com/support/solutions/articles/15000011059-yubikey-fips-series-technical-manual#2.3.4_Recommended_PIV_Settings11ale3
	# ssh : https://github.com/fredxinfan/ykman-piv-ssh
	# another ssh : https://somm15.github.io/yubikey/macos/ssh/2018/11/20/welcome-to-jekyll.html
	def __init__(self, serial_number=None):	

		# docs.
		DOCS = {
			"module":"ssht00ls.SmartCard", 
			"initialized":False,
			"description":[], 
			"chapter": "Keys", }

		# defaults.
		Traceback.__init__(self, traceback="ssht00ls.SmartCard", raw_traceback="ssht00ls.classes.smartcards.SmartCard")	

		# arguments.
		self.serial_number = serial_number

		# key path.
		self.path = smartcards.path

		# check permissions.
		#fp = FilePath(self.path)
		#fp.permission.check(permission=600)

		# variables.
		self.puk = None
		self.pin = None


		#
	
	# multiple keys plugged in compatible:
	def get_info(self):

		# get info.
		try: 
			output = subprocess.check_output(f"ykman --device {self.serial_number} piv info", shell=True).decode().replace('  ',' ').replace('  ',' ').replace('  ',' ').lower().split('\n')
		except: 
			return dev0s.response.error("Failed to retrieve yubikey info.")

		# iterate.
		info = {}
		for x in output:
			if x not in ["", " "]:
				if 'piv version: ' in x:
					info["pin_version"] = x.split("piv version: ")[1]
				elif 'pin tries remaining: ' in x:
					info["pin_attempts"] = x.split("pin tries remaining: ")[1]
		info["serial_number"] = self.serial_number

		# success.
		return dev0s.response.success(f"Successfully retrieved the information from smart card [{self.serial_number}].", {
				"info":info,
			})

		#
	def unblock_pin(self, 
		# the new pin code.
		pin=None, 
		# the smart cards puk code
		puk=None,
	):
		
		# check params.
		response = dev0s.response.parameters.check(
			default=None,
			traceback=self.__traceback__(function="unblock_pin"),
			parameters={
				"pin":pin,
				"puk":puk,
			})
		if not response["success"]: return response

		# unblock.
		response = dev0s.code.execute(f"ykman --device {self.serial_number} piv unblock-pin --puk {puk} --new-pin {pin}")
		if not response.success: return response
		output = response.output

		# handle defaults.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response

		# handle error.
		if output != "":
			return dev0s.response.error(f"Unknown error pin unblocking, output: [{output}].")

		# handle success.
		return dev0s.response.success(f"Successfully unblocked the pin code of smart card [{self.serial_number}].")

		#
	def change_pin(self, 
		# the smart cards new pin code.
		new=None, 
		# the smart cards old pin code.
		old=123456,
	):

		# check params.
		response = dev0s.response.parameters.check(
			default=None,
			traceback=self.__traceback__(function="change_pin"),
			parameters={
				"new":new,
				"old":old,
			})
		if not response["success"]: return response

		# do.
		command = f"ykman --device {self.serial_number} piv change-pin -P{old} -n{new}"
		response = dev0s.code.execute(command)
		if not response.success: return response
		output = response.output

		# handle defaults.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response

		# handle success.
		elif "New PIN set." in output: 
			return dev0s.response.success(f"Successfully changed the pin of smart card [{self.serial_number}].")

		# unknown error.
		else:
			return dev0s.response.error(f"Unknown error while changing pin, output: [{output}].")

		#
	def change_puk(self, 
		# the smart cards new puk code.
		new=None, 
		# the smart cards old puk code.
		old=12345678,
	):

		# check params.
		response = dev0s.response.parameters.check(
			default=None,
			traceback=self.__traceback__(function="change_puk"),
			parameters={
				"new":new,
				"old":old,
			})
		if not response["success"]: return response

		# do.
		command = f"ykman --device {self.serial_number} piv change-puk -p{old} -n{new}"
		response = dev0s.code.execute(command)
		if not response.success: return response
		output = response.output

		# handle defaults.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response


		# handle success.
		elif "New PUK set." in output: 
			return dev0s.response.success(f"Successfully changed the puk of smart card [{self.serial_number}].")

		# unknown error.
		else:
			return dev0s.response.error(f"Unknown error while changing puk, output: [{output}].")

		#
	def generate_key(self, 
		# the smart cards pin code.
		pin=None,
	):

		# check params.
		response = dev0s.response.parameters.check(
			default=None,
			traceback=self.__traceback__(function="generate_key"),
			parameters={
				"pin":pin,
			})
		if not response["success"]: return response

		# do.
		command = f"printf '\\n\\n' | ykman --device {self.serial_number} piv generate-key 9a public.pem --pin-policy ALWAYS  --pin {pin} --management-key 010203040506070801020304050607080102030405060708"
		response = dev0s.code.execute(command)
		if not response.success: return response
		output = response.output
		
		# handle error.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response
		elif output != "":
			return dev0s.response.error(f"Unknown error during key generation, output: [{output}].")

		# do.
		command = f'ykman --device {self.serial_number} piv generate-certificate -s "/CN=SSH-key/" 9a public.pem --pin {pin} --management-key 010203040506070801020304050607080102030405060708'
		response = dev0s.code.execute(command)
		if not response.success: return response
		output = response.output
		
		# handle error.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response
		elif output != "":
			return dev0s.response.error(f"Unknown error during certificate generation, output: [{output}].")

		# handle success.
		return dev0s.response.success(f"Successfully generated a signed certificate & key for smart card [{self.serial_number}].")

		#
	def generate_management_key(self, 
		# the smart cards pin code.
		pin=None,
	):

		# check params.
		response = dev0s.response.parameters.check(
			default=None,
			traceback=self.__traceback__(function="generate_management_key"),
			parameters={
				"pin":pin,
			})
		if not response["success"]: return response

		# do.
		command = f'ykman --device {self.serial_number} piv change-management-key --generate --protect --pin {pin} --management-key "010203040506070801020304050607080102030405060708"'
		response = dev0s.code.execute(command)
		if not response.success: return response
		output = response.output

		# handle success.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response
		elif output != "":
			return dev0s.response.error(f"Unknown error during management key generation, output: [{output}].")
		else:
			return dev0s.response.success(f"Successfully generated a management key for smart card [{self.serial_number}].")

		#
	def reset_piv(self): # for when both pin & puk codes are blocked.

		# do.
		#output = utils.__execute_script__(f"printf 'y\\n' | ykman --device {self.serial_number} piv reset", shell=True)
		response = dev0s.code.execute(f"printf 'y\\n' | ykman --device {self.serial_number} piv reset")
		if not response.success: return response
		output = response.output
		
		# handle success.
		if "Success!" in output:
			return dev0s.response.success("Successfully resetted the smart card.")

		# handle error.
		else:
			return dev0s.response.error("Failed to reset the smart card.")

	# single key plugged in compatible:
	def export_keys(self, 
		# optionally save the keys to a file.
		path=None, 
	):

		# output.
		command = f"ssh-keygen -D {self.path} -e"
		response = dev0s.code.execute(command)
		if not response.success: return response
		output = response.output.split("\n")
		
		# error.
		if len(output) == 0 or "ssh-rsa " not in output[0]:
			return dev0s.response.error(f"Failed to export smart card [{self.serial_number}].")
		else:

			# write out.
			if path != None:
				try:
					Files.save(path, utils.__array_to_string__(output, joiner="\n"))
				except:
					return dev0s.response.error(f"Failed to write out the exported key from smart card [{self.serial_number}].")

			# success.
			return dev0s.response.success(f"Successfully exported smart card [{self.serial_number}].", {"public_keys":output})

		#
	def check_smartcard(self):

		# check.
		try:
			output = subprocess.check_output("yubico-piv-tool -aversion", shell=True).decode()
		except:
			return dev0s.response.error("Failed to check for yubikey smart cards.")

		# success.
		if "Application version " in output: 
			return dev0s.response.success("Yubikey smart card detected.", {"smartcard":True})
		else: 
			return dev0s.response.success("No yubikey smart card detected.", {"smartcard":False})

		#
	def convert_to_smartcard(self):
		"""
			Option 1:
			should also bring into OTP+U2F+CCID mode.
			$ echo -e '\x06\x00\x00\x00' | u2f-host -d -a sendrecv -c c0

			Option 2:
			Plug in the key.
			$ ykpersonalize -m86
			Unplug the key & in a new terminal.
			$ doas pcscd --foreground --debug
			
		"""

		l_response = self.check_smartcard()
		if l_response["error"] != None: return l_response
		if l_response["smartcard"]:
			return dev0s.response.success("The plugged in yubikey is already a smart cards.")

		# check os.
		response = __check_os__(["linux"])
		if not response["success"]: return response



		##################








		
		#output = utils.__execute__("ykpersonalize -m86".split(" "))
		#print(f"CONVERT 2 SMARRT CARD; kpersonalize OUTPUT [{output}]")

		#output = utils.__execute__("doas pcscd --foreground --debug".split(" "))
		#print(f"CONVERT 2 SMARRT CARD; oas pcscd OUTPUT [{output}]")
		print("Key must be plugged in.")
		proc1 = subprocess.Popen(["ykpersonalize", "-m86"], shell=True)
		print("Plug out the key.")
		proc2 = subprocess.Popen(["doas", "pcscd", "--foreground", "--debug"], shell=True)
		print("Plug the key back in.")
		#proc.wait()
		#proc.terminate()
		proc1.wait()
		proc2.wait()
		"""
		# Key must be plugged in.
		# Bring the key into OTP+U2F+CCID mode.
		self.console.execute("ykpersonalize -m86")


		# Unplug the key.
		self.console.log("Unplug the smart key.", self.indent_increaser+2)
		while True:
			if self.console.input("Have you unplugged the smart key?", are_you_sure_enabled=True): break

		# Run in seperate terminal.
		proc = subprocess.Popen(["doas", "pcscd", "--foreground", "--debug"], shell=True)
		#proc.wait()
		#proc.terminate()

		# Plug the key back in.
		self.console.log("Plug the key back in.", self.indent_increaser+2)

		"""
	def install(self, 
		# specify a new pin (optional).
		pin=None, 
		# specify a new puk (optional).
		puk=None,
	):

		# initialize.
		if pin == None: 
			pin = utils.__generate_pincode__(characters=6)
		elif len(str(pin)) != 6: return dev0s.response.error("The pin code must be a six character integer code.")
		if puk == None: 
			puk = utils.__generate_pincode__(characters=8)
		elif len(puk) != 8: return dev0s.response.error("The puk code must be a eight character integer code.")
		info = {
			"pin":pin,
			"puk":puk,
			"public_key":None,
		}

		# check single key plugged in.
		l_response = smartcards.__single_key_plugged_in__()
		if l_response["error"] != None: return l_response

		# reset piv.
		l_response = self.reset_piv()
		if l_response["error"] != None: return l_response

		# convert to smart card.
		l_response = self.convert_to_smartcard()
		if l_response["error"] != None: return l_response

		# convert to smart card.
		l_response = self.change_pin(new=info["pin"], old=123456)
		if l_response["error"] != None: return l_response

		# convert to smart card.
		l_response = self.change_puk(new=info["puk"], old=12345678)
		if l_response["error"] != None: return l_response

		# convert to smart card.
		l_response = self.generate_key(pin=info["pin"])
		if l_response["error"] != None: return l_response

		# convert to smart card.
		l_response = self.generate_management_key(pin=info["pin"])
		if l_response["error"] != None: return l_response

		# success.
		return dev0s.response.success(f"Successfully installed smart card [{self.serial_number}].", {
			"pin":info["pin"],
			"puk":info["puk"],
		})

		#

	# properties.
	@property
	def activated(self):
		raise ValueError("Coming soon.")
		return False

	# system functions.
	def __handle_default_output__(self, output):

		# defaults.
		if isinstance(output, list): output = utils.__array_to_string__(output, joiner="\n")

		# handle.
		if "Incorrect PUK" in output:
			return dev0s.response.error(f"Provided an incorrect puk code.")
		elif "Incorrect PIN" in output:
			info = self.get_info()
			if info['success']: 
				return dev0s.response.error(f"Provided an incorrect pin code, {info['pin_attempts']} attempts left.")
			else: 
				return dev0s.response.error(f"Provided an incorrect pin code.")
			return response
		elif "PUK is blocked" in output:
			return False, dev0s.response.error(f"The puk code of smart card [{self.serial_number}] is blocked.")
		elif "Error: " in output:
			return dev0s.response.error(output.split("Error: ")[1].replace('.\n', '. ').replace('\n', ''))

		# success.
		return dev0s.response.success("Successfully checked the output.")

	# representations.
	def __repr__(self):
		return str(self)
	def __str__(self):
		return str(self.serial_number)
	def __int__(self):
		return int(self.serial_number)
	def __float__(self):
		return float(self.serial_number)
	#

# initialized classes.
smartcards = SmartCards()

"""

# scan for connected smart cards.
response = smartcards.scan()

# select an initialized smart card object.
smartcard = response["smartcards"]["10968447"]

# get information.
response = smartcard.get_info()

# install a new smart card.
# (warning: resets the smart card!)
response = smartcard.install()

# export the public keys.
response = smartcard.export_keys(
	# optionally save the keys to a file.
	path="/tmp/public_keys",)

# reset the smart card.
response = smartcard.reset_piv()

# change the pin code.
response = smartcard.change_pin(
	# the smart cards new puk code.
	new=123456, 
	# the smart cards old puk code.
	old=123456,)

# change the puk code.
response = smartcard.change_puk(
	# the smart cards new puk code.
	new=12345678, 
	# the smart cards old puk code.
	old=12345678,)

# unblock the pin code.
response = smartcard.unblock_pin(
	# the new pin code.
	pin=123456, 
	# the smart cards puk code
	puk=12345678,)

# generate a new key inside the smart card.
response = smartcard.generate_key(
	# the smart cards pin code.
	pin=123456, )

# generate a new management key inside the smart card.
response = smartcard.generate_management_key(
	# the smart cards pin code.
	pin=123456, )

# check if the yubikey is in the correct mode.
response = smartcard.check_smartcard()

# convert a yubikey into a piv smart card.
# (experimental)
response = smartcard.convert_to_smartcard()

"""
