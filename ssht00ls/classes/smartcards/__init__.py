#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils

def __check_os__(supported=[]):
	if syst3m.defaults.vars.os not in supported:
		return r3sponse.error(f"Unsupported operating system [{syst3m.defaults.vars.os}].")
	return r3sponse.success(f"Supported operating system [{syst3m.defaults.vars.os}].")

# the manager class.
class SmartCards(syst3m.objects.Traceback):
	def __init__(self, 
	):	
		
		# defaults.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.smartcards", raw_traceback="ssht00ls.classes.smartcards.SmartCards")

		# key path.
		if syst3m.defaults.vars.os in ["linux"]: 
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
			if self.path == None: raise ValueError("Unable to locate opensc-pkcs11.so path.")
					
		elif syst3m.defaults.vars.os in ["macos"]: 
			#self.original_path = "/usr/local/lib/libykcs11.dylib"
			#self.path = "/usr/local/lib/libykcs11_NOTALNK.dylib"
			#self.original_path = "/usr/local/lib/opensc-pkcs11.so"
			self.original_path = f"{SOURCE_PATH}/lib/opensc/macos/opensc-pkcs11.so"
			self.path = "/usr/local/lib/opensc-pkcs11_NOTALINK.so"
			if not Files.exists(self.original_path):
				raise OSError("opensc package is not installed, run: [$ brew install yubico-piv-tool opensc].")

		# attributes.
		self.__smartcards__ = {}

		#

	# functions.
	def scan(self, silent=False):

		# list.
		output = utils.__execute__(["ykman", "list"], shell=False, return_format="array")

		# iterate.
		count, smartcards = 0, {}
		for card in output:
			if card not in [""]:
				try: 
					serial_number = card.split("Serial: ")[1].replace(" ", "")
					text = card.split(" Serial:")[0]
					smartcards[serial_number] = SmartCard(serial_number=serial_number)
				except IndexError: 
					return r3sponse.error("Unrecognized smart card detected. Remove the smart card and plug it back in.")

		# response.
		return r3sponse.success(f"Successfully scanned & detected {len(smartcards)} smart card(s).", {
			"smartcards":smartcards
		})

		#
	def find_smartcard(self, serial_number=None):
		
		# scan for connected smart cards.
		response = self.scan()
		if response["error"] != None: return response
		elif str(serial_number) not in list(response["smartcards"].keys()):
			return r3sponse.error(f"There is no smart card detected  with serial number [{serial_number}].")

		# success.
		smartcard = response["smartcards"][str(serial_number)]
		return r3sponse.success(f"Successfully initialzed smart card [{serial_number}].", {
			"smartcard":smartcard
		})

		#

	# get & set client.
	def __getitem__(self, key):
		return self.__smartcards__[str(key)]
		#
	def __setitem__(self, key, value):
		self.__smartcards__[str(key)] = value
		#

	# iterate.
	def __iter__(self):
		return iter(self.__smartcards__)
	def list(self):
		return list(self.__smartcards__.keys())
	def iterate(self):
		return self.__smartcards__.items()

	# count.
	def __len__(self):
		return len(self.__smartcards__)
	
	# system functions.
	def __single_key_plugged_in__(self):

		# scan.
		l_response = self.scan()
		if l_response["error"] != None: return l_response

		# check one.
		if len(l_response["smartcards"]) > 1:
			return r3sponse.error("There are multiple smart cards plugged in.")

		# check zero.
		if len(l_response["smartcards"]) == 0:
			return r3sponse.error("There are no smart cards plugged in / detected.")

		# success.
		return r3sponse.success("There is only one smart cards plugged in.", {
			"smartcard":l_response["smartcards"][list(l_response["smartcards"].keys())[0]],
		})

	#


# the smart card class.
class SmartCard(syst3m.objects.Traceback):
	# the smart card is by default a YubiKey 5 NFC
	# main docs: https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-manual#ykman_piv_change-management-key1suvy
	# piv: https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html
	# docs : https://support.yubico.com/support/solutions/articles/15000011059-yubikey-fips-series-technical-manual#2.3.4_Recommended_PIV_Settings11ale3
	# ssh : https://github.com/fredxinfan/ykman-piv-ssh
	# another ssh : https://somm15.github.io/yubikey/macos/ssh/2018/11/20/welcome-to-jekyll.html
	def __init__(self, serial_number=None):	

		# defaults.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.SmartCard", raw_traceback="ssht00ls.classes.smartcards.SmartCard")	

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
			return r3sponse.error("Failed to retrieve yubikey info.")

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
		return r3sponse.success(f"Successfully retrieved the information from smart card [{self.serial_number}].", {
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
		response = r3sponse.check_parameters(
			empty_value=None,
			traceback=self.__traceback__(function="unblock_pin"),
			parameters={
				"pin":pin,
				"puk":puk,
			})
		if not response["success"]: return response

		# unblock.
		output = utils.__execute_script__(f"ykman --device {self.serial_number} piv unblock-pin --puk {puk} --new-pin {pin}", shell=True)

		# handle defaults.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response

		# handle error.
		if output != "":
			return r3sponse.error(f"Unknown error pin unblocking, output: [{output}].")

		# handle success.
		return r3sponse.success(f"Successfully unblocked the pin code of smart card [{self.serial_number}].")

		#
	def change_pin(self, 
		# the smart cards new pin code.
		new=None, 
		# the smart cards old pin code.
		old=123456,
	):

		# check params.
		response = r3sponse.check_parameters(
			empty_value=None,
			traceback=self.__traceback__(function="change_pin"),
			parameters={
				"new":new,
				"old":old,
			})
		if not response["success"]: return response

		# do.
		command = f"ykman --device {self.serial_number} piv change-pin -P{old} -n{new}"
		output = utils.__execute_script__(command, shell=True)

		# handle defaults.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response

		# handle success.
		elif "New PIN set." in output: 
			return r3sponse.success(f"Successfully changed the pin of smart card [{self.serial_number}].")

		# unknown error.
		else:
			return r3sponse.error(f"Unknown error while changing pin, output: [{output}].")

		#
	def change_puk(self, 
		# the smart cards new puk code.
		new=None, 
		# the smart cards old puk code.
		old=12345678,
	):

		# check params.
		response = r3sponse.check_parameters(
			empty_value=None,
			traceback=self.__traceback__(function="change_puk"),
			parameters={
				"new":new,
				"old":old,
			})
		if not response["success"]: return response

		# do.
		command = f"ykman --device {self.serial_number} piv change-puk -p{old} -n{new}"
		output = utils.__execute_script__(command, shell=True)

		# handle defaults.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response


		# handle success.
		elif "New PUK set." in output: 
			return r3sponse.success(f"Successfully changed the puk of smart card [{self.serial_number}].")

		# unknown error.
		else:
			return r3sponse.error(f"Unknown error while changing puk, output: [{output}].")

		#
	def generate_key(self, 
		# the smart cards pin code.
		pin=None,
	):

		# check params.
		response = r3sponse.check_parameters(
			empty_value=None,
			traceback=self.__traceback__(function="generate_key"),
			parameters={
				"pin":pin,
			})
		if not response["success"]: return response

		# do.
		command = f"printf '\\n\\n' | ykman --device {self.serial_number} piv generate-key 9a public.pem --pin-policy ALWAYS  --pin {pin} --management-key 010203040506070801020304050607080102030405060708"
		output = utils.__execute_script__(command, shell=True)
		
		# handle error.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response
		elif output != "":
			return r3sponse.error(f"Unknown error during key generation, output: [{output}].")

		# do.
		command = f'ykman --device {self.serial_number} piv generate-certificate -s "/CN=SSH-key/" 9a public.pem --pin {pin} --management-key 010203040506070801020304050607080102030405060708'
		output = utils.__execute_script__(command, shell=True)
		
		# handle error.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response
		elif output != "":
			return r3sponse.error(f"Unknown error during certificate generation, output: [{output}].")

		# handle success.
		return r3sponse.success(f"Successfully generated a signed certificate & key for smart card [{self.serial_number}].")

		#
	def generate_management_key(self, 
		# the smart cards pin code.
		pin=None,
	):

		# check params.
		response = r3sponse.check_parameters(
			empty_value=None,
			traceback=self.__traceback__(function="generate_management_key"),
			parameters={
				"pin":pin,
			})
		if not response["success"]: return response

		# do.
		command = f'ykman --device {self.serial_number} piv change-management-key --generate --protect --pin {pin} --management-key "010203040506070801020304050607080102030405060708"'
		output = utils.__execute_script__(command, shell=True)

		# handle success.
		response = self.__handle_default_output__(output)
		if not response["success"]: return response
		elif output != "":
			return r3sponse.error(f"Unknown error during management key generation, output: [{output}].")
		else:
			return r3sponse.success(f"Successfully generated a management key for smart card [{self.serial_number}].")

		#
	def reset_piv(self): # for when both pin & puk codes are blocked.

		# do.
		#output = utils.__execute_script__(f"printf 'y\\n' | ykman --device {self.serial_number} piv reset", shell=True)
		output = utils.__execute_script__(f"printf 'y\\n' | ykman --device {self.serial_number} piv reset", shell=True)
		
		# handle success.
		if "Success!" in output:
			return r3sponse.success("Successfully resetted the smart card.")

		# handle error.
		else:
			return r3sponse.error("Failed to reset the smart card.")

	# single key plugged in compatible:
	def export_keys(self, 
		# optionally save the keys to a file.
		path=None, 
	):

		# output.
		command = f"ssh-keygen -D {self.path} -e"
		output = utils.__execute_script__(command, shell=True, return_format="array")
		
		# error.
		if len(output) == 0 or "ssh-rsa " not in output[0]:
			return r3sponse.error(f"Failed to export smart card [{self.serial_number}].")
		else:

			# write out.
			if path != None:
				try:
					Files.save(path, utils.__array_to_string__(output, joiner="\n"))
				except:
					return r3sponse.error(f"Failed to write out the exported key from smart card [{self.serial_number}].")

			# success.
			return r3sponse.success(f"Successfully exported smart card [{self.serial_number}].", {"public_keys":output})

		#
	def check_smartcard(self):

		# check.
		try:
			output = subprocess.check_output("yubico-piv-tool -aversion", shell=True).decode()
		except:
			return r3sponse.error("Failed to check for yubikey smart cards.")

		# success.
		if "Application version " in output: 
			return r3sponse.success("Yubikey smart card detected.", {"smartcard":True})
		else: 
			return r3sponse.success("No yubikey smart card detected.", {"smartcard":False})

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
			return r3sponse.success("The plugged in yubikey is already a smart cards.")

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
		elif len(pin) != 6: return r3sponse.error("The pin code must be a six character integer code.")
		if puk == None: 
			puk = utils.__generate_pincode__(characters=8)
		elif len(puk) != 8: return r3sponse.error("The puk code must be a eight character integer code.")
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
		return r3sponse.success(f"Successfully installed smart card [{self.serial_number}].", {
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
			return r3sponse.error(f"Provided an incorrect puk code.")
		elif "Incorrect PIN" in output:
			info = self.get_info()
			if info['success']: 
				return r3sponse.error(f"Provided an incorrect pin code, {info['pin_attempts']} attempts left.")
			else: 
				return r3sponse.error(f"Provided an incorrect pin code.")
			return response
		elif "PUK is blocked" in output:
			return False, r3sponse.error(f"The puk code of smart card [{self.serial_number}] is blocked.")
		elif "Error: " in output:
			return r3sponse.error(output.split("Error: ")[1].replace('.\n', '. ').replace('\n', ''))

		# success.
		return r3sponse.success("Successfully checked the output.")

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
