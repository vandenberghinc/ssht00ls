#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import *
from ssht00ls.classes import utils
from ssht00ls.classes.smartcards import smartcards

# the ssh key object class.
class Keys(syst3m.objects.Traceback):
	def __init__(self,
		# initialize as specific not global (optional).
		#	the username.
		username=None,
		# the path to the public key.
		public_key=None,
		# the path to the private key.
		private_key=None,
	):

		# defaults.
		syst3m.objects.Traceback.__init__(self, traceback="ssht00ls.keys", raw_traceback="ssht00ls.classes.keys.Keys")

		# specific variables.
		self.specific = username != None
		self.username = username
		self.private_key = private_key
		self.pubic_key = public_key

		#
	def edit_passphrase(self, path=None, old=None, new=None):

		# check specific.
		if self.specific:
			if path == None: path = self.private_key

		# checks.
		path = Formats.denitialize(path)
		old = Formats.denitialize(old)
		new = Formats.denitialize(new)
		response = r3sponse.parameters.check({
			"old":old,
			"new":new,
			"path":path,
		}, traceback=self.__traceback__(function="edit_passphrase"))
		if not response["success"]: return response
		
		# check dir.
		if os.path.isdir(path): path += '/private_key'

		# do.
		output = utils.__execute__(["ssh-keygen", "-p", "-P", old, "-N", new, "-f", path])

		# check fails.
		if "incorrect passphrase supplied" in output:
			return r3sponse.error(f"Provided an incorrect passphrase for key [{path}].")
		elif "No such file or directory" in output:
			return r3sponse.error(f"Key [{path}] does not exist.")
		
		# check success.	
		elif "Your identification has been saved with the new passphrase" in output:
			return r3sponse.success(f"Successfully edited the passphrase of key [{path}].")

		# unknown.
		else:
			l = f"Failed to edit the passphrase of key [{path}]"
			return r3sponse.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))

			
		
		#
	def edit_comment(self, path=None, passphrase=None, comment=None):

		# check specific.
		if self.specific:
			if path == None: path = self.private_key

		# checks.
		path = Formats.denitialize(path)
		passphrase = Formats.denitialize(passphrase)
		comment = Formats.denitialize(comment)
		response = r3sponse.parameters.check({
			"old":old,
			"passphrase":passphrase,
			"comment":comment,
		}, traceback=self.__traceback__(function="edit_comment"))
		if not response["success"]: return response

		# check dir.
		if os.path.isdir(path): path += '/private_key'
		
		# do.
		output = utils.__execute__(["ssh-keygen", "-c", "-P", passphrase, "-C", comment, "-f", path])

		# check fails.
		if "incorrect passphrase supplied" in output:
			return r3sponse.error(f"Provided an incorrect passphrase for key [{path}].")
		elif "No such file or directory" in output:
			return r3sponse.error(f"Key [{path}] does not exist.")
		
		# check success.	
		elif "Comment '" in output and "' applied" in output:
			return r3sponse.success(f"Successfully edited the comment of key [{path}].")

		# unknown.
		else:
			l = f"Failed to edit the comment of key [{path}]"
			return r3sponse.error((f"{l}, error: "+output.replace("\n", ". ").replace(". .", ".")+".)").replace(". .",".").replace("\r","").replace("..","."))

			
		
		#
	def generate(self, path=None, passphrase=None, comment=""):

		# check specific.
		if self.specific:
			if path == None: path = gfp.base(path=self.private_key)

		# checks.
		directory = Formats.denitialize(path)
		passphrase = Formats.denitialize(passphrase)
		comment = Formats.denitialize(comment)
		if directory[len(directory)-1] != "/": directory += "/"
		response = r3sponse.parameters.check({
			"path":directory,
		}, traceback=self.__traceback__(function="generate"))
		if not response["success"]: return response

		# check arguments.
		if passphrase in [False, None, "", "null", "None", "none"]:
			passphrase = '""'

		# create dir.
		if directory != None and Files.exists(f"{directory}/public_key"): 
			return r3sponse.error(f"Public key [{directory}/public_key] already exists.")
		elif directory != None and Files.exists(f"{directory}/private_key"): 
			return r3sponse.error(f"Private key [{directory}/private_key] already exists.")
		elif directory != None and not Files.exists(directory): 
			os.mkdir(directory)
			Files.chmod(path=directory, permission=700, sudo=True)
			Files.chown(path=directory, owner=syst3m.defaults.vars.user, group=None, sudo=True)

		# options.
		private_key = f'{directory}/private_key'
		public_key = f'{directory}/public_key'
		identity_file = f'-f "{private_key}"'
		if comment == None: comment = ""
		if "[#id:" not in comment: comment += f" [#id:{utils.__generate_shell_string__(characters=48, numerical_characters=True, special_characters=True)}]"
		comment = '-C "{}"'.format(comment)
		passphrase = f'-N "{passphrase}"'#utils.__string_to_bash__(passphrase)

		# execute.
		os.system(f'ssh-keygen -q -v -o -a 100 -t ed25519 {passphrase} {identity_file} {comment}')
		if not Files.exists(private_key): 
			return r3sponse.error(f"Failed to generate key [{directory}].")

		# permissions.
		Files.chmod(path=private_key, permission=600, sudo=True)
		Files.chown(path=private_key, owner=syst3m.defaults.vars.user, group=None, sudo=True)
		os.system(f"mv '{private_key}.pub' '{public_key}'")
		if not Files.exists(public_key): 
			return r3sponse.error(f"Failed to move private key [{private_key}].")
		Files.chmod(path=public_key, permission=640, sudo=True)
		Files.chown(path=public_key, owner=syst3m.defaults.vars.user, group=None, sudo=True)

		# response.
		return r3sponse.success(f"Successfully generated key [{directory}].")

		#
	def check(self, username=None, public_keys=[], reversed=False):

		# check specific.
		if self.specific:
			if username == None: username = self.username

		# check if already present.
		if username == None: username = syst3m.defaults.vars.user
		username = Formats.denitialize(username)
		ssh_dir = FilePath(f"{syst3m.defaults.vars.homes}/{username}/.ssh/")
		auth_keys = FilePath(f"{syst3m.defaults.vars.homes}/{username}/.ssh/authorized_keys")
		output = self.__load_keys__(username)
		for key in public_keys:
			key = key.replace("\n", "")
			if key not in [""]:
				if not reversed and key not in output:
					ssh_dir.permission.set(permission=700, sudo=True, silent=True) # silent for when non existant.
					auth_keys.permission.set(permission=600, sudo=True, silent=True) # silent for when non existant.
					auth_keys.ownership.set(owner=username, sudo=True)
					ssh_dir.ownership.set(owner=username, sudo=True)
					return r3sponse.error(f'Public key [{key}] is not activated.')
				if reversed and key in output:
					ssh_dir.permission.set(permission=700, sudo=True, silent=True) # silent for when non existant.
					auth_keys.permission.set(permission=600, sudo=True, silent=True) # silent for when non existant.
					auth_keys.ownership.set(owner=username, sudo=True)
					ssh_dir.ownership.set(owner=username, sudo=True)
					return r3sponse.error(f'Public key [{key}] is activated.')

		# set correct permission.
		ssh_dir.permission.set(permission=700, sudo=True, silent=True) # silent for when non existant.
		auth_keys.permission.set(permission=600, sudo=True, silent=True) # silent for when non existant.
		auth_keys.ownership.set(owner=username, sudo=True)
		ssh_dir.ownership.set(owner=username, sudo=True)

		# success.
		if not reversed:
			return r3sponse.success(f'Successfully confirmed that the specfied {len(public_keys)} public key(s) are activated.')
		else:
			return r3sponse.success(f'Successfully confirmed that the specfied {len(public_keys)} public key(s) are not activated.')
	def enable(self, username=None, public_keys=[]):

		# check specific.
		if self.specific:
			if username == None: username = self.username
			if public_keys == []:
				public_keys = Array(Files.load(self.public_key).split("\n")).clean(remove_first=[" "], remove_last=[" "])

		# check if already present.
		if username == None: username = syst3m.defaults.vars.user
		output = self.__load_keys__(username)
		new_keys = []
		for key in public_keys:
			key = key.replace("\n", "")
			if key not in [""]:
				if key not in output:
					output.append(key)
		self.__save_keys__(username, output)

		# check if added.
		response = self.check(username, public_keys)
		if response["error"] != None: return response
	
		# success.
		return r3sponse.success(f'Successfully enabled {len(public_keys)} public key(s).')

		#
	def disable(self, username=None, public_keys=[]):

		# check specific.
		if self.specific:
			if username == None: username = self.username
			if public_keys == []:
				public_keys = Array(Files.load(self.public_key).split("\n")).clean(remove_first=[" "], remove_last=[" "])

		# check if already present.
		if username == None: username = syst3m.defaults.vars.user
		output = self.__load_keys__(username)
		new_keys = []
		for key in output:
			key = key.replace("\n", "")
			if key not in [""]:
				if key not in public_keys: new_keys.append(key)
		self.__save_keys__(username, new_keys)

		# check if added.
		response = self.check(username, public_keys, reversed=True)
		if response["error"] != None: return response
	
		# success.
		return r3sponse.success(f'Successfully disabled {len(public_keys)} public key(s).')

		#
	def __load_keys__(self, username):

		# make readable.
		if username == None: username = syst3m.defaults.vars.user
		sudo = syst3m.defaults.vars.user != username or True
		ssh_dir = FilePath(f"{syst3m.defaults.vars.homes}/{username}/.ssh/")
		auth_keys = FilePath(f"{syst3m.defaults.vars.homes}/{username}/.ssh/authorized_keys")

		# checks.
		if not ssh_dir.exists(sudo=sudo):
			ssh_dir.create(
				directory=True,
				permission=770,
				owner=username,
				group=None,
				sudo=sudo,)
		if not auth_keys.exists(sudo=sudo):
			auth_keys.create(
				directory=False,
				data="",
				permission=770,
				owner=username,
				group=None,
				sudo=sudo,)

		ssh_dir.permission.set(permission=770, sudo=sudo, silent=True) # silent for when non existant.
		auth_keys.permission.set(permission=770, sudo=sudo, silent=True) # silent for when non existant.
		auth_keys.ownership.set(owner=syst3m.defaults.vars.user, sudo=sudo)
		ssh_dir.ownership.set(owner=syst3m.defaults.vars.user, sudo=sudo)

		if sudo: command = ["sudo"]
		else: command = []
		output = utils.__execute__(command + ["cat", f"{syst3m.defaults.vars.homes}/{username}/.ssh/authorized_keys"], return_format="array")
		return output

		#
	def __save_keys__(self, username, public_keys):

		# make readable.
		if username == None: username = syst3m.defaults.vars.user
		sudo = syst3m.defaults.vars.user != username or True
		ssh_dir = FilePath(f"{syst3m.defaults.vars.homes}/{username}/.ssh/")
		auth_keys = FilePath(f"{syst3m.defaults.vars.homes}/{username}/.ssh/authorized_keys")

		# checks.
		if not ssh_dir.exists(sudo=sudo):
			ssh_dir.create(
				directory=True,
				permission=770,
				owner=username,
				group=None,
				sudo=sudo,)
		if not auth_keys.exists(sudo=sudo):
			auth_keys.create(
				directory=False,
				data="",
				permission=770,
				owner=username,
				group=None,
				sudo=sudo,)

		f = File(path="/tmp/file")
		new = []
		for public_key in public_keys:
			new.append(public_key.replace("\n",''))
		f.save(Array(path=False, array=new).string(joiner="\n"))
		os.system(f"sudo mv {f.file_path.path} {auth_keys.path}")

		ssh_dir.permission.set(permission=700, sudo=sudo, silent=True) # silent for when non existant.
		auth_keys.permission.set(permission=600, sudo=sudo, silent=True) # silent for when non existant.
		auth_keys.ownership.set(owner=syst3m.defaults.vars.user, sudo=sudo)
		ssh_dir.ownership.set(owner=syst3m.defaults.vars.user, sudo=sudo)

		#

# Initialized classes.
keys = Keys()

"""

# --------------------
# SSH Key.

# generate a key.
response = keys.generate(path="/path/to/mykey/", passphrase="passphrase123!", comment="my key")

# edit the passphrase of a key.
response = keys.edit_passphrase(path="/path/to/mykey/private_key", new="Passphrase123!", old="passphrase123!")

"""






