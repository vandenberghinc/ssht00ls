#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import * 
import os, sys, requests, ast, json, pathlib, glob, string, getpass, django

# save config file safely.
def save_config_safely(backup=True, __loader__=None, __keyboard_interrupt__=None):
	if backup: save_config_backup_safely()		
	try:
		CONFIG.save()
	except KeyboardInterrupt as e:
		if __loader__ == None:
			__loader__ = dev0s.console.Loader("&RED&Do not interrupt!&END& Saving ssht00ls config file.")
		return save_config_safely(backup=False, __loader__=__loader__, __keyboard_interrupt__=e)
	if __loader__ != None: __loader__.stop()
	if __keyboard_interrupt__ != None:
		raise KeyboardInterrupt(__keyboard_interrupt__)

# save backup of config file safely.
def save_config_backup_safely(__loader__=None):
	path = DATABASE.join(".backups")
	if not Files.exists(path): Files.create(path, directory=True)
	path += "/config/"
	if not Files.exists(path): Files.create(path, directory=True)
	path += f"/{Date().date}"
	try:
		Files.save(path, CONFIG.dictionary, format="json")
	except KeyboardInterrupt as e:
		if __loader__ == None:
			__loader__ = dev0s.console.Loader("&RED&Do not interrupt!&END& Saving backup of ssht00ls config file.")
		return save_config_backup_safely(__loader__=__loader__)
	if __loader__ != None: __loader__.stop()
	fp = FilePath(gfp.base(path))
	if fp.size(format=int, mode="mb") >= 5:
		fp.delete(forced=True)
		fp.create(directory=True)

# check / start the ssh agent (due to circular import keep it over here for classes: [aliases]).
def ssh_agent():
	"""
	SSH_AUTH_SOCK = os.environ.get("SSH_AUTH_SOCK")
	SSH_AGENT_PID = os.environ.get("SSH_AGENT_PID")
	"""
	"""
	try:
		output = utils.__execute__([f"ssh-add", "-D"])
	except: a=1
	try:
		output = utils.__execute__([f"ssh-add", "-k"])
	except: a=1
	"""

	# version 2.
	if len(dev0s.code.processes(includes="ssh-agent").processes) >= 10:
		dev0s.code.execute(f"pkill -9 -f ssh-agent")
	try:
		output = dev0s.code.execute(f"ssh-agent")
		if not output.success: output.crash()
		output = str(output)
		try: 
			SSH_AUTH_SOCK = output.split("SSH_AUTH_SOCK=")[1].split(";")[0]
			os.environ["SSH_AUTH_SOCK"] = SSH_AUTH_SOCK
		except: return None
		try: 
			SSH_AGENT_PID = output.split("SSH_AGENT_PID=")[1].split(";")[0]
			os.environ["SSH_AGENT_PID"] = SSH_AGENT_PID
		except: return None
	except: return None
	os.environ["SSH_AUTH_SOCK"] = SSH_AUTH_SOCK
	os.environ["SSH_AGENT_PID"] = SSH_AGENT_PID

# converting variables.
def __array_to_string__(array, joiner=" "):
	string = ""
	for i in array:
		if string == "": string = str(i)
		else: string += joiner+str(i)
	return string
def __string_to_boolean__(string):
	if string in ["true", "True", True]: return True
	elif string in ["false", "False", False]: return False
	else: raise ValueError(f"Could not convert string [{string}] to a boolean.")
def __string_to_bash__(string):
	a = string.replace('(','\(').replace(')','\)').replace("'","\'").replace(" ","\ ").replace("$","\$").replace("!","\!").replace("?","\?").replace("@","\@").replace("$","\$").replace("%","\%").replace("^","\^").replace("&","\&").replace("*","\*").replace("'","\'").replace('"','\"')       
	return a

# generation.
def __generate_pincode__(characters=6, charset=string.digits):
	return ''.join(random.choice(charset) for x in range(characters))
	#

# execute a shell command.
def __execute__(
	# the command in array.
	command=[],
	# wait till the command is pinished. 
	wait=False,
	# the commands timeout, [timeout] overwrites parameter [wait].
	timeout=None, 
	# the commands output return format: string / array.
	return_format="string", 
	# the subprocess.Popen.shell argument.
	shell=False,
	# pass a input string to the process.
	input=None,
):
	def __convert__(byte_array, return_format=return_format):
		if return_format == "string":
			lines = ""
			for line in byte_array:
				lines += line.decode()
			return lines
		elif return_format == "array":
			lines = []
			for line in byte_array:
				lines.append(line.decode().replace("\n","").replace("\\n",""))
			return lines

	# create process.
	if isinstance(command, str): command = command.split(' ')
	p = subprocess.Popen(
		command, 
		shell=shell,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		stdin=subprocess.PIPE,)
	
	# send input.
	if input != None:
		if isinstance(input, list):
			for s in input:
				p.stdin.write(f'{s}\n'.encode())
		elif isinstance(input, str):
			p.stdin.write(f'{input}\n'.encode())
		else: raise ValueError("Invalid format for parameter [input] required format: [string, array].")
		p.stdin.flush()
	
	# timeout.
	if timeout != None:
		time.sleep(timeout)
		p.terminate()
	
	# await.
	elif wait:
		p.wait()

	# get output.
	output = __convert__(p.stdout.readlines(), return_format=return_format)
	if return_format == "string" and output == "":
		output = __convert__(p.stderr.readlines(), return_format=return_format)
	elif return_format == "array" and output == []:
		output = __convert__(p.stderr.readlines(), return_format=return_format)
	return output

# execute a shell script.
def __execute_script__(
	# the script in string.
	script="",
	# wait till the command is pinished. 
	wait=False,
	# the commands timeout, [timeout] overwrites parameter [wait].
	timeout=None, 
	# the commands output return format: string / array.
	return_format="string", 
	# the subprocess.Popen.shell argument.
	shell=False,
	# pass a input string to the process.
	input=None,
):
	path = f"/tmp/shell_script.{__generate_pincode__(characters=32)}.sh"
	with open(str(path), "w") as file:
		file.write(str(script))
	os.system(f"chmod +x {path}")
	output = __execute__(
		command=[f"sh", f"{path}"],
		wait=wait,
		timeout=timeout, 
		return_format=return_format, 
		shell=shell,
		input=input,)
	os.system(f"rm -fr {path}")
	return output
