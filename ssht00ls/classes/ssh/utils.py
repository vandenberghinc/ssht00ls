#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import * 
from ssht00ls.classes import utils
import os, sys, json, subprocess, pexpect

# check default errors..
def check_errors(output):
	for i in [
		"\nrsync: ",
		"\nrsync error: ",
		"\nssh: ",
		"\nssh error: ",
		"\nsshfs: ",
		"\nsshfs error: ",
		"\nscp: ",
		"\nscp error: ",
		"\nmount_smbfs: ",
		"\nmount_smbfs error: ",
		"\nclient_loop: ",
	]:
		if i in "\n"+output:
			e = str(String(("\n"+output).split(i)[1].split("\n")[0]).capitalized_word())
			while True:
				if len(e) > 0 and e[len(e)-1] in [" ", ".", "\n"]: e = e[:-1]
				elif len(e) > 0 and e[0] in [" "]: e = e[1:]
				else: break
			return dev0s.response.error(e+" ("+i.replace("\n","").replace(" ","").replace(":","").replace(" error","")+").")
	return dev0s.response.success("The output contains no (default) errors.")
	"""
	for i in [
		"rsync: ", "rsync error: ",
		"ssh: ", "ssh error: ",
		"sshfs: ", "sshfs error: ",
		"scp: ", "scp error: ",
		"mount_smbfs: ", "mount_smbfs error: ",
		"client_loop: send disconnect: Broken pipe",
	]:
		if i in output:
			e = String(i+output.split(i)[1].split("\n")[0]).capitalized_word().replace("Client_loop: send disconnect:", "Client loop: send disconnect:").replace("Ssh", "SSH")
			while True:
				if len(e) > 0 and e[len(e)-1] in [" ", "."]: e = e[:-1]
				elif len(e) > 0 and e[0] in [" "]: e = e[1:]
				else: break
			return dev0s.response.error(e+".")
	return dev0s.response.success("The output contains no (default) errors.")
	"""

# execute command.
def execute( 
	# 
	# Command:
	#   the command in str.
	command="ssh <alias> ' ls ' ",
	#
	# Options:
	#   asynchronous process.
	async_=False,
	#	await asynchronous child (sync process always awaits).
	wait=False,
	#	kill process when finished (async that is not awaited is never killed).
	kill=True,
	#   the subprocess shell parameter.
	shell=False,
	#   serialize output to dict (expect literal dictionary / json output).
	serialize=False,
	# accept new host keys.
	accept_new_host_keys=True,
	#
	# Input (sync only):
	#   send input to the command.
	#	  undefined: send no input & automatically await the process since input is always sync.
	#	  dict instance: selects "and" mode ; send expected inputs and their value & return error when one of them is missing.
	#	  list[dict] instance: send all dictionaries in the list (default dict behaviour so one of the keys in each dict is expected).
	input=None,
	#   the input timeout (float) (list with floats by index from input)
	timeout=2.0,
	#   do not throw an error when the input is missing or not expected when optional is disabled (bool).
	optional=False, 
	#	apped default accept host keys input.
	append_default_input=True,
	#
	# Logging.
	# the success message (leave None to use the default).
	message=None,
	#   loader message (str, Loader).
	loader=None,
	# stop the loader at the end of the request (bool).
	stop_loader=True,
	#   the log level (int).
	log_level=dev0s.defaults.options.log_level,
	#
	# System functions.
	#   add additional attributes to the spawn object.
	__spawn_attributes__={},
):

	# execute.
	if log_level >= 6: print(command)
	if message != None: message = message.replace("$COMMAND", command)

	# default input.
	default_input = {
		"Are you sure you want to continue connecting":Boolean(accept_new_host_keys).string(true="yes", false="no"),
	}
	if input.__class__.__name__ in ["list", "Array"]:
		if append_default_input:
			input = [default_input] + input
	elif input.__class__.__name__ in ["dict", "Dictionary"]:
		if append_default_input:
			input = [
				default_input,
				input,
			]
	elif append_default_input:
		input = default_input
		optional = True

	# execute.
	final_response = dev0s.code.execute(
		command=command,
		input=input,
		optional=optional,
		async_=async_,
		wait=wait,
		kill=kill,
		shell=shell,
		serialize=serialize,
		loader=loader,
		stop_loader=stop_loader,
		log_level=log_level,
		__spawn_attributes__=__spawn_attributes__,	)
	if not final_response.success: return final_response
	if message != None: final_response.message = message

	# check errors.
	response = check_errors(final_response.output)
	if not response.success: return response
	return final_response




















	#########################
	#
	# DEPRICATED
	# old.
	# script.

	# version 1.
	#output = dev0s.utils.__execute_script__(command)
	
	# version 2.
	#try:
	#	output = subprocess.check_output(["sh", path]).decode()
	#except subprocess.CalledProcessError as e:
	#	return dev0s.response.error(f"Failed to execute command [{command}], (output: {e.output}), (error: {e}).")

	# version 3.
	#response = dev0s.code.execute(
	#	command=command,)
	#if not response["success"]: return response
	#output = response.output
	# equal to:
	path = f"/tmp/tmp_script_{String('').generate()}"
	Files.save(path, command)
	try:
		proc = subprocess.run(
		    ["sh", path],
		    stdin=subprocess.PIPE,
			check=True,
			capture_output=True,
			text=True,
		)
	except subprocess.CalledProcessError as error:
		error_, output = error.stderr, error.output
		if isinstance(error_, bytes): error_ = error_.decode()
		if isinstance(output, bytes): output = output.decode()
		if loader != None: loader.stop(success=False)
		if log_level <= 0:
			return dev0s.response.error(f"Failed to execute command ({command}), (error: {error_}).")
		else:
			return dev0s.response.error(f"Failed to execute command ({command}), (error: {error_}), (output: {output}).")
	error_, output = proc.stderr, proc.stdout
	if isinstance(error_, bytes): error_ = error_.decode()
	if isinstance(output, bytes): output = output.decode()
	if error_ != "":
		if loader != None: loader.stop(success=False)
		if log_level <= 0:
			return dev0s.response.error(f"Failed to execute command ({command}), (error: {error_}).")
		else:
			return dev0s.response.error(f"Failed to execute command ({command}), (error: {error_}), (output: {output}).")
	if len(output) > 0 and output[len(output)-1] == "\n": output = output[:-1]
	Files.delete(path)

	# handler.
	response = check_errors(output)
	if not response.success:
		if loader != None: loader.stop(success=False)
		return response
		#print(output)
		#return dev0s.response.error(error)
	else:
		if serialize:
			try: response = dev0s.response.ResponseObject(output)
			except Exception as e: 
				if loader != None: loader.stop(success=False)
				return dev0s.response.error(f"Failed to serialize output: {output}")
			if loader != None: loader.stop()
			return response
		else:
			if loader != None: loader.stop()
			if get_output:
				return dev0s.response.success(message, {
					"output":output,
				})
			else:
				return dev0s.response.success(message)

	#

# test ssh functions.
def test(alias=None, accept_new_host_keys=True, checks=True):

	# init.
	command = f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ' echo "Hello World" ' """
	
	# version 3.
	response = dev0s.code.execute(
		command=command,
		input={
			"Are you sure you want to continue connecting":Boolean(accept_new_host_keys).string(true="yes", false="no"),
		},
		optional=True,)
	if not response.success:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {response.error}")
	output = response.output
	response = check_errors(output)
	if "Hello World" in output:
		return dev0s.response.success(f"Successfully connected with {alias}.")
	else:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {output}")

	"""
	version 2.
	# pexpect.
	spawn = dev0s.console.Spawn(command)
	response = spawn.start()
	if not response.success: return response

	# expect.
	response = spawn.expect(timeout=1.0, data=[
		"Are you sure you want to continue connecting",
	])
	if not response.success:
		if "None of the specified inputs were expected." not in response.error:
			return response
		else:
			a=1 # skip not required.

	# send.
	elif response.success:
		if response.index == 0:
			response = spawn.send(timeout=0.5, data={
				"Are you sure you want to continue connecting":"yes",
			})
			if not response.success: return response
		else: raise exceptions.InvalidUsage(f"Missed expected spawn index: [{response.index}].")

	# handler.
	response = spawn.output()
	if not response.success: return response
	output = response.output
	response = check_errors(output)
	if not response.success:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {output}")
	elif "Hello World" in output:
		return dev0s.response.success(f"Successfully connected with {alias}.")
	else:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {output}")
	"""

	"""
	# version 1
	if dev0s.defaults.options.log_level >= 6:
		print(f"<{ALIAS}.ssh.utils.test> command: {command}")
	response = dev0s.code.execute(command)
	if not response.success: return dev0s.response.error(response.error)
	output = response.output
	response = check_errors(output)
	if not response.success:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {output}")
	elif "Hello World" in output:
		return dev0s.response.success(f"Successfully connected with {alias}.")
	else:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {output}")
	"""
def test_path(alias=None, path=None, accept_new_host_keys=True, checks=True):
	if checks:
		response = test(alias=alias, accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response
	command = f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ' ls -ld {path} ' """
	if dev0s.defaults.options.log_level >= 6:
		print(f"<{ALIAS}.ssh.utils.test> command: {command}")
	response = dev0s.code.execute(
		command=command,
		input={
			"Are you sure you want to continue connecting":Boolean(accept_new_host_keys).string(true="yes", false="no"),
		},
		optional=True,)
	if not response.success:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {response.error}")
	output = response.output
	response = check_errors(output)
	if not response.success:
		return dev0s.response.error(f"Path {alias}:{path} does not exist.")
	elif "No such file or directory" not in output:
		return dev0s.response.success(f"Path {alias}:{path} exists.")
	else:
		return dev0s.response.error(f"Path {alias}:{path} does not exist.")
def test_dir(alias=None, path=None, accept_new_host_keys=True, create=False, created=False, checks=True):
	if checks:
		response = test(alias=alias, accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response
	lpath = "\'"+path+"\'"
	command = f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ''' .ssht00ls/utils/isdir {path}''' """
	if dev0s.defaults.options.log_level >= 6:
		print(f"<{ALIAS}.ssh.utils.test> command: {command}")
	response = dev0s.code.execute(
		command=command,
		input={
			"Are you sure you want to continue connecting":Boolean(accept_new_host_keys).string(true="yes", false="no"),
		},
		optional=True,)
	if not response.success:
		return dev0s.response.error(f"Failed to connect with {alias}, error: {response.error}")
	output = response.output
	if output.replace("\n","") == "directory":
		return dev0s.response.success(f"Path {alias}:{path} is a directory.", {
			"created":created,
		})
	elif output.replace("\n","") in ["directory", "does-not-exist"]:
		if output.replace("\n","") in ["does-not-exist"]:
			if create:
				output = dev0s.utils.__execute_script__(f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ''' mkdir -p {path}''' """)
				if "permission denied" in output: return dev0s.response.error(f"Unable to create remote directory [{alias}:{path}].")
				return test_dir(alias=alias, path=path, checks=False, create=False, created=True)
			else:
				return dev0s.response.error(f"Path {alias}:{path} does not exist.")
		else:
			return dev0s.response.error(f"Path {alias}:{path} is not a directory.")
	else:
		return dev0s.response.error(f"Unable to check remote directory {alias}:{path}, output: {output}.")
def test_ssht00ls(alias=None, accept_new_host_keys=True, install=True):
	for path in [f"/usr/local/lib/{ALIAS}"]:
		response = test_path(alias=alias, accept_new_host_keys=accept_new_host_keys, path=path)
		if not response.success:
			if response.error == f"Path {alias}:{path} does not exist.":
				if install:
					loader = dev0s.console.Loader(f"Installing ssht00ls library on remote {alias}.")
					response = dev0s.code.execute(f"ssh {DEFAULT_SSH_OPTIONS} {alias} ' curl https://raw.githubusercontent.com/vandenberghinc/{ALIAS}/master/{ALIAS}/requirements/installer.remote | bash ' ")
					if not response.success: return dev0s.response.error(response.error)
					output = response.output
					response = test_ssht00ls(alias=alias, accept_new_host_keys=accept_new_host_keys, install=False)
					loader.stop(success=response.success)
					#print(output)
					return response
				else:
					return dev0s.response.error(f"Remote {alias} does not have library ssht00ls installed.")
			else:
				return response
	return dev0s.response.success(f"Remote {alias} has library ssht00ls installed.")

# check / start the ssh agent.
def ssh_agent():
	return utils.ssh_agent()

# kill all ssh procs with that includes the identifier.
def kill(identifier=None, sudo=False):
	response = dev0s.response.parameters.check({
		"identifier:str":identifier,})
	if not response.success: return response
	return dev0s.code.kill(includes=identifier, sudo=sudo)
	# old.
	killed = 0
	output = dev0s.utils.__execute_script__(f"""ps -ax | grep "{identifier}" | """ + """awk '{print $1"|"$2"|"$3"|"$4}' """)
	for line in output.split("\n"):
		if line not in ["", " "]:
			pid,tty,_,process = line.split("|")
			if process not in dont_kill:
				loader = dev0s.console.Loader(f"Killing process {pid}.")
				if sudo: _sudo_ = "sudo "
				else: _sudo_ = ""
				output = dev0s.utils.__execute_script__(f"{_sudo_}kill {pid}")
				if "terminated" in output:
					loader.stop()
					killed += 1
				else:
					loader.stop(success=False)
					dev0s.response.log(f"Failed to stop process {pid}, error: {output}")
	return dev0s.response.success(f"Successfully killed {killed} process(es) that included identifier [{identifier}].")
