#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
from ssht00ls.classes.config import * 
import os, sys, json, subprocess

# execute.
def check_errors(output):
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
			return r3sponse.error(e+".")
	return r3sponse.success("The output contains no (default) errors.")
def execute( 
	# the command in str.
	command="ls",
	# the success message.
	message="Successfully executed the specified command.",
	# the error message.
	error="Failed to execute the specified command.",
	# loader message.
	loader=None,
	# serialize to json (overwrites message & error).
	serialize=False,
	# get the output.
	get_output=False,
	# the log level.
	log_level=0,
):

	# execute.
	if log_level >= 6: print(command)
	if loader != None:
		loader = syst3m.console.Loader(loader, interactive=INTERACTIVE)
	
	# script.

	# version 1.
	#output = syst3m.utils.__execute_script__(command)
	
	# version 2.
	#try:
	#	output = subprocess.check_output(["sh", path]).decode()
	#except subprocess.CalledProcessError as e:
	#	return r3sponse.error(f"Failed to execute command [{command}], (output: {e.output}), (error: {e}).")

	# version 3.
	#response = syst3m.console.execute(
	#	command=command,)
	#if not response["success"]: return response
	#output = response.output
	# equal to:
	path = f"/tmp/tmp_script_{String('').generate()}"
	Files.save(path, command)
	try:
		proc = subprocess.run(
		    ["sh", path],
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
			return r3sponse.error(f"Failed to execute command ({command}), (error: {error_}).")
		else:
			return r3sponse.error(f"Failed to execute command ({command}), (error: {error_}), (output: {output}).")
	error_, output = proc.stderr, proc.stdout
	if isinstance(error_, bytes): error_ = error_.decode()
	if isinstance(output, bytes): output = output.decode()
	if error_ != "":
		if loader != None: loader.stop(success=False)
		if log_level <= 0:
			return r3sponse.error(f"Failed to execute command ({command}), (error: {error_}).")
		else:
			return r3sponse.error(f"Failed to execute command ({command}), (error: {error_}), (output: {output}).")
	if len(output) > 0 and output[len(output)-1] == "\n": output = output[:-1]
	Files.delete(path)

	# handler.
	response = check_errors(output)
	if not response.success:
		if loader != None: loader.stop(success=False)
		return response
		#print(output)
		#return r3sponse.error(error)
	else:
		if serialize:
			try: response = r3sponse.ResponseObject(json=output)
			except Exception as e: 
				if loader != None: loader.stop(success=False)
				return r3sponse.error(f"Failed to serialize output: {output}")
			if loader != None: loader.stop()
			return response
		else:
			if loader != None: loader.stop()
			if get_output:
				return r3sponse.success(message, {
					"output":output,
				})
			else:
				return r3sponse.success(message)

	#

# test ssh functions.
def test(alias=None, accept_new_host_keys=True, checks=True):
	accept_new_host_keys = Boolean(accept_new_host_keys).convert(true="printf 'yes' | ", false="")
	output = syst3m.utils.__execute_script__(f"""{accept_new_host_keys}ssh {DEFAULT_SSH_OPTIONS} {alias} ' echo "Hello World" ' """)
	response = check_errors(output)
	if not response.success:
		return r3sponse.error(f"Failed to connect with {alias}, error: {output}")
	elif "Hello World" in output:
		return r3sponse.success(f"Successfully connected with {alias}.")
	else:
		return r3sponse.error(f"Failed to connect with {alias}, error: {output}")
def test_path(alias=None, path=None, accept_new_host_keys=True, checks=True):
	if checks:
		response = test(alias=alias, accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response
	output = syst3m.utils.__execute_script__(f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ' ls -ld {path} ' """)
	response = check_errors(output)
	if not response.success:
		return r3sponse.error(f"Path {alias}:{path} does not exist.")
	elif "No such file or directory" not in output:
		return r3sponse.success(f"Path {alias}:{path} exists.")
	else:
		return r3sponse.error(f"Path {alias}:{path} does not exist.")
def test_dir(alias=None, path=None, accept_new_host_keys=True, create=False, created=False, checks=True):
	if checks:
		response = test(alias=alias, accept_new_host_keys=accept_new_host_keys)
		if not response.success: return response
	lpath = "\'"+path+"\'"
	output = syst3m.utils.__execute_script__(f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ''' python3 /usr/local/lib/ssht00ls/classes/utils/isdir.py {path}''' """)
	if output.replace("\n","") == "directory":
		return r3sponse.success(f"Path {alias}:{path} is a directory.", {
			"created":created,
		})
	elif output.replace("\n","") in ["directory", "does-not-exist"]:
		if output.replace("\n","") in ["does-not-exist"]:
			if create:
				output = syst3m.utils.__execute_script__(f"""ssh {DEFAULT_SSH_OPTIONS} {alias} ''' mkdir -p {path}''' """)
				if "permission denied" in output: return r3sponse.error(f"Unable to create remote directory [{alias}:{path}].")
				return test_dir(alias=alias, path=path, checks=False, create=False, created=True)
			else:
				return r3sponse.error(f"Path {alias}:{path} does not exist.")
		else:
			return r3sponse.error(f"Path {alias}:{path} is not a directory.")
	else:
		return r3sponse.error(f"Unable to check remote directory {alias}:{path}, output: {output}.")
def test_ssht00ls(alias=None, accept_new_host_keys=True, install=True):
	for path in [f"/usr/local/lib/{ALIAS}"]:
		response = test_path(alias=alias, accept_new_host_keys=accept_new_host_keys, path=path)
		if not response.success:
			if response.error == f"Path {alias}:{path} does not exist.":
				if install:
					loader = syst3m.console.Loader(f"Installing ssht00ls library on remote {alias}.")
					output = syst3m.utils.__execute_script__(f"ssh {DEFAULT_SSH_OPTIONS} {alias} ' curl https://raw.githubusercontent.com/vandenberghinc/{ALIAS}/master/{ALIAS}/requirements/installer.remote | bash ' ")
					response = test_ssht00ls(alias=alias, accept_new_host_keys=accept_new_host_keys, install=False)
					loader.stop(success=response.success)
					#print(output)
					return response
				else:
					return r3sponse.error(f"Remote {alias} does not have library ssht00ls installed.")
			else:
				return response
	return r3sponse.success(f"Remote {alias} has library ssht00ls installed.")

# check / start the ssh agent.
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
	try:
		output = utils.__execute__(f"ssh-agent")
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

# kill all ssh procs with that includes the identifier.
def kill(identifier=None, sudo=False, dont_kill=["grep", "ssht00ls"]):
	response = r3sponse.check_parameters({
		"identifier:str":identifier,})
	if not response.success: return response
	killed = 0
	output = syst3m.utils.__execute_script__(f"""ps -ax | grep "{identifier}" | """ + """awk '{print $1"|"$2"|"$3"|"$4}' """)
	for line in output.split("\n"):
		if line not in ["", " "]:
			pid,tty,_,process = line.split("|")
			if process not in dont_kill:
				loader = syst3m.console.Loader(f"Killing process {pid}.")
				if sudo: _sudo_ = "sudo "
				else: _sudo_ = ""
				output = syst3m.utils.__execute_script__(f"{_sudo_}kill {pid}")
				if "terminated" in output:
					loader.stop()
					killed += 1
				else:
					loader.stop(success=False)
					r3sponse.log(f"Failed to stop process {pid}, error: {output}")
	return r3sponse.success(f"Successfully killed {killed} process(es) that included identifier [{identifier}].")
