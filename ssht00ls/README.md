# ssht00ls
Author(s):  Daan van den Bergh.<br>
Copyright:  © 2020 Daan van den Bergh All Rights Reserved.<br>
Supported Operating Systems: macos & linux.<br>
<br>
<br>
<p align="center">
  <img src="https://raw.githubusercontent.com/vandenberghinc/public-storage/master/vandenberghinc/icon/icon.png" alt="Bergh-Encryption" width="50"> 
</p>

## Table of content:
  * [Description](#description)
  * [Installation](#installation)
  * [Notes.](#notes.)
  * [CLI Usage](#cli-usage)
  * [Code Examples](#code-examples)

# Description:
Python & cli ssh toolset.

# Installation:
Install the package.

	curl -s https://raw.githubusercontent.com/vandenberghinc/ssht00ls/master/ssht00ls/requirements/installer.remote | bash 

# Notes.
1. (linux required to convert smart card modes.)

# CLI Usage:
	Usage: ssht00ls <mode> <options> 
	Modes:
	    Keys:
	        --generate : Generate a ssh key.
	            --path /keys/mykey/ : Specify the keys directory path.
	            --passphrase Passphrase123 : Specify the keys passphrase.
	            --comment 'My Key' : Specify the keys comment.
	    Aliases:
	        --list-aliases : List all aliases.
	            --joiner ',' : Optionally specify the joiner.
	        --alias example.com : Select one or multiple aliases (example: x,y,z) (or use all to select all aliases).
	            --info : Show the aliases info.
	            --delete   : Delete an alias.
	                -f / --forced : Ignore the are you sure prompt.
	            --create : Create an alias.
	                --server example.com : Specify the server's name.
	                --username myuser : Specify the username.
	                --ip 0.0.0.0 : Specify the server's ip.
	                --port 22 : Specify the server's port.
	                for ssh keys :
	                --key /path/to/key/private_key : Specify the path to the private key.
	                --passphrase 'MyPassphrase123' : Specify the keys pasphrase (optional).
	                for smart cards :
	                --smart-cards : Enable the smart cards boolean.
	                --pin 123456 : Specify the smart cards pin code (optional).
	            --edit : Edit the alias config.
	                *** same options as --create ***:
	                --alias newalias : Rename the alias.
	    Sessions:
	        --command <alias> 'ls .' : Execute a command over ssh.
	        --session <alias> : Start a ssh session.
	            --options ''  : Specify additional ssh options (optional).
	    Push & pull:
	        --pull <path> <alias>:<remote> : Pull a file / directory.
	            --delete : Also update the deleted files (optional).
	            --safe : Enable version control.
	            --forced : Enable forced mode.
	        --push <alias>:<remote> <path> : Push a file / directory.
	            --delete  : Also update the deleted files (optional).
	            --safe  : Enable version control.
	            --forced  : Enable forced mode.
	            --exclude .git,.gitignore  : Exclude additional subpaths (optioal).
	            --no-exclude : Skip the default excludes and exlude nothing.
	    Mounts:
	        --mount <alias>:<id> <path> : Mount a remote share.
	            --smb : Select smb mode (default).
	            --sshfs : Select sshfs mode (when enabled parameter id becomes remote).
	            *** smb options: *** : SMB --mount options.
	            --reconnect : Attempt to reconnect the mount when the connection is lost.
	            --tunnel : Mount the smb share through a ssh tunnel (overwrites options --port & --ip).
	            --username administrator : Overwrite the smb user (default is retrieved from alias).
	            --password 'SomePassphrase123' : Set the password of the smb user login (default is no password '').
	            --port 445 : Select a specific smb port (default is 445).
	            --ip 127.0.0.1 : Select a specific ip (default is retrieved from alias).
	        --unmount <path> : Unmount a mounted share.
	            --sudo   : Root permission required.
	            --forced   : Enable forced mode.
	    Tunnels:
	        --list-tunnels [optional: <alias>] : List all tunnels, optionally pass an alias filter.
	            --joiner ','  : Optionally specify the joiner.
	        --tunnel <port>:<ip>:<remote_port>:<alias> : Select a ssh tunnel.
	            --establish : Establish the selected ssh tunnel.
	                --reconnect : Attempt to reconnect the tunnel when the connection is lost.
	                --sleeptime 60 : Set the sleeptime value (default is 60) (only when --reconnect is enabled).
	                --reattempts 15 : Set the reattempts value (default is 15) (only when --reconnect is enabled).
	            --kill : Kill the selected ssh tunnel.
	    Agent:
	        --sync : Manually synchronize the aliases & add the keys to the agent.
	        --start-agent : Start the ssht00ls agent manually.
	        --stop-agent : Stop the ssht00ls agent.
	    Basic:
	        --kill <identifier> : Kill all ssh processes that include the identifier.
	        --config : Edit the ssht00ls configuration file (nano).
	        --reset-cache : Reset the cache directory.
	        --version : Show the ssht00ls version.
	        -h / --help : Show the documentation.
	Notes:
	    Include config file : Specify the $SSHT00LS_CONFIG environment variable to use a different ssht00ls config file.
	Author: Daan van den Bergh. 
	Copyright: © Daan van den Bergh 2020 - 2021. All rights reserved.

# Code Examples:

### Table of content:
- [__Agent__](#agent)
  * [add](#add)
  * [delete](#delete)
  * [list](#list)
  * [check](#check)
  * [initialize](#initialize)
- [__Aliases__](#aliases)
  * [list](#list-1)
  * [iterate](#iterate)
  * [check](#check-1)
  * [check_duplicate](#check_duplicate)
  * [info](#info)
  * [delete](#delete-1)
  * [edit](#edit)
  * [create](#create)
  * [sync](#sync)
  * [public](#public)
- [__Client__](#client)
  * [generate](#generate)
  * [create](#create-1)
  * [check](#check-2)
  * [exists](#properties)
- [__Connections__](#connections)
  * [list](#list-2)
- [__Encryption__](#encryption)
  * [generate](#generate-1)
  * [activate](#activate)
  * [activated](#properties-1)
- [__Installation__](#installation)
  * [install](#install)
  * [check_installed](#check_installed)
- [__Keys__](#keys)
  * [edit_passphrase](#edit_passphrase)
  * [edit_comment](#edit_comment)
  * [generate](#generate-2)
  * [check](#check-3)
  * [enable](#enable)
  * [disable](#disable)
- [__SCP__](#scp)
  * [download](#download)
  * [upload](#upload)
- [__SMB__](#smb)
  * [mount](#mount)
  * [unmount](#unmount)
  * [parse](#parse)
  * [id](#properties-2)
- [__SSH__](#ssh)
  * [session](#session)
  * [command](#command)
- [__SSHD__](#sshd)
  * [create](#create-2)
- [__SSHFS__](#sshfs)
  * [mount](#mount-1)
  * [unmount](#unmount-1)
- [__SSync__](#ssync)
  * [index](#index)
  * [set_mounted_icon](#set_mounted_icon)
  * [pull](#pull)
  * [push](#push)
- [__SmartCard__](#smartcard)
  * [get_info](#get_info)
  * [unblock_pin](#unblock_pin)
  * [change_pin](#change_pin)
  * [change_puk](#change_puk)
  * [generate_key](#generate_key)
  * [generate_management_key](#generate_management_key)
  * [reset_piv](#reset_piv)
  * [export_keys](#export_keys)
  * [check_smartcard](#check_smartcard)
  * [convert_to_smartcard](#convert_to_smartcard)
  * [install](#install-1)
- [__SmartCards__](#smartcards)
  * [scan](#scan)
  * [find_smartcard](#find_smartcard)
- [__Tunnel__](#tunnel)
  * [establish](#establish)
  * [kill](#kill)
  * [list](#list-3)
  * [iterate](#iterate-1)
  * [id](#properties-3)

## Agent:
The agent object class.
``` python 

# initialize the agent object class.
agent = ssht00ls.classes.agent.Agent(
    # initialize as specific not global (optional).
    # the path to the public key.
    public_key=None,
    # the path to the private key.
    private_key=None,
    # the smart card boolean.
    smartcard=False, )

```

#### Functions:

##### add:
``` python

# call agent.add.
response = agent.add(
    # the private key's path.
    private_key=None,
    # the public key's path (optional).
    public_key=None,
    # the keys passphrase.
    passphrase=None,
    # enable if you are using a smart card.
    smartcard=False,
    # the smart cards pin code
    pin=None,
    # default timeout (do not use).
    timeout=0.5,
    # reattempt (do not use).
    reattempt=True, )

```
##### delete:
``` python

# call agent.delete.
response = agent.delete()

```
##### list:
``` python

# call agent.list.
response = agent.list()

```
##### check:
``` python

# call agent.check.
response = agent.check(public_key=None, raw=False)

```
##### initialize:
``` python

# call agent.initialize.
response = agent.initialize()

```

## Aliases:
The aliases object class.
``` python 

# initialize the aliases object class.
aliases = ssht00ls.classes.aliases.Aliases(
    # initialize as specific not global (optional).
    #     the alias.
    alias=None,
    #     the username.
    username=None,
    #     the public ip.
    public_ip=None,
    #     the private ip.
    private_ip=None,
    #     the public port.
    public_port=None,
    #     the private port.
    private_port=None,
    #     the path to the public key.
    public_key=None,
    #     the path to the private key.
    private_key=None,
    #     the smart card boolean.
    smartcard=False,
    #     the log level.
    log_level=syst3m.defaults.options.log_level, )

```

#### Functions:

##### list:
``` python

# call aliases.list.
response = aliases.list()

```
##### iterate:
``` python

# call aliases.iterate.
_ = aliases.iterate()

```
##### check:
``` python

# call aliases.check.
response = aliases.check(
    # the alias to check.
    alias=None,
    # the info to check.
    #     adds / replaces the current (except the exceptions).
    info={},
    # the info key exceptions.
    exceptions=[],
    # the info value exceptions.
    value_exceptions=[],
    # create if not present (must also specify all required info when enabled).
    create=False, )

```
##### check_duplicate:
``` python

# call aliases.check_duplicate.
response = aliases.check_duplicate(alias=None)

```
##### info:
``` python

# call aliases.info.
response = aliases.info(alias=None)

```
##### delete:
``` python

# call aliases.delete.
response = aliases.delete(alias=None)

```
##### edit:
``` python

# call aliases.edit.
response = aliases.edit(
    # the alias.
    alias=None,
    # the edits (dict).
    #     adds / replaces the current (except the exceptions).
    edits={},
    # the edits key exceptions.
    exceptions=[],
    # the edits value exceptions.
    value_exceptions=[None],
    # save the edits.
    save=True,
    # the log level.
    log_level=syst3m.defaults.options.log_level, )

```
##### create:
``` python

# call aliases.create.
response = aliases.create(
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
    serialized={}, )

```
##### sync:
``` python

# call aliases.sync.
response = aliases.sync(aliases=["*"], interactive=None, log_level=None)

```
##### public:
``` python

# call aliases.public.
_ = aliases.public(public_ip=None, private_ip=None)

```

## Client:
The client object class.
``` python 

# initialize the client object class.
client = ssht00ls.classes.client.Client(
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
    parameters={}, )

```

#### Functions:

##### generate:
``` python

# call client.generate.
response = client.generate(
    # the new passphrase.
    passphrase=None,
    # the new smartcard pin.
    pin=None, )

```
##### create:
``` python

# call client.create.
response = client.create(
    # the new passphrase.
    passphrase=None,
    # the new smartcard pin.
    pin=None, )

```
##### check:
``` python

# call client.check.
response = client.check()

```

#### Properties:
```python

# the exists property.
exists = client.exists
```
```python

# the activated property.
activated = client.activated
```
```python

# the id property.
id = client.id
```
```python

# the alias  property.
alias_ = client.alias_
```
```python

# the username property.
username = client.username
```
```python

# the public ip property.
public_ip = client.public_ip
```
```python

# the private ip property.
private_ip = client.private_ip
```
```python

# the public port property.
public_port = client.public_port
```
```python

# the private port property.
private_port = client.private_port
```
```python

# the ip property.
ip = client.ip
```
```python

# the port property.
port = client.port
```
```python

# the public property.
public = client.public
```
```python

# the private key property.
private_key = client.private_key
```
```python

# the public key property.
public_key = client.public_key
```
```python

# the is smartcard property.
is_smartcard = client.is_smartcard
```

## Connections:
The connections object class.
``` python 

# initialize the connections object class.
connections = ssht00ls.classes.connections.Connections()

```

#### Functions:

##### list:
``` python

# call connections.list.
response = connections.list(filter="ssh")

```

## Encryption:
The encryption object class.
``` python 

# initialize the encryption object class.
encryption = ssht00ls.classes.encryption.Encryption(
    # the configuration file (Dictionary).
    config=Dictionary,
    # the webserver cache (syst3m.cache.WebServer).
    webserver=syst3m.cache.WebServer,
    # encrypted cache path.
    cache=None,
    # the passphrase (optional to prompt) (str).
    passphrase=None,
    # the interactive mode (prompt for password) (bool).
    interactive=True, )

```

#### Functions:

##### generate:
``` python

# call encryption.generate.
response = encryption.generate(
    # the passphrase (optional to prompt) (str).
    passphrase=None,
    # the verify passphrase (optional).
    verify_passphrase=None,
    # interactive (optional).
    interactive=None )

```
##### activate:
``` python

# call encryption.activate.
response = encryption.activate(
    # the key's passphrase (optional to retrieve from webserver) (str).
    passphrase=None,
    # interactive (optional)
    interactive=None, )

```

#### Properties:
```python

# the activated property.
activated = encryption.activated
```
```python

# the public key activated property.
public_key_activated = encryption.public_key_activated
```
```python

# the private key activated property.
private_key_activated = encryption.private_key_activated
```
```python

# the generated property.
generated = encryption.generated
```

## Installation:
The installation object class.
``` python 

# initialize the installation object class.
installation = ssht00ls.classes.installation.Installation()

```

#### Functions:

##### install:
``` python

# call installation.install.
response = installation.install(
    # optional define the user (leave None for current user).
    username=None, )

```
##### check_installed:
``` python

# call installation.check_installed.
response = installation.check_installed(
    # optional define the user (leave None for current user).
    username=None, )

```

## Keys:
The keys object class.
``` python 

# initialize the keys object class.
keys = ssht00ls.classes.keys.Keys(
    # initialize as specific not global (optional).
    #    the username.
    username=None,
    # the path to the public key.
    public_key=None,
    # the path to the private key.
    private_key=None, )

```

#### Functions:

##### edit_passphrase:
``` python

# call keys.edit_passphrase.
response = keys.edit_passphrase(path=None, old=None, new=None)

```
##### edit_comment:
``` python

# call keys.edit_comment.
response = keys.edit_comment(path=None, passphrase=None, comment=None)

```
##### generate:
``` python

# call keys.generate.
response = keys.generate(path=None, passphrase=None, comment="")

```
##### check:
``` python

# call keys.check.
response = keys.check(username=None, public_keys=[], reversed=False)

```
##### enable:
``` python

# call keys.enable.
response = keys.enable(username=None, public_keys=[])

```
##### disable:
``` python

# call keys.disable.
response = keys.disable(username=None, public_keys=[])

```

## SCP:
The scp object class.
``` python 

# initialize the scp object class.
scp = ssht00ls.classes.scp.SCP()

```

#### Functions:

##### download:
``` python

# call scp.download.
response = scp.download(
    # the file paths.
    server_path=None,
    client_path=None,
    directory=False,
    # the ssh params.
    # option 1:
    alias=None,
    # option 2:
    username=None,
    ip=None,
    port=22,
    key_path=None, )

```
##### upload:
``` python

# call scp.upload.
response = scp.upload(
    # the file paths.
    server_path=None,
    client_path=None,
    directory=False,
    # the ssh params.
    # option 1:
    alias=None,
    # option 2:
    username=None,
    ip=None,
    port=22,
    key_path=None, )

```

## SMB:
The smb object class.
``` python 

# initialize the smb object class.
smb = ssht00ls.classes.smb.SMB(
    # initialize as specific not global (optional).
    #     the share id (#1).
    id=None,
    #     the mountpoint path (#2).
    path=None,
    #     the alias (#3).
    alias=None,
    #     the server's ip (leave None to retrieve from alias).
    ip=None,
    #     the server's port.
    port=445,
    #     tunnel smb through ssh.
    tunnel=False,
    tunnel_obj=None, # do not use the tunnel_obj parameter.
    #     the reconnect boolean (only used whe tunnel is enabled).
    reconnect=False,
    #     the thread's sleeptime.
    sleeptime=60,
    #     the reconnect reattemps.
    reattemps=15,
    #     the log level.
    log_level=syst3m.defaults.options.log_level, )

```

#### Functions:

##### mount:
``` python

# call smb.mount.
response = smb.mount(
    # the share id (leave None to use smb.id) (REQUIRED) (#1).
    id=None,
    # the mountpoint path (leave None to use smb.path) (REQUIRED) (#2).
    path=None,
    # the ssh alias (leave None to use smb.alias) (REQUIRED) (#3).
    alias=None,
    # the username of for the remote server (leave None to use the aliases username).
    username=None,
    # the password of the remote server's user (optional) (leave None to prompt) (use "" for no passphrase).
    password=None,
    # the ip of the remote server (leave None to use the aliases ip).
    ip=None,
    # the port (leave None to use smb.port).
    port=None,
    # tunnel over ssh (leave None to use smb.tunnel).
    tunnel=None,
    # the reconnect boolean (only used whe tunnel is enabled) (leave None to use smb.reconnect).
    reconnect=None,
    # the log level (leave None to use smb.log_level).
    log_level=None, )

```
##### unmount:
``` python

# call smb.unmount.
response = smb.unmount(
    # the mountpoint path (leave None to use smb.path) (REQUIRED) (#1).
    path=None,
    # the forced umount option.
    forced=False,
    # root permission required for force.
    sudo=False,
    # the log level (leave None to use smb.log_level).
    log_level=None, )

```
##### parse:
``` python

# call smb.parse.
response = smb.parse(
    # the mountpoint path (leave None to use smb.path) (REQUIRED) (#1).
    path=None, )

```

#### Properties:
```python

# the id property.
id = smb.id
```
```python

# the mounted property.
mounted = smb.mounted
```

## SSH:
The ssh object class.
``` python 

# initialize the ssh object class.
ssh = ssht00ls.classes.ssh.SSH(
    # initialize as specific not global (optional).
    #     the alias.
    alias=None, )

```

#### Functions:

##### session:
``` python

# call ssh.session.
response = ssh.session(
    alias=None, )

```
##### command:
``` python

# call ssh.command.
_ = ssh.command(
    # the alias.
    alias=None,
    # the command to execute.
    command=None,
    # serialize the output to json.
    serialize=False,
    # the log level.
    log_level=0, )

```

## SSHD:
The sshd object class.
``` python 

# initialize the sshd object class.
sshd = ssht00ls.classes.sshd.SSHD()

```

#### Functions:

##### create:
``` python

# call sshd.create.
response = sshd.create(
    # save the configuration & banner.
    save=False,
    # the ssh port.
    port=22,
    # the listen addresses.
    listen_addresses=[],
    # the server's banner.
    banner="Hello World!",
    # the allowed users & options.
    users={
        # define per user (all keys are optional).
        "administrator": {
            # the user's root permissions.
            "root_permissions":False,
            # authentication by password.
            "password_authentication":False,
            # authentication by keys.
            "key_authentication":True,
            # ip filter.
            "ip_filter":False,
            "allowed_ips":[],
            # sftp server only.
            "sftp_only":False,
            # the chroot directory (leave null to disable).
            "chroot_directory":None,
            # allowed connection options.
            "x11_forwarding":False,
            "tcp_forwarding":False,
            "permit_tunnel":False,
            "allow_stream_local_forwarding":False,
            "gateway_ports":False,
        },
    }, )

```

## SSHFS:
The sshfs object class.
``` python 

# initialize the sshfs object class.
sshfs = ssht00ls.classes.sshfs.SSHFS()

```

#### Functions:

##### mount:
``` python

# call sshfs.mount.
response = sshfs.mount(
    # the directory paths.
    remote=None,
    path=None,
    # the ssh params.
    # option 1:
    alias=None,
    # option 2:
    username=None,
    ip=None,
    port=22,
    key_path=None, )

```
##### unmount:
``` python

# call sshfs.unmount.
response = sshfs.unmount(
    # the client path.
    path=None,
    # the forced umount option.
    forced=False,
    # forced option may require sudo.
    sudo=False, )

```

## SSync:
The ssync object class.
``` python 

# initialize the ssync object class.
ssync = ssht00ls.classes.ssync.SSync(
    # initialize as specific not global (optional).
    #    the username.
    alias=None, )

```

#### Functions:

##### index:
``` python

# call ssync.index.
response = ssync.index(path=None, alias=None, log_level=0, checks=True, accept_new_host_keys=True)

```
##### set_mounted_icon:
``` python

# call ssync.set_mounted_icon.
_ = ssync.set_mounted_icon(path)

```
##### pull:
``` python

# call ssync.pull.
response = ssync.pull(
    # the local path.
    path=None,
    # the ssht00ls alias.
    alias=None,
    # the remote path.
    remote=None,
    # exlude subpaths (list) (leave None to exclude none).
    exclude=[],
    # path is directory boolean (leave None to parse automatically).
    directory=True,
    empty_directory=False,
    # update deleted files.
    delete=False,
    # forced mode.
    forced=False,
    # version control.
    safe=False,
    # accept new hosts keys.
    accept_new_host_keys=True,
    # checks.
    checks=True,
    # log level.
    log_level=0,
    # get the command in str.
    command=False, )

```
##### push:
``` python

# call ssync.push.
response = ssync.push(
    # the local path.
    path=None,
    # the ssht00ls alias.
    alias=None,
    # the remote path.
    remote=None,
    # exlude subpaths (list) (leave None to exclude none).
    exclude=[],
    # path is directory boolean (leave None to parse automatically).
    directory=True,
    empty_directory=False,
    # update deleted files.
    delete=False,
    # forced mode.
    forced=False,
    # version control.
    safe=False,
    # accept new hosts keys.
    accept_new_host_keys=True,
    # checks.
    checks=True,
    check_base=True,
    # log level.
    log_level=0,
    # get the command in str.
    command=False, )

```

## SmartCard:
The smartcard object class.
``` python 

# initialize the smartcard object class.
smartcard = ssht00ls.classes.smartcards.SmartCard(serial_number=None)

```

#### Functions:

##### get_info:
``` python

# call smartcard.get_info.
response = smartcard.get_info()

```
##### unblock_pin:
``` python

# call smartcard.unblock_pin.
response = smartcard.unblock_pin(
    # the new pin code.
    pin=None,
    # the smart cards puk code
    puk=None, )

```
##### change_pin:
``` python

# call smartcard.change_pin.
response = smartcard.change_pin(
    # the smart cards new pin code.
    new=None,
    # the smart cards old pin code.
    old=123456, )

```
##### change_puk:
``` python

# call smartcard.change_puk.
response = smartcard.change_puk(
    # the smart cards new puk code.
    new=None,
    # the smart cards old puk code.
    old=12345678, )

```
##### generate_key:
``` python

# call smartcard.generate_key.
response = smartcard.generate_key(
    # the smart cards pin code.
    pin=None, )

```
##### generate_management_key:
``` python

# call smartcard.generate_management_key.
response = smartcard.generate_management_key(
    # the smart cards pin code.
    pin=None, )

```
##### reset_piv:
``` python

# call smartcard.reset_piv.
response = smartcard.reset_piv()

```
##### export_keys:
``` python

# call smartcard.export_keys.
response = smartcard.export_keys(
    # optionally save the keys to a file.
    path=None, )

```
##### check_smartcard:
``` python

# call smartcard.check_smartcard.
response = smartcard.check_smartcard()

```
##### convert_to_smartcard:
``` python

# call smartcard.convert_to_smartcard.
response = smartcard.convert_to_smartcard()

```
##### install:
``` python

# call smartcard.install.
response = smartcard.install(
    # specify a new pin (optional).
    pin=None,
    # specify a new puk (optional).
    puk=None, )

```

## SmartCards:
The smartcards object class.
``` python 

# initialize the smartcards object class.
smartcards = ssht00ls.classes.smartcards.SmartCards()

```

#### Functions:

##### scan:
``` python

# call smartcards.scan.
response = smartcards.scan(silent=False)

```
##### find_smartcard:
``` python

# call smartcards.find_smartcard.
response = smartcards.find_smartcard(serial_number=None)

```

## Tunnel:
The tunnel object class.
``` python 

# initialize the tunnel object class.
tunnel = ssht00ls.classes.ssh.tunnel.Tunnel(
    # initialize as specific not global (optional).
    #     the alias.
    alias=None,
    #     the tunnel ip.
    ip=None,
    #     the local port.
    port=None,
    #     the remote port.
    remote_port=None,
    #     the reconnect boolean.
    reconnect=False,
    #     the thread's sleeptime.
    sleeptime=60,
    #     the reconnect reattemps.
    reattemps=15,
    #     the log level.
    log_level=0, )

```

#### Functions:

##### establish:
``` python

# call tunnel.establish.
response = tunnel.establish(
    # the alias.
    alias=None,
    # the tunnel ip.
    ip=None,
    # the local port.
    port=None,
    # the remote port.
    remote_port=None,
    # the reconnect boolean (leave None to use False).
    reconnect=None,
    # the log level (leave None to use 0).
    log_level=None, )

```
##### kill:
``` python

# call tunnel.kill.
response = tunnel.kill(
    # the alias.
    alias=None,
    # the tunnel ip.
    ip=None,
    # the local port.
    port=None,
    # the remote port.
    remote_port=None,
    # the log level.
    log_level=None, )

```
##### list:
``` python

# call tunnel.list.
response = tunnel.list(alias=None)

```
##### iterate:
``` python

# call tunnel.iterate.
_ = tunnel.iterate(alias=None)

```

#### Properties:
```python

# the id property.
id = tunnel.id
```
```python

# the established property.
established = tunnel.established
```
```python

# the pid property.
pid = tunnel.pid
```

