#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# import classes.
# keep this import style so you can also use the keys.Keys() etc directly.
from ssht00ls import classes
from ssht00ls.classes import ssht00ls_agent, network_info

# import initialized classes & objects.
from ssht00ls.classes.installation import installation
from ssht00ls.classes.sshd import sshd
from ssht00ls.classes.sshfs import sshfs
from ssht00ls.classes.scp import scp
from ssht00ls.classes.agent import agent
from ssht00ls.classes.keys import keys
from ssht00ls.classes.connections import connections
from ssht00ls.classes.smartcards import smartcards, SmartCard
from ssht00ls.classes.aliases import aliases
from ssht00ls.classes.ssh import ssh
from ssht00ls.classes.ssync import ssync
from ssht00ls.classes.smb import smb
from ssht00ls.classes.client import clients, Client

# shortcuts.
push = ssync.push
pull = ssync.pull

# source path & version.
from dev0s.shortcuts import Version, Directory, Files, gfp
source = Directory(gfp.base(__file__))
base = Directory(source.fp.base())
version = Version(Files.load(source.join(".version")))