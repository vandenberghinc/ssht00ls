#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports.
import os, sys
from dev0s.shortcuts import *

# index.
def index(path):
	indexed, dir, ids = Dictionary(path=False, dictionary={}), Files.Directory(path=path), []
	for _path_ in dir.paths(recursive=True, files_only=True, banned=[f"Icon\r"], banned_names=[".DS_Store", "._DS_Store", "__pycache__"]):
		if _path_ not in ids: 
			indexed[_path_] = gfp.mtime(path=_path_, format="seconds")
			ids.append(_path_)
	for _path_ in dir.paths(recursive=True, dirs_only=True, banned=[f"Icon\r"], banned_names=[".DS_Store", "._DS_Store", "__pycache__"]):
		id = _path_+" (d)"
		if os.listdir(_path_) == []: id += " (e)"
		if id not in ids:
			indexed[id] = gfp.mtime(path=_path_, format="seconds")
			ids.append(id)
	return indexed.sort(alphabetical=True)

# main.
if __name__ == "__main__":

	# arguments.
	path = dev0s.cli.get_argument("--path")
	json = dev0s.cli.arguments_present(["--json", "-j"])

	# checks.
	if not Files.exists(path):
		dev0s.response.log(response=dev0s.response.error(f"Path [{path}] does not exist."), json=json)
	elif not os.path.isdir(path):
		dev0s.response.log(response=dev0s.response.error(f"Path [{path}] is not a directory."), json=json)

	# handler.
	dict = index(path)
	dev0s.response.log(json=json, response=dev0s.response.success(f"Successfully indexed {len(dict)} files from directory [{path}].", {
		"index":dict,
	}))