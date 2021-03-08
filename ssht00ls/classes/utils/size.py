import os, sys
from dev0s import *
size = None
path = sys.argv[1]
if not Files.exists(path):
	Response.log(response=Response.error(f"Path {path} does not exist."))
else:
	Response.log(response=Response.success(f"Successfully retrieved the size of {path}.", {
		"size":FilePath(path).size(mode="MB"),
	}))