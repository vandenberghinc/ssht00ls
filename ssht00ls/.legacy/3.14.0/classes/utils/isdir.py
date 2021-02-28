import os, sys
from fil3s import *
status = None
path = sys.argv[1]
if not Files.exists(path):
	status = "does-not-exist"
elif os.path.isdir(path):
	status = "directory"
else:
	status = "file"
print(status)