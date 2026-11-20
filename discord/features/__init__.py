# more on this soon
import glob, importlib, os

all = []

for path in sorted(glob.glob(os.path.dirname(__file__) + "/[!_]*.py")):
	all.append(importlib.import_module("features." + os.path.basename(path)[:-3]))
