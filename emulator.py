# emulator includes
from unicorn import *
from unicorn.arm_const import *
from capstone import *
# TUI includes
from inquirer import List, Checkbox, prompt as _prompt
from argparse import ArgumentParser
from rich import print
# helper includes
from subprocess import Popen, PIPE, STDOUT
from functools import partial
from struct import pack
from re import finditer
# general includes
import json, sys, os

# partials, lambda's and aliases
prompt = lambda x: _prompt([x,], raise_keyboard_interrupt=True)
dir_name =	os.path.dirname



# Python exception handler
def exception_hook(type, value, traceback):
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)


if __name__ == "__main__":
	sys.excepthook = exception_hook
	#os.chdir(dir_name(dir_name(os.getcwd())))

	configs = os.popen("cat platformio.ini | grep env: | sed 's/.*env://' | sed 's/]//'").read()
	if not configs: raise ValueError("no platformio config found")
	build_config = prompt(List(
		"build_config",
		message="select build config",
		choices=configs.split("\n")[:-1]
		))["build_config"]

	print(build_config)


