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
abs_path =	os.path.abspath

# constants
EMU_DIR = abs_path(dir_name(__file__))


# Python exception handler
def exception_hook(type, value, traceback):
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)


if __name__ == "__main__":
	sys.excepthook = exception_hook

	configs = os.listdir(f"{EMU_DIR}/configs")
	if not configs: raise ValueError("no emulation config found")
	config = configs[0] if len(configs) <= 1 else \
		prompt(List(
			"emulation_config",
			message="select emulation config",
			choices=configs
		))["emulation_config"]

	with open(config, "r") as file:
		config = json.load(file)

	envs = os.popen("cat platformio.ini | grep env: | sed 's/.*env://' | sed 's/]//'").read()
	if not envs: raise ValueError("no platformio config found")
	envs = envs.split("\n")[:-1]
	env = envs[0] if len(envs) <= 1 else \
		prompt(List(
			"build_config",
			message="select build config",
			choices=envs
		))["build_config"]

	os.system(f"pio debug -e {env}")
	os.system(f"cp ./.pio/build/{env}/firmware.bin {EMU_DIR}/{env}.bin")
	os.system(f"cp ./.pio/build/{env}/firmware.elf {EMU_DIR}/{env}.elf")

	print(config, env)


# ARM emulator should:
# 1. Read the ./doc/ files to find information on pin definitions and memory map
# 2. Have a config file containing additional information
# 3. Have a real time ociloscope output CLI
# 4. have threads emulating hardware