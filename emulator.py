# emulator includes
from unicorn import *
from unicorn.arm_const import *
# TUI includes
from rich import print
# general includes
import json, sys, os

# custom includes
from helpers import *
from emulator import *


# partials, lambda's and aliases
dir_name =	os.path.dirname
abs_path =	os.path.abspath

# constants
EMU_DIR =		abs_path(dir_name(__file__))
EMU_ARG =		{"arch": UC_ARCH_ARM, "mode": UC_MODE_THUMB}

# Python exception handler
def exception_hook(type, value, traceback):
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)

# init
def init_config() -> Software:
	os.chdir(EMU_DIR)
	configs = os.listdir("./configs")
	if not configs: raise ValueError("no emulation config found")
	config = configs[0] if len(configs) <= 1 else \
		prompt(Choice(
			"emulation_config",
			message="select emulation config",
			choices=configs
		))

	with open(f"./configs/{config}", "r") as file:
		soft = load_emu(file, **EMU_ARG)
		file.close()

	return soft
def compile_env() -> str:
	envs = os.popen("cat platformio.ini | grep env: | sed 's/.*env://' | sed 's/]//'").read()
	if not envs: raise ValueError("no platformio config found")

	envs = envs.split("\n")[:-1]
	env = envs[0] if len(envs) <= 1 else \
		prompt(Choice(
			"build_config",
			message="select build config",
			choices=envs
		))

	os.system(f"pio debug -e {env}")
	os.system(f"cp ./.pio/build/{env}/firmware.bin {EMU_DIR}/{env}.bin")
	os.system(f"cp ./.pio/build/{env}/firmware.elf {EMU_DIR}/{env}.elf")
	return env
def load_binary(env: str) -> tuple[bytes, dict]:
	with open(f"{EMU_DIR}/{env}.bin", "rb") as prog:
		code = prog.read()
		prog.close()

	symbols = os.popen(
		f"arm-none-eabi-readelf {EMU_DIR}/{env}.elf -Ws |" +
		"grep -E 'FUNC|OBJECT|SECTION' |" +
		"grep -E 'LOCAL|GLOBAL' |" +
		"sed 's/.*: //'"
	).read().split("\n")
	stack_pointer =	int.from_bytes(code[0:4], "little")
	entry_point =	int.from_bytes(code[4:8], "little")
	sections =		sorted([(int(s[0:8], 16), s[43:]) for s in symbols if "SECTION" in s], key=lambda x: x[0])
	functions =		sorted([(int(s[0:8], 16), int(s[8:14]), s[43:]) for s in symbols if "FUNC" in s], key=lambda x: x[0])
	variables =		sorted([(int(s[0:8], 16), int(s[8:14]), s[43:]) for s in symbols if "OBJECT" in s], key=lambda x: x[0])

	return code, {
		"stack_pointer":	stack_pointer,
		"entry_point":		entry_point,
		"sections":			sections,
		"functions":		functions,
		"variables":		variables
	}


if __name__ == "__main__":
	sys.excepthook = exception_hook

	# init sequence
	emu = init_config()
	env = compile_env()
	code, info = load_binary(env)

	# load code
	emu.load_code(code, info)

	# start emulation
	try:					emu.start()
	except UcError as e:	print(e)


# ARM emulator should:
# 1. Read the ./doc/ files to find information on pin definitions and memory map
# 2. Have a config file containing additional information
# 3. Have a real time ociloscope output CLI
# 4. have threads emulating hardware