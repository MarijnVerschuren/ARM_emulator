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

# init disassembler
asm = Cs(CS_ARCH_ARM, UC_MODE_THUMB); asm.detail = True
emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)


# Python exception handler
def exception_hook(type, value, traceback):
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)


# emulation hooks
def memory_invalid_hook(emu, access, address, size, value, user_data):
	print(f"invalid: {access}, {hex(address)}, {size}, {value}: {hex(value)}")
	return False


def memory_read_hook(emu, access, address, size, value, user_data):
	print(f"read: {access}, {hex(address)}, {size}, {value}")


def memory_write_hook(emu, access, address, size, value, user_data):
	print(f"write: {access}, {hex(address)}, {size}, {value}")


def code_hook(emu, address, size, user_data):
	for f_address, s, f_name in functions[::-1]:
		if f_address < address: break
	opcode = emu.mem_read(address, size)
	mnemonics = asm.disasm(opcode, address)
	for i in mnemonics:
		print(f"{hex(i.address)} ({f_name} + {hex(address - f_address)}): {i.mnemonic}\t{i.op_str}")


def interrupt_hook(emu, address, size, user_data):
	print("interrupt")



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

	with open(f"{EMU_DIR}/configs/{config}", "r") as file:
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

	# read and analyse binary
	ADDRESS = config["memory"]["load"]
	with open(f"{EMU_DIR}/{env}.bin", "rb") as prog:
		CODE = prog.read()
		prog.close()

	symbols = os.popen(
		f"arm-none-eabi-readelf {EMU_DIR}/{env}.elf -Ws |" +
		"grep -E 'FUNC|OBJECT|SECTION' |" +
		"grep -E 'LOCAL|GLOBAL' |" +
		"sed 's/.*: //'"
	).read().split("\n")
	sp = int.from_bytes(CODE[0:4], "little")
	entry = int.from_bytes(CODE[4:8], "little")
	sections = sorted([(int(s[0:8], 16), s[43:]) for s in symbols if "SECTION" in s], key=lambda x: x[0])
	functions = sorted([(int(s[0:8], 16), int(s[8:14]), s[43:]) for s in symbols if "FUNC" in s], key=lambda x: x[0])
	variables = sorted([(int(s[0:8], 16), int(s[8:14]), s[43:]) for s in symbols if "OBJECT" in s], key=lambda x: x[0])

	print(config, env, sp, entry, sections, functions, variables)


# ARM emulator should:
# 1. Read the ./doc/ files to find information on pin definitions and memory map
# 2. Have a config file containing additional information
# 3. Have a real time ociloscope output CLI
# 4. have threads emulating hardware