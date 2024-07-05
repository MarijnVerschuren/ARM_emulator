# emulator includes
from unicorn import *
from unicorn.arm_const import *
from capstone import *
# TUI includes
from inquirer import List, Checkbox, prompt as _prompt
from rich import print
# helper includes
import readline
# general includes
import json, sys, os

from helpers import namespace


# partials, lambda's and aliases
prompt = lambda x: _prompt([x,], raise_keyboard_interrupt=True)
dir_name =	os.path.dirname
abs_path =	os.path.abspath

# constants
EMU_DIR =	abs_path(dir_name(__file__))
CFG	=		namespace()

# init disassembler
asm = Cs(CS_ARCH_ARM, UC_MODE_THUMB); asm.detail = True
emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)


# Python exception handler
def exception_hook(type, value, traceback):
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)

# helpers
def parse_dict(data: dict) -> namespace:
	ns = namespace(**data)
	for key, val in data.items():
		if not isinstance(val, dict): continue
		ns.__setattr__(key, parse_dict(val))
	return ns

# init
def init_config() -> None:
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
		file.close()

	CFG.emu = parse_dict(config["EMU"])
	CFG.dut = parse_dict(config["DUT"])
def compile_env() -> str:
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
	return env
def load_binary(env: str) -> None:
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

	CFG.code = code
	CFG.info = namespace(**{
		"stack_pointer":	stack_pointer,
		"entry_point":		entry_point,
		"sections":			sections,
		"functions":		functions,
		"variables":		variables
	})



# emulation hooks
def memory_invalid_hook(emu, access, address, size, value, user_data):
	print(f"invalid: {access}, {hex(address)}, {size}, {value}: {hex(value)}")
	return False

def memory_read_hook(emu, access, address, size, value, user_data):
	print(f"read: {access}, {hex(address)}, {size}, {value}")

def memory_write_hook(emu, access, address, size, value, user_data):
	print(f"write: {access}, {hex(address)}, {size}, {value}")

def code_hook(emu, address, size, user_data):
	f_address = 0; f_name = ""
	for f_address, s, f_name in CFG.info.functions[::-1]:
		if f_address < address: break
	opcode = emu.mem_read(address, size)
	mnemonics = asm.disasm(opcode, address)
	for i in mnemonics:
		print(f"{hex(i.address)} ({f_name} + {hex(address - f_address)}): {i.mnemonic}\t{i.op_str}")

def interrupt_hook(emu, address, size, user_data):
	print("interrupt")



if __name__ == "__main__":
	sys.excepthook = exception_hook

	# init sequence
	init_config()
	env = compile_env()
	load_binary(env)

	print(CFG)

	# setup memory map and code loading
	for bank in CFG.emu.mem.flash:
		print("map: ", CFG.dut.mem.flash[bank], CFG.dut.mem.flash[f"{bank}_size"])
		emu.mem_map(CFG.dut.mem.flash[bank], CFG.dut.mem.flash[f"{bank}_size"])
	#emu.mem_map(periph["start"], periph["end"] - periph["start"])	# map peripheral space
	# emu.mem_map(UNKNOWN, UNKNOWN_END - UNKNOWN)	# map unknown space
	# emu.mem_map(VAR_BASE, 0x100000)		# map variable space

	# TODO

# ARM emulator should:
# 1. Read the ./doc/ files to find information on pin definitions and memory map
# 2. Have a config file containing additional information
# 3. Have a real time ociloscope output CLI
# 4. have threads emulating hardware