# emulator includes
from unicorn import *
from unicorn.arm_const import *
from capstone import *
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
CFG	=			namespace()
CFG.asm = asm =	Cs(CS_ARCH_ARM, UC_MODE_THUMB); asm.detail = True
emu =			Uc(UC_ARCH_ARM, UC_MODE_THUMB)


# Python exception handler
def exception_hook(type, value, traceback):
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)


# init
def init_config() -> None:
	configs = os.listdir(f"{EMU_DIR}/configs")
	if not configs: raise ValueError("no emulation config found")
	config = configs[0] if len(configs) <= 1 else \
		prompt(Choice(
			"emulation_config",
			message="select emulation config",
			choices=configs
		))

	with open(f"{EMU_DIR}/configs/{config}", "r") as file:
		config = json.load(file)
		file.close()

	CFG.emu = parse_dict(config["EMU"])
	CFG.dut = parse_dict(config["DUT"])

	with open(f"{EMU_DIR}/dev_configs/{CFG.dut.hardware}") as file:
		CFG.dut.hardware = load_hardware_config(emu, json.load(file))
		file.close()

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



if __name__ == "__main__":
	sys.excepthook = exception_hook

	# init sequence
	init_config()
	env = compile_env()
	load_binary(env)

	# setup memory map and code loading
	emem, dmem = CFG.emu.mem, CFG.dut.mem
	for bank in emem.flash:	emu.mem_map(dmem.flash[bank],		dmem.flash[f"{bank}_size"])		# memory map flash banks
	if emem.periph:			emu.mem_map(dmem.periph.start,		dmem.periph.size)				# memory map peripheral space
	if emem.var:			emu.mem_map(dmem.var.start,			dmem.var.size)					# memory map variable space
	if emem.ROM_table:		emu.mem_map(dmem.ROM_table.start,	dmem.ROM_table.size)			# memory map ROM_table space
	emu.mem_write(emem.load, CFG.code)															# load code

	# add hooks
	emu.hook_add(
		UC_HOOK_MEM_READ_UNMAPPED	|
		UC_HOOK_MEM_WRITE_UNMAPPED	|
		UC_HOOK_MEM_INVALID,
		memory_invalid_hook,
		user_data=CFG
	)
	emu.hook_add(UC_HOOK_MEM_READ,		memory_read_hook,	user_data=CFG)
	emu.hook_add(UC_HOOK_MEM_WRITE,		memory_write_hook,	user_data=CFG)
	emu.hook_add(UC_HOOK_CODE,			code_hook,			user_data=CFG)
	emu.hook_add(UC_HOOK_INTR,			interrupt_hook,		user_data=CFG)

	# init hardware emulation
	init_hardware(emu, CFG.dut.hardware)

	# start emulation
	emu.reg_write(UC_ARM_REG_SP, CFG.info.stack_pointer)
	try:					emu.emu_start(CFG.info.entry_point, emem.load + len(CFG.code))
	except UcError as e:	print(e)


# ARM emulator should:
# 1. Read the ./doc/ files to find information on pin definitions and memory map
# 2. Have a config file containing additional information
# 3. Have a real time ociloscope output CLI
# 4. have threads emulating hardware