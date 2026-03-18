# emulator includes
from threading import Thread
from unicorn import *
from unicorn.arm_const import *
# TUI includes
from rich import print
# general includes
import json, sys, os

# custom includes
from helpers import *
from emulator import *
from TUI.TUI_lib import *


# partials, lambda's and aliases
dir_name =	os.path.dirname
abs_path =	os.path.abspath

# constants
EMU_DIR =		abs_path(dir_name(__file__))
EMU_ARG =		{"arch": UC_ARCH_ARM, "mode": UC_MODE_THUMB}



# TUI class
class Emulator_TUI(Emulator_UI):
	def __init__(self) -> None:
		color = (0xD9, 0xA3, 0x4C)
		config = {
			"grid": [3, 2],
			"modules": {
				"tbox": [
					{"x": 0, "y": 0, "w": 1, "h": 2, "title": "code",		"color": color, "augments": [(0, 1, "❯")]},
					{"x": 1, "y": 0, "w": 1, "h": 1, "title": "call_stack",	"color": color, "augments": [(0, 1, "❯")]},
					{"x": 2, "y": 0, "w": 1, "h": 1, "title": "registers",	"color": color},
					{"x": 1, "y": 1, "w": 2, "h": 1, "title": "hardware",	"color": color},
				]
			}
		}
	
		self.tui = TUI(**config)
		self.code_tbox =		self.tui.get_child("tbox", "code")
		self.hardware_tbox =	self.tui.get_child("tbox", "hardware")
		self.call_stack_tbox =	self.tui.get_child("tbox", "call_stack")
		self.register_tbox =	self.tui.get_child("tbox", "registers")
	
	
	def log(self, log_type: str, text: str) -> None:
		if log_type == "CODE":
			self.code_tbox.add(text)
		elif log_type == "MEM":
			self.hardware_tbox.add(text)
		elif log_type == "CALL":
			self.call_stack_tbox.add(text)
		elif log_type == "RET":
			self.call_stack_tbox.pop()
			if self.call_stack_tbox[0] != text:
				pass # TODO: error
		elif log_type == "IRQ_RET":
			self.call_stack_tbox.pop()
			# TODO: some error checking
		elif log_type == "IRQ_CALL":
			self.call_stack_tbox.add(f"{rgb_fg(255,135,0)}[↯] {text}{COL_RESET}")




# Python exception handler
def exception_hook(type, value, traceback):
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)


# init
def init_config(single_step: bool = False, UI_class: Emulator_UI = Emulator_UI_default()) -> Software:
	configs = os.listdir(f"{EMU_DIR}/configs")
	if not configs: raise ValueError("no emulation config found")
	config = configs[0] if len(configs) <= 1 else \
		prompt(Choice(
			"emulation_config",
			message="select emulation config",
			choices=configs
		))

	with open(f"{EMU_DIR}/configs/{config}", "r") as file:
		factory = load_emu(file)
		file.close()
	
	return factory(f"{EMU_DIR}/dev_configs", single_step=single_step, UI_class=UI_class, **EMU_ARG)


def compile_pio_env() -> str:
	envs = os.popen("cat platformio.ini | grep env: | sed 's/.*env://' | sed 's/]//'").read()
	if not envs: raise ValueError("no platformio config found")

	envs = envs.split("\n")[:-1]
	env = envs[0] if len(envs) == 1 else \
		prompt(Choice(
			"build_config",
			message="select build config",
			choices=envs
		))

	os.system(f"pio debug -e {env}")
	os.system(f"cp ./.pio/build/{env}/firmware.bin {EMU_DIR}/{env}.bin")
	os.system(f"cp ./.pio/build/{env}/firmware.elf {EMU_DIR}/{env}.elf")
	return env	# binary name


def compile_cmake_env() -> str:
	print("TODOOOO")
	return ""	# binary name


def select_binary() -> str:
	bins = os.listdir(f"{EMU_DIR}/bin")
	bin = bins[0] if len(bins) == 1 else \
		prompt(Choice(
			"binary",
			message="select binary",
			choices=bins
		))
	bin = bin[:bin.rfind(".")]
	
	# TODO: why do we need a elf, bin pair??????????????????????????????????
	os.system(f"cp {EMU_DIR}/bin/{bin}.bin {EMU_DIR}/{bin}.bin")
	os.system(f"cp {EMU_DIR}/bin/{bin}.elf {EMU_DIR}/{bin}.elf")
	return bin	# binary name


def compile_env() -> str:
	funcs = {
		"pio": compile_pio_env,
		"cmake": compile_cmake_env,
		"precompiled": select_binary
	}
	
	env = prompt(Choice(
		"compile_type",
		message="select compile method",
		choices=list(funcs.keys())
	))
	
	return funcs[env]()


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




# TODO: why do we need a elf, bin pair???
if __name__ == "__main__":
	sys.excepthook = exception_hook

	UI = Emulator_TUI()
	
	# init sequence
	emu = init_config(False, UI)
	env = compile_env()
	code, info = load_binary(env)

	# load code
	print(info)
	input()
	emu.load_code(code, info)
	
	t = Thread(target=UI.tui.run)
	t.start()

	# start emulation
	try:					emu.start()
	except UcError as e:	print(e)
	t.join()
	
	
# TODO: prompting
# TODO: register window (new UI item class (info))
# TODO: hardware window ^
