# TUI includes
from rich import print
# helper includes
from functools import partial
from helpers import *
from tabulate import tabulate
from string import printable
# general includes
from pymupdf import open as open_pdf, Page
import json, sys, os

# custom includes
from helpers import *
from emulator import *


# partials, lambda's and aliase
dir_name =	os.path.dirname
abs_path =	os.path.abspath
clear = partial(os.system, "clear")


# constants
EMU_DIR = abs_path(dir_name(__file__))


# Python exception handler
def exception_hook(type, value, traceback) -> None:
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)


# types
class Table:
	def __init__(self, header, data) -> None:
		self.header = header
		self.data = data

	def __str__(self) -> str:	return tabulate(self.data, headers=self.header, tablefmt='orgtbl')
	def __repr__(self) -> str:	return str(self.header)

	def __add__(self, other: "Table") -> "Table" or None:
		if other.header == self.header:
			data = self.data + other.data
			return Table(self.header, data)
	def __iadd__(self, other: "Table") -> "Table":
		if other.header == self.header:
			self.data += other.data
		return self

def load_register_map(doc_path: str) -> Table:
	doc = open_pdf(doc_path)
	page_num =		safe_input("register map page number: ",	int)
	page_count =	safe_input("register map page count: ",	int)
	segments = []
	for i in range(-1, page_count - 1, 1):
		page: Page = doc[page_num + i]
		tabs = page.find_tables()
		for tab in tabs:
			data = tab.extract()
			if not data: continue
			tab = Table(data[0], data[0:])
			segments.append(tab)
	res = None
	if len(segments) > 1:
		res = segments[0]
		for i, segment in enumerate(segments[0:]):
			res += segment
	else: res = segments[0]
	return res


class Software:
	def __init__(self, config: dict, hardware: str) -> None:
		self.config = config
		self.hardware_orig = hardware
		with open(f"{EMU_DIR}/dev_configs/{hardware}", "w") as file:
			self.hardware = load(file)
			file.close()

	def __dict__(self) -> dict:	return {"config": self.config, "hardware": self.hardware_orig}

class Hardware:
	def __init__(self, memory: dict, device: dict) -> None:
		self.memory = memory
		self.device_orig = device
		self.device = []
		for type, data in device.items():
			base_cfg, regs = data
			self.device.append(Peripheral(type, regs, base_cfg))

	def __dict__(self) -> dict: return {"memory": self.memory, "device": self.device}

class Peripheral:
	def __init__(self, type: str, base_cfg: dict, regs: dict) -> None:
		self.type = type
		self.map = {int(offset): Register(int(offset), **reg) for offset, reg in regs.items()}
		self.base_cfg = base_cfg

	def __dict__(self) -> dict: return {"type": self.type, "base_cfg": self.base_cfg, "regs": self.map}


class Register:
	def __init__(self, offset: int, label: str, bits: list[str], reset: int, triggers: list["Trigger"] = None) -> None:
		self.offset = offset
		self.label = label
		self.bits = bits
		self.reset = reset
		self.triggers = triggers or []

	def __dict__(self) -> dict:
		return {"offset": self.offset, "label": self.label, "bits": self.bits, "reset": self.reset} |\
			   ({"triggers": self.triggers} if self.triggers else {})

class Trigger:
	def __init__(self, actions: list["Action"], src: None or tuple[int, int, int or None] = None):
		# write if src, else read
		self.actions = actions
		self.src = src		# bit, count, setting or any

	def __dict__(self) -> dict: return {"actions": self.actions} | ({"src": self.src} if self.src else {})

class Action:
	def __init__(self, src: int or tuple[str, int, int, int], dst: tuple[str, int, int, int]):
		# write if type(src) == int, else copy src
		self.src = src		# peripheral, offset, bit, count
		self.dst = dst		# peripheral, offset, bit, count

	def __dict__(self) -> dict: return {"src": self.src, "dst": self.dst}

# en/decoders
class encoder(json.JSONEncoder):
	def default(self, obj: object) -> dict:
		try:	return dict(obj)
		except:	return super().default(obj)


class decoder(json.JSONDecoder):
	def __init__(self, *args, **kwargs):
		self.orig_obj_hook =	kwargs.pop("object_hook", None)
		super(self.__class__, self).__init__(*args, object_hook=self.default, **kwargs)

	def default(self, data: dict) -> object:
		try:	return Software(**data)
		except:	pass
		try:	return Hardware(**data)
		except: pass
		try:	return Peripheral(**data)
		except:	pass
		try:	return Register(**data)
		except: pass
		try:	return Trigger(**data)
		except: pass
		try:	return Action(**data)
		except:	pass
		return data


# partials
dump = partial(json.dump, cls=encoder)
load = partial(json.load, cls=decoder)
dumps = partial(json.dumps, cls=encoder)
loads = partial(json.loads, cls=decoder)


# helpers
def pad(msg: str, until: int, char: str = " ") -> str: return f"{msg}{char * (until - len(msg))}"
def format_bits(bits: list) -> list:
	prev = None
	return [
		prev := ''.join(list(filter(lambda x: x in set(printable), bit)))
		if bit else prev for bit in bits
	][::-1]
def select_dev(config: dict) -> str:
	dev = prompt(Choice(
		"device",
		message="select device",
		choices=["[NEW_DEVICE]"] + list(config.keys())  # TODO <<<<<<<<<<<<<<<<<<<<<<<<<<<<
	))
	if dev == "[NEW_DEVICE]":
		dev = safe_input("device name: ", str)
	return dev
def select_bit(registers: list[Register], msg: str = "", show_reset: bool = False) -> tuple[Register, str]:
	register = prompt(Choice(
		"reg",
		message=f"select {msg} register",
		format_choices=registers,
		format=lambda x: x.label
	))

	format = lambda x: x
	def srf(bit: str) -> str:
		if bit == srf.prev:	srf.count += 1
		else:				srf.count = 0
		srf.prev = bit; offset = register.bits.index(bit) + srf.count
		return f"{pad(bit, 20)}{(register.reset >> offset) & ((2 ^ srf.count) - 1)}"
	srf.prev = None; srf.count = 0
	if show_reset: format = srf

	bit = prompt(Choice(
		"bit",
		message=f"select {msg} bit (field)",
		format_choices=[bit for bit in register.bits if bit.lower() != "res."],
		format=format
	))
	return register, bit


# functions
def get_base_cfg(dev_name: str) -> dict:
	base_cfg = {}
	cfg_count =	safe_input("device count: ", int)
	for i in range(cfg_count):
		name = f"{dev_name}{f'_{i + 1}' if cfg_count > 1 else ''}"
		base_cfg[name] = safe_input(f"base for {name}: ", int)
	return base_cfg
def save_register_map(table: Table, config_path: str) -> None:
	data =	table.data
	regs = []
	for index, dat in enumerate(data):
		try:
			offset:	int = int(dat[0], 16)
			value:	str = dat[1]
			bits:	list = dat[2:]
			if value in ["Reserved", "Reset value", "Register name"]: continue
			bits = format_bits(bits)
			reset = int(''.join([x if x == '1' else '0' for x in data[index + 1][2:]]), 2)
			regs.append(Register(offset, value, bits, reset))
		except Exception as e: pass
	with open(config_path, "r") as file:
		config = load(file)
		file.close()
	dev = select_dev(config.device)
	config.device[dev] = [get_base_cfg(dev), regs]
	with open(config_path, "w") as file:
		try:	dump(config, file, indent=4)
		except Exception as e:	print(e, config)
		file.close()
def set_default_value(config_path: str) -> None:
	with open(config_path, "r") as file:
		config = load(file)
		file.close()
	_, dev_config = config.device[select_dev(config.device)]
	reg, bit = select_bit(dev_config, "source", True)
	count = reg.bits.count(bit)
	offset = reg.bits.index(bit)

	mask = (2 ** count) - 1
	reg.reset = (
		(reg.reset & ~(mask << offset)) |
		((safe_input("new value: ", int) & mask) << offset)
	)

	with open(config_path, "w") as file:
		dump(config, file, indent=4)
		file.close()
def add_emulation_rule(config_path: str) -> None:
	with open(config_path, "r") as file:
		config = load(file)
		file.close()
	_, dev_config = config.device[select_dev(config.device)]
	s_reg, s_bit = select_bit(dev_config, "source")
	trigger = prompt(Choice(
		"trigger",
		message=f"trigger type",
		choices=["read", "write", "setting"]
	))

	trigger_src = None
	setting = None
	if trigger == "setting":
		setting = safe_input("trigger setting: ", int)
	if trigger != "read":
		offset =	s_reg.bits.index(s_bit)
		count =		s_reg.bits.count(s_bit)
		trigger_src = (offset, count, setting)	# ARG1

	actions = []
	while True:
		act = prompt(Choice(
			"action",
			message=f"action type",
			choices=["write", "copy"]
		))
		t_dev = select_dev(config.device)
		_, t_dev_cfg = config.device[t_dev]
		t_reg, t_bit = select_bit(t_dev_cfg, "target")
		offset =	t_reg.bits.index(t_bit)
		count =		t_reg.bits.count(t_bit)
		t_act_dst = (t_dev, t_dev_cfg.index(t_reg), offset, count)
		if act == "copy":
			c_dev = select_dev(config.device)
			_, c_dev_cfg = config.device[c_dev]
			c_reg, c_bit = select_bit(c_dev_cfg, "copy source")
			offset =	c_reg.bits.index(c_bit)
			count =		c_reg.bits.count(c_bit)
			t_act_src = (c_dev, c_dev_cfg.index(c_reg), offset, count)
		else:
			t_act_src = safe_input(f"set {t_bit} to: ", int)
		actions.append(Action(t_act_src, t_act_dst))
		break  # TODO: loop for more actions on trigger
	trigger = Trigger(actions, trigger_src)
	s_reg.triggers.append(trigger)

	with open(config_path, "w") as file:
		dump(config, file, indent=4)
		file.close()


if __name__ == "__main__":
	sys.excepthook = exception_hook

	configs = os.listdir(f"{EMU_DIR}/dev_configs")
	config = prompt(Choice(
		"dev_config",
		message="select device config",
		choices=["[NEW_CONFIG]"] + configs
	))

	if config == "[NEW_CONFIG]":
		config_name = safe_input("dev config name: ", str)
		with open(f"{EMU_DIR}/dev_configs/{config_name}.json", "w") as file:
			dump({"memory": {}, "device": {}}, file, indent=4)
			file.close()
		config = config_name

	action = prompt(Choice(
		"action",
		message="select configuration action",
		choices=[
			"load register map",
			"set default value",
			"add emulation rule"
		]
	))

	if action == "load register map":
		docs = [doc for doc in os.listdir(f"{EMU_DIR}/doc/src") if "soft" in doc]
		doc = docs[0] if len(docs) == 1 else prompt(Choice(
			"software_document",
			message="select software document",
			choices=docs
		))
		table = load_register_map(f"{EMU_DIR}/doc/src/{doc}")
		save_register_map(table, f"{EMU_DIR}/dev_configs/{config}")
	elif action == "set default value":
		set_default_value(f"{EMU_DIR}/dev_configs/{config}")
	elif action == "add emulation rule":
		add_emulation_rule(f"{EMU_DIR}/dev_configs/{config}")
