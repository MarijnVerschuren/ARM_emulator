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


# helpers
def format_bits(bits: list) -> list:
	prev = None
	return [
		prev := ''.join(list(filter(lambda x: x in set(printable), bit)))
		if bit else prev for bit in bits
	]
def select_dev(config: dict) -> str:
	devices = list(config.keys())
	dev = prompt(Choice(
		"device",
		message="select device",
		choices=["[NEW_DEVICE]"] + devices
	))
	if dev == "[NEW_DEVICE]":
		dev = safe_input("device name: ", str)
	return dev
def select_bit(dev_config: dict, msg: str = "") -> tuple[int, str]:
	offset, reg = prompt(Choice(
		"reg",
		message=f"select {msg} register",
		format_choices=list(dev_config.items()),
		format=lambda x: x[1]["label"]
	))
	bit = prompt(Choice(
		"bit",
		message=f"select {msg} bit (field)",
		choices=[bit for bit in reg["bits"] if bit.lower() != "res."]
	))
	return offset, bit


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
		return None
	def __iadd__(self, other: "Table") -> None:
		if other.header == self.header:
			self.data += other.data
		return self


def load_register_map(doc_path: str) -> dict:
	doc = open_pdf(doc_path)

	page_num =		safe_input("register map page number: ", int)
	page_count =	safe_input("register map page count: ", int)

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
def save_register_map(table: Table, config_path: str) -> None:
	data =	table.data

	rows = {}
	try:
		for index, dat in enumerate(data):
			offset:	int = dat[0]
			value:	str = dat[1]
			bits:	list = dat[1:]
			if value in ["Reserved", "Reset value", "Register name"]: continue
			bits = format_bits(bits)
			print(bits)
			reset = ''.join([x if x else '0' for x in data[index + 1][2:]])
			rows.update({offset: {
				"label": value[value.find("_") + 1:],
				"bits": bits,
				"reset": reset
			}})

	except IndexError: pass

	with open(config_path, "r") as file:
		config = json.load(file)
		file.close()

	dev = select_dev(config)
	config[dev] = rows
	with open(config_path, "w") as file:
		try:
			json.dump(config, file, indent=4)
		except:
			print(config)
		file.close()
def add_emulation_rule(config_path: str) -> None:
	with open(config_path, "r") as file:
		config = json.load(file)
		file.close()

	dev = select_dev(config)
	dev_config = config[dev]
	s_offset, s_bit = select_bit(dev_config, "source")
	trigger = prompt(Choice(
		"trigger",
		message=f"trigger type",
		choices=["read", "write", "setting"]
	))
	if trigger == "setting":	trigger = ("setting", safe_input("trigger setting: ", int))
	t_offset, t_bit = select_bit(dev_config, "target")
	act = prompt(Choice(
		"action",
		message=f"action type",
		choices=["write", "copy"]
	))
	if act == "write":			act = ("write", safe_input(f"set {t_bit} to: ", int))
	else:						act = ("copy", select_bit(dev_config, "copy source"))
	if "actions" not in config[dev][s_offset]:
		config[dev][s_offset]["actions"] = []
	config[dev][s_offset]["actions"].append({
		"source":	dev_config[s_offset]["bits"].index(s_bit),
		"trigger":	trigger,
		"target":	{
			"offset":		t_offset,
			"bit_offset":	dev_config[t_offset]["bits"].index(t_bit)
		},
		"action":	act
	})

	with open(config_path, "w") as file:
		json.dump(config, file, indent=4)
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
		with open(f"{EMU_DIR}/dev_configs/{config_name}.json", "wx") as file:
			file.write("{}")
			file.close()
		config = config_name

	docs = [doc for doc in os.listdir("./doc") if "soft" in doc]
	doc = docs[0] if len(docs) == 1 else prompt(Choice(
		"software_document",
		message="select software document",
		choices=docs
	))

	action = prompt(Choice(
		"action",
		message="select configuration action",
		choices=[
			"load register map",
			"add emulation rule"
		]
	))

	if action == "load register map":
		table = load_register_map(f"./doc/{doc}")
		save_register_map(table, f"{EMU_DIR}/dev_configs/{config}")
	elif action == "add emulation rule":
		add_emulation_rule(f"{EMU_DIR}/dev_configs/{config}")