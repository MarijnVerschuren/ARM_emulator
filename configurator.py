# TUI includes
from rich import print
# helper includes
from functools import partial
from helpers import *
# general includes
import json, sys, os


# partials, lambda's and aliase
dir_name =	os.path.dirname
abs_path =	os.path.abspath
clear = partial(os.system, "clear")

# constants
EMU_DIR = abs_path(dir_name(__file__))
CONTAINERS = [dict, list, tuple]

# Python exception handler
def exception_hook(type, value, traceback) -> None:
	if type == KeyboardInterrupt:
		sys.exit(0)
	else: sys.__excepthook__(type, value, traceback)

# helpers
def pad(msg: str, count: int, char: str = " ") -> str:
	return f"{msg}{char * (count - len(msg))}"

def get_keys(data: CONTAINERS, path: str = "") -> list[tuple[str, str, type]]:
	if not isinstance(data, dict): data = {i: x for i, x in enumerate(data)}
	keys = [(x, path, type(y)) for x, y in data.items()]
	local_keys = keys.copy()
	for key, _, t in local_keys:
		if t not in CONTAINERS: continue
		keys += get_keys(data[key], f"{path}/{key}")
	return keys

def iter_path(config: dict, path: str) -> CONTAINERS:
	if not path: return config
	for p in path.split("/")[1:]:
		config = config[p]
	return config


# inputs
def safe_input(prompt: str, expect: type) -> int | float | bool | str:
	while True:
		try:
			data = input(prompt)
			if expect == int:
				data = data.lower().strip("ul")
				if data.startswith("0x"):	data = int(data, 16)
				elif data.endswith("h"):	data = int(data[:-1], 16)
				elif data.startswith("0o"):	data = int(data, 8)
				else:						data = int(data)
			elif expect == float:			data = float(data)
			elif expect == bool:			data = bool(data)
			return data
		except ValueError as e: pass



# functions
def edit_field(config: dict, field: tuple[str, str, type]) -> dict:
	name, path, type = field
	parent = iter_path(config, path)
	print("current value:")
	if type == int:
		print(f"dec: {parent[name]}", f"hex: {hex(parent[name])}", sep="\n")
		config[name] = safe_input("new value: ", int)
		return config
	print(parent[name])
	config[name] = safe_input("new value: ", type)
	return config

def add_field(config: dict) -> dict:
	valid =		[("[ROOT]", None, dict)] + [(x, y, z) for x, y, z in get_keys(config) if z in CONTAINERS]
	choices =	[f"{path}/{name}" if [x for x, _, __ in valid].count(name) > 1 else name for name, path, __ in valid]
	print(config)
	parent = prompt(Choice(
		"parent",
		message="select parent",
		choices= ["[CANCEL]"] + choices
	))
	if parent == "[CANCEL]": return config
	parent, path, type = valid[choices.index(parent)]

	current = iter_path(config, path)
	if parent != "[ROOT]": current = current[parent]

	if type == dict:
		name = safe_input("field name: ", str)
		add = lambda x: current.update({name: x})
	else: add = current.append

	type = prompt(Choice(
		"type",
		message="select field type",
		choices= ["size"],
		format_choices=[int, float, bool, str, dict, list, tuple],
		format=lambda x: x.__name__
	))

	if type in CONTAINERS: data = type()
	if type == "size":
		field = prompt(Choice(
			"field",
			message="select field as base",
			format_choices=[(x, y, z) for x, y, z in get_keys(config) if z not in CONTAINERS and y == f"{path}/{parent}"],
			format=lambda x: f"{pad(f'{x[1][x[1].rfind(chr(0x2F)) + 1:]}[{x[0]}]:', 20)} {x[2].__name__}"
		))
		base, path, type = field
		if type != int: raise ValueError("base value must be int!")
		data = safe_input("field data: ", int) - iter_path(config, path)[base]
	else: data = safe_input("field data: ", type)

	add(data)

	return config


# TODO: template???
def new_config() -> None:
	config_name = safe_input("config name: ", str)
	with open(f"{EMU_DIR}/configs/{config_name}", "wx") as file:
		json.dump({}, file)
		file.close()
	edit_config(config_name)

def edit_config(config_name: str) -> None:
	with open(f"{EMU_DIR}/configs/{config_name}", "r") as file:
		config = json.load(file)
		file.close()

	while True:
		clear()
		field = prompt(Choice(
			"field",
			message="select field to edit",
			choices=[
				"[SAVE]",
				"[NEW_FIELD]"
			],
			format_choices=[(x, y, z) for x, y, z in get_keys(config) if z not in CONTAINERS],
			format=lambda x: f"{pad(f'{x[1][x[1].rfind(chr(0x2F)) + 1:]}[{x[0]}]:', 20)} {x[2].__name__}"
		))

		try:
			if field == "[SAVE]":		break
			if field == "[NEW_FIELD]":	config = add_field(config); continue
			config = edit_field(config, field)
		except ValueError as e: input(f"{e}\npress_enter to continue...")

	with open(f"{EMU_DIR}/configs/{config_name}", "w") as file:
		json.dump(config, file, indent=4)
		file.close()



if __name__ == "__main__":
	sys.excepthook = exception_hook

	configs = os.listdir(f"{EMU_DIR}/configs")
	if not configs: raise ValueError("no emulation config found")
	config = prompt(Choice(
		"emulation_config",
		message="select emulation config",
		choices=["[NEW_CONFIG]"] + configs
	))

	if config == "[NEW_CONFIG]":	new_config()
	else:							edit_config(config)

# TODO: values on edit screen?
# TODO: edit containers??
# TODO: delete?
