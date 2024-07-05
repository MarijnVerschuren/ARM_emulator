# TUI includes
from inquirer import List, Checkbox, prompt as _prompt
from rich import print
# helper includes
from functools import partial
# general includes
import json, sys, os


# partials, lambda's and aliases
prompt = lambda x: _prompt([x,], raise_keyboard_interrupt=True)
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
	choices =	[name for name, _, __ in valid]
	print(config)
	parent = prompt(List(
		"parent",
		message="select field to edit",
		choices= ["[CANCEL]"] + choices
	))["parent"]
	if parent == "[CANCEL]": return config
	parent, path, type = valid[choices.index(parent)]

	current = iter_path(config, path)
	if parent != "[ROOT]": current = current[parent]

	if type == dict:
		name = safe_input("field name: ", str)
		add = lambda x: current.update({name: x})
	else: add = current.append

	choices =	[int, float, bool, str, dict, list, tuple]
	formatted =	[c.__name__ for c in choices]
	type = prompt(List(
		"type",
		message="select field type",
		choices=formatted
	))["type"]
	type = choices[formatted.index(type)]

	if type in CONTAINERS:	data = type()
	else:					data = safe_input("field data: ", type)

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
		valid = [(x, y, z) for x, y, z in get_keys(config) if z not in CONTAINERS]
		fields = [f"{pad(f'{y[y.rfind(chr(0x2F)) + 1:]}[{x}]:', 20)} {z.__name__}" for x, y, z in valid]
		field = prompt(List(
			"field",
			message="select field to edit",
			choices=[
				"[SAVE]",
				"[NEW_FIELD]",
				*fields
			]
		))["field"]

		if field == "[SAVE]":		break
		if field == "[NEW_FIELD]":	config = add_field(config); continue
		field = valid[fields.index(field)]
		config = edit_field(config, field)

	with open(f"{EMU_DIR}/configs/{config_name}", "w") as file:
		json.dump(config, file, indent=4)
		file.close()



if __name__ == "__main__":
	sys.excepthook = exception_hook

	configs = os.listdir(f"{EMU_DIR}/configs")
	if not configs: raise ValueError("no emulation config found")
	config = configs[0] if len(configs) <= 1 else \
		prompt(List(
			"emulation_config",
			message="select emulation config",
			choices=["[NEW_CONFIG]"] + configs
		))["emulation_config"]

	if config == "[NEW_CONFIG]":	new_config()
	else:							edit_config(config)

# TODO: values on edit screen?
# TODO: edit containers??
