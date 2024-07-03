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
def get_keys(data: CONTAINERS, path: str = "") -> list[tuple[str, str, type]]:
	if type(data) != dict: data = {i: x for i, x in enumerate(data)}
	keys = [(x, path, type(y)) for x, y in data.items()]
	local_keys = keys.copy()
	for key, _, t in local_keys:
		if t not in CONTAINERS: continue
		keys += get_keys(data[key], f"{path}/{key}")
	return keys


# functions
def edit_field(config: dict, field: tuple[str, str, type]) -> dict:  # TODO: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	name, path, type = field
	if type == int:		pass
	elif type == float:	pass
	elif type == bool:	pass
	return config

def add_field(config: dict) -> dict:
	valid =		[("[ROOT]", None, dict)] + [(x, y, z) for x, y, z in get_keys(config) if z in CONTAINERS]
	choices =	[name for name, _, __ in valid]
	print(json.dumps(config, indent=4))
	parent = prompt(List(
		"parent",
		message="select field to edit",
		choices=choices
	))["parent"]
	parent, path, type = valid[choices.index(parent)]

	if type == dict:
		pass  # TODO!!!!!!
	else:
		print("list")
		pass  # TODO<<<<<<<<<<<<<<<

	return config


def new_config() -> None:
	pass  # TODO

def edit_config(config_name: str) -> None:
	with open(f"{EMU_DIR}/configs/{config_name}", "r") as file:
		config = json.load(file)

	while True:
		# clear()  TODO<<<<<<<<<<<<<<<<<<<<<<
		valid = [(x, y, z) for x, y, z in get_keys(config) if z not in CONTAINERS]
		fields = [f"{x}: {z.__name__}" for x, y, z in valid]
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

