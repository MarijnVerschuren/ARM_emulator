# TUI includes
from rich import print
# helper includes
from functools import partial
from helpers import *
# general includes
from pymupdf import open, find_tables
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



if __name__ == "__main__":
	sys.excepthook = exception_hook

	configs = os.listdir(f"{EMU_DIR}/configs")
	if not configs: raise ValueError("no emulation config found")
	config = prompt(Choice(
		"emulation_config",
		message="select emulation config",
		choices=["[NEW_CONFIG]"] + configs
	))


	# TODO: use: find_tables