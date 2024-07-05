# TUI includes
from rich import print
# general includes
import json

# custom includes
from helpers import *


__all__ = [
	"init_hardware"
]


def init_hardware(cfg: namespace) -> None:
	print(cfg)