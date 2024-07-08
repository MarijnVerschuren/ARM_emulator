# TUI includes
from rich import print
# general includes
import json

# custom includes
from helpers import *


__all__ = [
	"init_hardware",
	"memory_invalid_hook",
	"memory_read_hook",
	"memory_write_hook",
	"code_hook",
	"interrupt_hook"
]


# types
class Peripheral:
	def __init__(self, type: str, map: dict, label: str, base: int) -> None:
		self.type =		type
		self.map = 		{offset: Register(*reg) for offset, reg in map.items()}
		self.label =	label
		self.base =		base

	def __str__(self) -> str:	return f"<{self.label}@{self.base}, {self.map}>"
	def __repr__(self) -> str:	return f"<{self.label}@{self.base}>"


class Register:
	def __init__(self, label: str, bits: list[str], reset: int) -> None:
		self.label =	label
		self.bits =		bits
		self.reset =	reset

	def __str__(self) -> str:	return f"<{self.label}, {self.bits}, {self.reset}>"
	def __repr__(self) -> str:	return f"<{self.label}>"


def init_hardware(cfg: dict) -> list[Peripheral]:
	peripherals = []
	for type, data in cfg.items():
		base_cfg, regs = data
		for label, base in base_cfg.items():
			peripherals.append(Peripheral(type, regs, label, base))
	return peripherals



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
	for f_address, s, f_name in user_data.info.functions[::-1]:
		if f_address < address: break
	opcode = emu.mem_read(address, size)
	mnemonics = user_data.asm.disasm(opcode, address)
	for i in mnemonics:
		print(f"{hex(i.address)} ({f_name} + {hex(address - f_address)}): {i.mnemonic}\t{i.op_str}")

def interrupt_hook(emu, address, size, user_data):
	print("interrupt")


# TODO use config