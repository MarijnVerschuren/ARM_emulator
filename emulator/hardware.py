# TUI includes
from crc import Register
from rich import print
# general includes
import json

# custom includes
from helpers import *


__all__ = [
	"Peripheral",
	"Register",
	"load_hardware_config",
	"init_hardware",

	"memory_invalid_hook",
	"memory_read_hook",
	"memory_write_hook",
	"code_hook",
	"interrupt_hook"
]


# types
class Peripheral:
	def __init__(self, type: str, reg_map: dict, label: str, base: int) -> None:
		self.type =		type
		self.map = 		{offset: Register(self, **reg) for offset, reg in reg_map.items()}
		self.label =	label
		self.base =		base
		self.map_max =	max(map(lambda x: int(x, 16), self.map.keys())) + 4
		self.i = 0

	def offset(self, addr: int) -> tuple[bool, int]:
		offset: int = addr - self.base
		return 0 <= offset < self.map_max, offset
	def read(self, offset: int) -> None:				self.map[str(offset)].read()
	def write(self, offset: int, value: int) -> None:	self.map[str(offset)].write(value)

	def __getitem__(self, offset: int) -> Register:		return self.map[str(offset)]
	def __iter__(self) -> "Peripheral":					self.i = 0; return self
	def __next__(self) -> tuple:
		try:
			data = list(self.map.items())[self.i]
			self.i += 1; return data
		except IndexError: raise StopIteration

	def __str__(self) -> str:	return f"<{self.label}@{self.base}, {self.map}>"
	def __repr__(self) -> str:	return f"<{self.label}@{self.base}>"


class Register:
	def __init__(self, parent: Peripheral, label: str, bits: list[str], reset: int, actions: dict = None) -> None:
		self.parent =	parent
		self.label =	label
		self.bits =		bits
		self.reset =	reset
		self.actions =	actions

	def __str__(self) -> str:	return f"<{self.label}, {self.bits}, {self.reset}>"
	def __repr__(self) -> str:	return f"<{self.label}>"

	def read(self) -> None:
		print(f"read {self.parent.label}->{self.label}")

	def write(self, val: int) -> None:
		print(f"write {self.parent.label}->{self.label} with {val}")



# init
def load_hardware_config(cfg: dict) -> list[Peripheral]:
	peripherals = []
	for type, data in cfg.items():
		base_cfg, regs = data
		for label, base in base_cfg.items():
			peripherals.append(Peripheral(type, regs, label, base))
	return peripherals

def init_hardware(emu, hardware: list[Peripheral]) -> None:
	for peripheral in hardware:
		for offset, register in peripheral:
			emu.mem_write(peripheral.base + int(offset), register.reset.to_bytes(4, byteorder="little"))



# emulation hooks
def memory_invalid_hook(emu, access, address, size, value, user_data):
	print(f"invalid: {access}, {hex(address)}, {size}, {value}: {hex(value)}")
	return False

def memory_read_hook(emu, access, address, size, value, user_data):
	peripherals: list[Peripheral] = user_data.dut.hardware
	for periph in peripherals:
		in_range, offset = periph.offset(address)
		if not in_range: continue
		print(f"read {value} from {hex(access)} -> {hex(address)}, {offset}")
		periph.read(offset); break
	else: print(f"read: {access}, {hex(address)}, {size}, {value}")

def memory_write_hook(emu, access, address, size, value, user_data):
	peripherals: list[Peripheral] = user_data.dut.hardware
	for periph in peripherals:
		in_range, offset = periph.offset(address)
		if not in_range: continue
		print(f"write {value} to {hex(access)} -> {hex(address)}, {offset}")
		periph.write(offset, value); break
	else: print(f"write: {access}, {hex(address)}, {size}, {value}")

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