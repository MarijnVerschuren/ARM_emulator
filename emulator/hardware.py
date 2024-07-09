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
	def __init__(self, emu, type: str, reg_map: dict, label: str, base: int) -> None:
		self.emu = emu
		self.type = type
		self.map = {offset: Register(emu, self, int(offset), **reg) for offset, reg in reg_map.items()}
		self.label = label
		self.base = base
		self.map_max = max(map(lambda x: int(x, 16), self.map.keys())) + 4
		self.i = 0

	def offset(self, addr: int) -> tuple[bool, int]:
		offset: int = addr - self.base
		return 0 <= offset < self.map_max, offset

	def read(self, offset: int) -> None:
		self.map[str(offset)].read()

	def write(self, offset: int, value: int) -> None:
		self.map[str(offset)].write(value)

	def __getitem__(self, offset: int) -> Register:
		return self.map[str(offset)]

	def __iter__(self) -> "Peripheral":
		self.i = 0; return self

	def __next__(self) -> tuple:
		try:
			data = list(self.map.items())[self.i]
			self.i += 1;
			return data
		except IndexError:
			raise StopIteration

	def __str__(self) -> str:
		return f"<{self.label}@{self.base}, {self.map}>"

	def __repr__(self) -> str:
		return f"<{self.label}@{self.base}>"


class Register:
	def __init__(self, emu, parent: Peripheral, offset: int, label: str, bits: list[str], reset: int,
				 actions: dict = None) -> None:
		self.emu = emu
		self.parent = parent
		self.offset = offset
		self.label = label
		self.bits = bits
		self.reset = reset
		self.actions = actions

	def __str__(self) -> str:
		return f"<{self.label}, {self.bits}, {self.reset}>"

	def __repr__(self) -> str:
		return f"<{self.label}>"

	def action(self, action: dict) -> None:
		dst = action["target"]
		d_ptr = self.parent.base + dst["offset"]
		for act, dat in action["action"].items():
			if act == "copy":
				# TODO: inter periph copy
				c_ptr = self.parent.base + dat["offset"]
				data = int.from_bytes(self.emu.mem_read(c_ptr, 4), byteorder="little")
				dat = (data >> dat["bit_offset"]) & ((2 ** dat["count"]) - 1)
			dat = (dat & ((2 ** dst["count"]) - 1)) << dst["bit_offset"]
			input(f"{hex(dat)}, {hex(d_ptr)}")
			self.emu.mem_write(d_ptr, dat.to_bytes(4, byteorder="little"))

	def read(self) -> None:
		print(f"read {self.parent.label}->{self.label}")
		if not self.actions: return
		for action in self.actions:
			if action["trigger"] != "read": continue
			self.action(action)

	def write(self, val: int) -> None:
		self.emu.mem_write(self.parent.base + self.offset, val.to_bytes(4, byteorder="little"))
		print(f"write {self.parent.label}->{self.label} with {val}")
		if not self.actions: return
		for action in self.actions:
			if action["trigger"] != "write": continue
			src = action["source"]
			s_mask = ((2 ** src["count"]) - 1) << src["bit_offset"]
			if "setting" in action:
				if ((val & s_mask) >> src["bit_offset"]) == action["setting"]:
					self.action(action)
			elif val & s_mask:
				self.action(action)


# init
def load_hardware_config(emu, cfg: dict) -> list[Peripheral]:
	peripherals = []
	for type, data in cfg.items():
		base_cfg, regs = data
		for label, base in base_cfg.items():
			peripherals.append(Peripheral(emu, type, regs, label, base))
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
		periph.read(offset);
		break
	else:
		print(f"read: {access}, {hex(address)}, {size}, {value}")


def memory_write_hook(emu, access, address, size, value, user_data):
	peripherals: list[Peripheral] = user_data.dut.hardware
	for periph in peripherals:
		in_range, offset = periph.offset(address)
		if not in_range: continue
		periph.write(offset, value);
		break
	else:
		print(f"write: {access}, {hex(address)}, {size}, {value}")


def code_hook(emu, address, size, user_data):
	f_address = 0;
	f_name = ""
	for f_address, s, f_name in user_data.info.functions[::-1]:
		if f_address < address: break
	opcode = emu.mem_read(address, size)
	mnemonics = user_data.asm.disasm(opcode, address)
	for i in mnemonics:
		print(f"{hex(i.address)} ({f_name} + {hex(address - f_address)}): {i.mnemonic}\t{i.op_str}")


def interrupt_hook(emu, address, size, user_data):
	print("interrupt")

# TODO use config