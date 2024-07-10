# TUI includes
from rich import print

# custom includes
from .software import Software


__all__ = [
	"Hardware",
	"Peripheral",
	"Register"
]


# types
class Hardware:
	def __init__(self, emu: Software, memory: dict, device: dict):
		self.emu = emu
		self.mem = memory
		self.devs = []
		for type, data in device.items():
			base_cfg, regs = data
			for label, base in base_cfg.items():
				self.devs.append(Peripheral(emu, type, regs, label, base))

	def reset_peripherals(self):
		for peripheral in self.devs:
			for offset, register in peripheral:
				self.emu.mem_write(
					peripheral.base + int(offset),
					register.reset.to_bytes(4, byteorder="little")
				)
	# hooks
	def memory_read_hook(self, emu, access, address, size, value, user_data):
		for periph in self.devs:
			in_range, offset = periph.offset(address)
			if not in_range: continue
			periph.read(offset)
			break
		else: print(f"read: {access}, {hex(address)}, {size}, {value}")
	def memory_write_hook(self, emu, access, address, size, value, user_data):
		for periph in self.devs:
			in_range, offset = periph.offset(address)
			if not in_range: continue
			periph.write(offset, value)
			break
		else: print(f"write: {access}, {hex(address)}, {size}, {value}")


class Peripheral:
	def __init__(self, emu, type: str, reg_map: dict, label: str, base: int) -> None:
		self.emu = emu
		self.type = type
		self.map = {int(offset): Register(emu, self, int(offset), **reg) for offset, reg in reg_map.items()}
		self.label = label
		self.base = base
		self.map_max = max(map(lambda x: int(x, 16), self.map.keys())) + 4
		self.i = 0

	def offset(self, addr: int) -> tuple[bool, int]:
		offset: int = addr - self.base
		return 0 <= offset < self.map_max, offset
	def read(self, offset: int) -> None:				self.map[offset].read()
	def write(self, offset: int, value: int) -> None:	self.map[offset].write(value)

	def __getitem__(self, offset: int) -> "Register":	return self.map[offset]
	def __iter__(self) -> "Peripheral":					self.i = 0; return self
	def __next__(self) -> tuple:
		try:
			data = list(self.map.items())[self.i]
			self.i += 1; return data
		except IndexError: raise StopIteration
	def __str__(self) -> str:	return f"<{self.label}@{self.base}, {self.map}>"
	def __repr__(self) -> str:	return f"<{self.label}@{self.base}>"


class Register:
	def __init__(self, emu, parent: Peripheral, offset: int, label: str, bits: list[str], reset: int, actions: dict = None) -> None:
		self.emu = emu
		self.parent = parent
		self.offset = offset
		self.label = label
		self.bits = bits
		self.reset = reset
		self.actions = actions

	def __str__(self) -> str:	return f"<{self.label}, {self.bits}, {self.reset}>"
	def __repr__(self) -> str:	return f"<{self.label}>"

	def action(self, action: dict) -> None:
		dst = action["target"]
		d_ptr = self.parent.base + dst["offset"]
		for act, dat in action["action"].items():
			if act == "copy":
				c_ptr = self.parent.base + dat["offset"]
				data = int.from_bytes(self.emu.mem_read(c_ptr, 4), byteorder="little")
				dat = (data >> dat["bit_offset"]) & ((2 ** dat["count"]) - 1)
			dat = (dat & ((2 ** dst["count"]) - 1)) << dst["bit_offset"]
			input(f"{hex(dat)}, {hex(d_ptr)}")
			self.emu.mem_write(d_ptr, dat.to_bytes(4, byteorder="little"))
	def read(self) -> None:
		val = int.from_bytes(self.emu.mem_read(self.parent.base + self.offset, 4), "little")
		print(f"read {val} from {self.parent.label}->{self.label}")
		if not self.actions: return
		for action in self.actions:
			if action["trigger"] != "read": continue
			self.action(action)
	def write(self, val: int) -> None:
		self.emu.mem_write(self.parent.base + self.offset, val.to_bytes(4, byteorder="little"))
		print(f"wrote {val} to {self.parent.label}->{self.label}")
		if not self.actions: return
		for action in self.actions:
			if action["trigger"] != "write": continue
			src = action["source"]
			val &= ((2 ** src["count"]) - 1) << src["bit_offset"]
			if not val and not ("setting" in action and (val >> src["bit_offset"]) == action["setting"]): continue
			self.action(action)
