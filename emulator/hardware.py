# TUI includes
from crc import Register
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
			for _, register in peripheral:
				register.update()
	def find_register(self, label: str, offset: int) -> Register:
		for periph in self.devs:
			if periph.label != label: continue
			return periph[offset]

	# hooks
	def memory_read_hook(self, emu, access, address, size, value, user_data):
		value = int.from_bytes(emu.mem_read(address, size), "little")
		for periph in self.devs:
			in_range, offset = periph.offset(address)
			if not in_range: continue
			periph.read(offset, value)
			break
		else: print(f"read {hex(value)} from {hex(address)}, size: {size}, access:{access}")
	def memory_write_hook(self, emu, access, address, size, value, user_data):
		emu.mem_write(address, value.to_bytes(size, byteorder="little"))
		for periph in self.devs:
			in_range, offset = periph.offset(address)
			if not in_range: continue
			periph.write(offset, value)
			break
		else: print(f"write {hex(value)} to {hex(address)}, size: {size}, access:{access}")


class Peripheral:
	def __init__(self, emu, type: str, reg_map: dict, label: str, base: int) -> None:
		self.emu = emu
		self.type = type
		self.map = {int(offset): Register(emu, self, int(offset), **reg) for offset, reg in reg_map.items()}
		self.label = label
		self.base = base
		self.map_max = max(self.map.keys()) + 4
		self.i = 0

	def offset(self, addr: int) -> tuple[bool, int]:
		offset: int = addr - self.base
		return 0 <= offset < self.map_max, offset
	def read(self, offset: int, value: int) -> None:	self.map[offset].read(value)
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

		self.ptr = parent.base + offset
		self.value = reset

	def __str__(self) -> str:	return f"<{self.label}, {self.bits}, {self.reset}>"
	def __repr__(self) -> str:	return f"<{self.label}>"

	def update(self) -> None:
		self.emu.memory.write(self.ptr, self.value.to_bytes(4, byteorder="little"))

	def action(self, action: dict) -> None:
		dst = action["target"]
		d_ptr = self.parent.base + dst["offset"]
		for act, dat in action["action"].items():
			if act == "copy":
				c_ptr = self.parent.base + dat["offset"]
				data = int.from_bytes(self.emu.mem_read(c_ptr, 4), byteorder="little")
				dat = (data >> dat["bit_offset"]) & ((2 ** dat["count"]) - 1)
			cval = int.from_bytes(self.emu.mem_read(d_ptr, 4), byteorder="little")
			mask = ((2 ** dst["count"]) - 1); pos = dst["bit_offset"]
			cval &= ~(mask << pos)
			cval |= (dat & mask) << pos
			print(f"act: {act}, res: {hex(cval)}, ptr: {hex(d_ptr)}, regs: {self.emu.read_regs()}")
			if cval == 0xb3005: self.emu.single_step = True
			self.emu.mem_write(d_ptr, cval.to_bytes(4, byteorder="little"))
			# Write to self cannot be done because output is overwritten by code!!!!!!!
			# NEW system: cache the output and write it on read
	def read(self, value: int) -> None:
		self.update()
		print(f"read {hex(value)} from {self.parent.label}->{self.label}, regs: {self.emu.read_regs()}")
		if not self.actions: return
		for action in self.actions:
			if action["trigger"] != "read": continue
			self.action(action)
	def write(self, value: int) -> None:
		print(f"wrote {hex(value)} to {self.parent.label}->{self.label}, regs: {self.emu.read_regs()}")
		if not self.actions: return
		for action in self.actions:
			if action["trigger"] != "write": continue
			src = action["source"]
			val = value & ((2 ** src["count"]) - 1) << src["bit_offset"]
			if not val and not ("setting" in action and (val >> src["bit_offset"]) == action["setting"]): continue
			self.action(action)
