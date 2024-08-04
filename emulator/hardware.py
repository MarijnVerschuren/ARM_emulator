# includes
from threading import Thread
import time

# TUI includes
from functools import cache
from typing import Iterator
from rich import print

# custom includes
from .software import Software


__all__ = [
	"Hardware",
	"Peripheral",
	"Register",
	"Trigger",
	"Action"
]



# peripheral types
class Hardware_Thread(Thread):
	def __init__(self, dev: "Peripheral", num: int = None) -> None:
		super(Hardware_Thread, self).__init__(target=self.func, name=f"{self.__class__.__name__}{num or ''}", daemon=False)
		self.dev = dev
		self.start()

	def func(self) -> None: pass


class SysTick(Hardware_Thread):
	CTRL =	0x00; LOAD =	0x04
	VAL =	0x08; CALIB =	0x0C
	def __init__(self, dev: "Peripheral") -> None:
		super(SysTick, self).__init__(dev)

	@property
	def kernel(self) -> int:	return self.dev.emu.step.value
	@property
	def accel(self) -> int:		return self.dev.emu.hardware_accel
	@property
	def ctrl(self) -> tuple[int, int, int]:
		val = self.dev[self.CTRL].data.value
		return (
			(val << 0) & 0b1,
			(val << 1) & 0b1,
			(val << 2) & 0b1,
		)
	@property
	def load(self) -> int:		return self.dev[self.LOAD].data.value
	@property
	def val(self) -> int:		return self.dev[self.VAL].data.value
	@property
	def calib(self) -> int:		return self.dev[self.CALIB].data.value

	def func(self) -> None:
		last_check = self.kernel
		last_tick = 0
		while True:
			if last_check == self.kernel:			continue
			last_check = self.kernel
			en, ie, src = self.ctrl
			if not en:								continue
			ticks = int((self.load - 1) * 2000 * (8 - (7 * src)) / self.accel)
			print("SYSTICK | t, thresh: ", self.kernel - last_tick, ticks)
			if self.kernel - last_tick <= ticks:	continue
			last_tick = self.kernel
			print("SYSTICKed")
			if not ie:								continue
			# TODO: call interrupt, how??



def get_thread(dev: "Peripheral") -> Hardware_Thread or None:
	match dev.type:
		case "SysTick":	return SysTick(dev)
		case _:			return None



# types
class Hardware:
	def __init__(self, emu: Software, memory: dict, device: list["Peripheral"]) -> None:
		self.emu = emu
		self.mem = memory
		self.dev = device

	# getters
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], mem: {self.mem}, dev: {self.dev}>"
	def __repr__(self) -> str:	return f"<[{self.__class__.__name__}], {self.mem}, {self.dev}>"

	# control
	def reset_peripherals(self):
		for peripheral in self.dev:
			for register in peripheral:
				register.update()
	def find_register(self, peripheral: str, offset: int) -> "Register":
		for periph in self.dev:
			if periph.label != peripheral: continue
			return periph[offset]

	# hooks
	def memory_read_hook(self, emu, access, address, size, value, user_data):
		value = int.from_bytes(emu.mem_read(address, size), "little")
		for periph in self.dev:
			in_range, offset = periph.offset(address)
			if not in_range: continue
			periph.read(offset, value)
			break
		else: print(f"read {hex(value)} from {hex(address)}, size: {size}, access:{access}")
	def memory_write_hook(self, emu, access, address, size, value, user_data):
		emu.mem_write(address, value.to_bytes(size, byteorder="little"))
		for periph in self.dev:
			in_range, offset = periph.offset(address)
			if not in_range: continue
			periph.write(offset, value)
			break
		else: print(f"write {hex(value)} to {hex(address)}, size: {size}, access:{access}")


class Peripheral:
	def __init__(self, emu, type: str, regs: list["Register"], label: str, base: int) -> None:
		self.emu =		emu
		self.type =		type
		self.regs =		regs
		self.label =	label
		self.base =		base
		self.thread =	get_thread(self)
		self.i = 0

	# getters
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], type: {self.type}, label: {self.label}, base: {self.base}, regs: {self.regs}>"
	def __repr__(self) -> str:	return f"<[{self.__class__.__name__}], {self.type}, {self.label}, {self.base}, {self.regs}>"

	@property
	@cache
	def map_max(self) -> int: return max(self.regs, key=lambda x: x.offset).offset + 4
	def offset(self, addr: int) -> tuple[bool, int]:
		offset: int = addr - self.base
		return 0 <= offset < self.map_max, offset
	def __getitem__(self, offset: int) -> "Register":
		for reg in self.regs:
			if reg.offset == offset: return reg
	def __iter__(self) -> Iterator["Register"]:
		return iter(self.regs)

	# control
	def read(self, offset: int, value: int) -> None:	self[offset].read(value)
	def write(self, offset: int, value: int) -> None:	self[offset].write(value)


class Register:
	def __init__(self, emu, parent: Peripheral, offset: int, label: str, bits: list[str], reset: int, triggers: list["Trigger"] = None) -> None:
		self.emu = emu
		self.parent = parent
		self.offset = offset
		self.label = label
		self.bits = bits
		self.reset = reset
		self.triggers = triggers

		self.ptr = parent.base + offset
		self.data = self.emu.manager.Value(f"{self.label}@{self.offset}->value", reset)

	# getters
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], offset: {self.offset}, label: {self.label}, bits: {self.bits}, reset: {self.reset}, triggers: {self.triggers}>"
	def __repr__(self) -> str:	return f"<[{self.__class__.__name__}], {self.offset}, {self.label}, {self.reset}, {self.triggers}>"

	# control
	def update(self) -> None:
		self.emu.mem_write(self.ptr, self.data.value.to_bytes(4, byteorder="little"))

	def read(self, value: int) -> None:
		self.update()
		print(f"read {hex(value)} from {self.parent.label}->{self.label}, regs: {self.emu.regs}")
		for trigger in self.triggers: trigger.read_hook(self)

	def write(self, value: int) -> None:
		self.data.value = value
		print(f"wrote {hex(value)} to {self.parent.label}->{self.label}, regs: {self.emu.regs}")
		for trigger in self.triggers: trigger.write_hook(self, value)


class Trigger:
	def __init__(self, emu, actions: list["Action"], src: None or tuple[int, int, int or None] = None):
		# write if src, else read
		self.emu =		emu
		self.actions =	actions
		self.src =		src		# bit, count, setting or any

	# getters
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], type: {self.type}, src: {self.src}, actions: {self.actions}>"
	def __repr__(self) -> str:	return f"<[{self.__class__.__name__}], {self.type}, {self.src}, {self.actions}>"
	@property
	def type(self) -> str:		return ("write " + ("setting" if self.src[2] else "any")) if self.src else "read"

	# control
	def __call__(self, *args, **kwargs) -> None:
		for action in self.actions: action()

	def read_hook(self, reg: Register) -> None:
		if not self.src: self()

	def write_hook(self, reg: Register, value: int) -> None:
		if not self.src:				return
		o, c, s = self.src
		msk = ((2 ** c) - 1) << o
		dat = value & msk
		if not dat:						return
		if s and not ((dat >> o) == s):	return
		self()


class Action:
	def __init__(self, emu, src: int or tuple[str, int, int, int], dst: tuple[str, int, int, int]):
		# write if type(src) == int, else copy src
		self.emu = emu
		self.src = src		# peripheral, offset, bit, count
		self.dst = dst		# peripheral, offset, bit, count

	# getters
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], type: {self.type}, src: {self.src}, dst: {self.dst}>"
	def __repr__(self) -> str:	return f"<[{self.__class__.__name__}], {self.type}, {self.src}, {self.dst}>"
	@property
	def type(self) -> str:		return "write" if isinstance(self.src, int) else "copy"

	# control
	def __call__(self, *args, **kwargs) -> None:
		d_reg = self.emu.hardware.find_register(*self.dst[:2])
		do, dc = self.dst[2:]; d_msk = ((2 ** dc) - 1) << do
		d_reg.data.value &= ~d_msk
		if isinstance(self.src, int): d_reg.data.value |= self.src << do; return
		s_reg = self.emu.hardware.find_register(*self.src[:2])
		so, sc = self.src[2:]; s_msk = ((2 ** sc) - 1) << so
		d_reg.data.value |= ((s_reg.data.value & s_msk) >> so) << do


