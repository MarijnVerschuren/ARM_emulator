from json import dump, JSONEncoder, load, JSONDecoder
from functools import partial

from .software import *
from .hardware import *


__all__ = [
	"load_emu"
]


# factory structures
class Software_Factory:
	def __init__(self, config: dict, hardware: str) -> None:
		self.config = config
		self.hardware = hardware

	def __call__(self, cfg_dir, arch: int, mode: int) -> Software:
		return Software(arch, mode, self.config, f"{cfg_dir}/{self.hardware}", load_emu)
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], config: {self.config}, hardware: {self.hardware}>"
	def __repr__(self) -> str:	return str(self)

class Hardware_Factory:
	def __init__(self, memory: dict, device: list["Peripheral_Factory"]) -> None:
		self.memory = memory
		self.device = device

	def __call__(self, soft: Software) -> Hardware:
		peripherals = []
		for factory in self.device: peripherals.extend(factory(soft))
		return Hardware(soft, self.memory, peripherals)

	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], memory: {self.memory}, device: {self.device}>"
	def __repr__(self) -> str:	return str(self)

class Peripheral_Factory:
	def __init__(self, type: str, base_cfg: dict, regs: list["Register_Factory"]) -> None:
		self.type = type
		self.regs = regs
		self.base_cfg = base_cfg

	def __call__(self, soft: Software) -> list[Peripheral]:
		peripherals = []
		for label, base in self.base_cfg.items():
			registers = []
			peripheral = Peripheral(soft, self.type, registers, label, base)
			for factory in self.regs: registers.append(factory(soft, peripheral))
			peripherals.append(peripheral)
		return peripherals

	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], type: {self.type}, base_cfg: {self.base_cfg}, regs: {self.regs}>"
	def __repr__(self) -> str:	return str(self)

class Register_Factory:
	def __init__(self, offset: int, label: str, bits: list[str], reset: int, triggers: list["Trigger_Factory"] = None) -> None:
		self.offset = offset
		self.label = label
		self.bits = bits
		self.reset = reset
		self.triggers = triggers or []

	def __call__(self, soft: Software, parent: Peripheral) -> Register:
		triggers = [trigger(soft) for trigger in self.triggers]
		return Register(soft, parent, self.offset, self.label, self.bits, self.reset, triggers)

	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], label: {self.label}, offset: {self.offset}, bits: {self.bits}, reset: {self.reset}, triggers: {self.triggers}>"
	def __repr__(self) -> str:	return str(self)

class Trigger_Factory:
	def __init__(self, actions: list["Action_Factory"], src: None or tuple[int, int, int or None] = None):
		# write if src, else read
		self.actions = actions
		self.src = src		# bit, count, setting or any

	def __call__(self, soft: Software) -> Trigger:
		actions = [action(soft) for action in self.actions]
		return Trigger(soft, actions, self.src)

	@property
	def type(self) -> str:		return ("write " + ("setting" if self.src[2] else "any")) if self.src else "read"
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], trigger_t: {self.type}, actions: {self.actions}, src: {self.src}>"
	def __repr__(self) -> str:	return str(self)

class Action_Factory:
	def __init__(self, src: int or tuple[str, int, int, int], dst: tuple[str, int, int, int]):
		# write if type(src) == int, else copy src
		self.src = src		# peripheral, offset, bit, count
		self.dst = dst		# peripheral, offset, bit, count

	def __call__(self, soft: Software) -> Action:
		return Action(soft, self.src, self.dst)

	@property
	def type(self) -> str:		return "write" if isinstance(self.src, int) else "copy"
	def __str__(self) -> str:	return f"<[{self.__class__.__name__}], action_t: {self.type}, src: {self.src}, dst: {self.dst}>"
	def __repr__(self) -> str:	return str(self)


# decoder
class emu_decoder(JSONDecoder):
	def __init__(self, *args, **kwargs):
		self.orig_obj_hook =	kwargs.pop("object_hook", None)
		self.emu_arch =			kwargs.pop("arch", None)
		self.emu_mode = 		kwargs.pop("mode", None)
		self.soft =				kwargs.pop("soft", None)
		super(self.__class__, self).__init__(*args, object_hook=self.default, **kwargs)

	def default(self, data: dict) -> object:
		try:	return Software_Factory(**data)
		except:	pass
		try:	return Hardware_Factory(**data)
		except:	pass
		try:	return Peripheral_Factory(**data)
		except:	pass
		try:	return Register_Factory(**data)
		except:	pass
		try:	return Trigger_Factory(**data)
		except:	pass
		try:	return Action_Factory(**data)
		except:	pass
		return data


# partials
load_emu = partial(load, cls=emu_decoder)
