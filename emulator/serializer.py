from json import dump, JSONEncoder, load, JSONDecoder
from functools import partial

from .software import Software
from .hardware import Hardware


__all__ = [
	"dump_emu",
	"load_emu"
]


# en/decoders
class emu_encoder(JSONEncoder):
	def default(self, obj: object) -> dict:
		if isinstance(obj, Software):
			pass  # TODO
		if isinstance(obj, Hardware):
			pass  # TODO
		return super().default(obj)


class emu_decoder(JSONDecoder):
	def __init__(self, *args, **kwargs):
		self.orig_obj_hook = kwargs.pop("object_hook", None)
		super(self.__class__, self).__init__(*args, object_hook=self.default, **kwargs)
		self.emu_arch = kwargs.get("arch", None)
		self.emu_mode = kwargs.get("mode", None)
		self.soft =		kwargs.get("soft", None)

	def default(self, data: dict) -> object:
		if self.emu_arch and self.emu_mode:		return Software(self.emu_arch, self.emu_mode, **data, load_emu=load_emu)
		if self.soft:							return Hardware(self.soft, **data)
		raise ValueError(
			"""
			Missing arguments for:
				Software(arch, mode, [JSON])
				Hardware(soft, [JSON])
			"""
		)


# partials
dump_emu = partial(load, cls=emu_encoder)
load_emu = partial(load, cls=emu_decoder)
