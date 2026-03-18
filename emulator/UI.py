from rich import print


__all__ = [
	"Emulator_UI",
	"Emulator_UI_default"
]


class Emulator_UI(object):
	def log(self, log_type: str, text: str) -> None:
		pass

		# TODO:prompts!!!

class Emulator_UI_default(Emulator_UI):
	def log(self, log_type: str, text: str) -> None:
		color = ""
		if log_type == "ERROR": color = "red1"
		if log_type == "IRQ": color = "dark_orange"
		print(f"{(f'[{color}]' if color else '')}{text}{(f'[/{color}]' if color else '')}")
		