from rich import print


# custom includes
from helpers import *



__all__ = [
	"Emulator_UI",
	"Emulator_UI_default"
]


class Emulator_UI(object):
	def log_regs(self, regs: dict) -> None:						pass
	def log(self, log_type: str, text: str) -> None:			pass
	def prompt(self, msg: str, text: str) -> None:				pass
	def prompt_choice(self, msg: str, choices: list) -> any:	pass
	

class Emulator_UI_default(Emulator_UI):
	def log_regs(self, regs: dict) -> None:
		print(regs)
	
	def log(self, log_type: str, text: str) -> None:
		color = ""
		if log_type == "ERROR": color = "red1"
		if log_type == "IRQ": color = "dark_orange"
		print(f"{(f'[{color}]' if color else '')}{text}{(f'[/{color}]' if color else '')}")
		
	def prompt(self, msg: str, text: str) -> None:
		print(f"{msg}: {text}"); input()
	
	def prompt_choice(self, msg: str, choices: list) -> any:
		return prompt(Choice(
			msg, message=msg,
			choices=choices
		))
		