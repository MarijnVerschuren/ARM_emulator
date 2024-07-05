from inquirer import (
	List as _list,
	Checkbox as _checkbox,
	themes
)
from inquirer.render.console import ConsoleRender


__all__ = [
	"Choice",
	"Multi_Choice",
	"prompt"
]

class Choice(_list):
	def __init__(
			self, name: str, message: str,
		 	choices: list = None, format_choices: list = None,
			format: callable = None, hints: list = None,
			default: any = None, ignore: bool = False,
			validate: bool = True, carousel: bool = False,
			other: bool = False, autocomplete: any = None
	):
		super().__init__(
			name, message, (choices or []) + list(map(format, format_choices) if format else []),
			hints, default, ignore, validate, carousel, other, autocomplete
		); self.orig_choices = (choices or []) + (format_choices or [])

	def format(self, answer) -> any: return self.orig_choices[self.choices.index(answer)]


class Multi_Choice(_checkbox):
	def __init__(
			self, name: str, message: str,
		 	choices: list = None, format_choices: list = None,
			format: callable = None, hints: list = None,
			locked: any = None, default: any = None,
			ignore: bool = False, validate: bool = True,
			carousel: bool = False, other: bool = False,
			autocomplete: any = None
	):
		super().__init__(
			name, message, (choices or []) + list(map(format, format_choices) if format else []),
			hints, locked, default, ignore, validate, carousel, other, autocomplete
		); self.orig_choices = (choices or []) + (format_choices or [])

	def format(self, answer) -> any: return self.orig_choices[self.choices.index(answer)]



def prompt(*questions: Choice or Multi_Choice, theme=themes.Default()) -> dict or any:
	render = ConsoleRender(theme=theme)
	answers = {question.name: question.format(render.render(question)) for question in questions}
	if len(answers.keys()) > 1: return answers
	return list(answers.values())[0]


