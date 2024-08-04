from unicorn import Uc
from unicorn.unicorn_const import *
from unicorn.arm_const import *
from capstone import Cs
from pynput.keyboard import Key, Listener, Controller
from multiprocessing import Process, Manager
from rich import print
from time import sleep

# custom includes
from helpers import *


__all__ = [
	"Software"
]


# types
class Software(Uc):
	def __init__(self, arch: int, mode: int, config: dict, actions: list, breakpoints: list, hardware: str, load_emu: callable, single_step: bool = False) -> None:
		# unicorn
		super(self.__class__, self).__init__(arch, mode)
		self.asm = Cs(arch - 1, mode); self.asm.detail = True

		# flags and variables
		self.manager = Manager()		# multi core variable manager
		self.single_step =	self.manager.Value("single_step",	single_step)
		self.next_step =	self.manager.Value("next_step",		False)
		self.step =			self.manager.Value("step",			0)

		# init component classes
		with open(hardware, "r") as file:
			factory = load_emu(file)
			file.close()
		self.hardware = factory(self)
		self.config =			config
		self.actions =			actions
		self.breakpoints =		breakpoints
		self.hardware_accel =	self.config["accel"]

		# map memory
		dmem = self.hardware.mem
		for bank in self.config["flash"]:	self.mem_map(dmem["flash"][bank],		dmem["flash"][f"{bank}_size"])	# memory map flash banks
		if self.config["periph"]:			self.mem_map(dmem["periph"]["start"],	dmem["periph"]["size"])			# memory map peripheral space
		if self.config["var"]:				self.mem_map(dmem["var"]["start"],		dmem["var"]["size"])			# memory map variable space
		if self.config["core"]:				self.mem_map(dmem["core"]["start"],		dmem["core"]["size"])			# memory map core space

		# add hooks
		self.hook_add(
			UC_HOOK_MEM_READ_UNMAPPED |
			UC_HOOK_MEM_WRITE_UNMAPPED |
			UC_HOOK_MEM_INVALID,
			self.memory_invalid_hook
		)
		self.hook_add(UC_HOOK_MEM_READ,		self.hardware.memory_read_hook)
		self.hook_add(UC_HOOK_MEM_WRITE,	self.hardware.memory_write_hook)
		self.hook_add(UC_HOOK_CODE,			self.code_hook)
		self.hook_add(UC_HOOK_INTR,			self.interrupt_hook)

		# write peripheral reset values
		self.hardware.reset_peripherals()

		# UI
		self.UI_thread = None
		self.keyboard = Controller()

	# getters
	def __str__(self) -> str:		return f"<[{self.__class__.__name__}], hardware: {self.hardware}>"
	def __repr__(self) -> str:		return f"<[{self.__class__.__name__}], {repr(self.hardware)}>"

	@property
	def regs(self) -> dict:
		regs = {}
		for i in range(13): regs |= {f"R{i}": hex(self.reg_read(UC_ARM_REG_R0 + i))}
		return regs | {
			"SP": hex(self.reg_read(UC_ARM_REG_SP)),
			"LR": hex(self.reg_read(UC_ARM_REG_LR)),
			"PC": hex(self.reg_read(UC_ARM_REG_PC))
		}

	# control
	def load_code(self, code: bytes, info: dict) -> None:
		self.code = code; self.info = info
		self.mem_write(self.hardware.mem["load"], code)
		self.reg_write(UC_ARM_REG_SP, info["stack_pointer"])

	def start(self) -> None:
		self.step.value = 0

		start = Process(target=self.emu_start, args=(self.info["entry_point"], self.hardware.mem["load"] + len(self.code)))
		with Listener(on_press=self.UI) as self.UI_thread:
			start.start(); start.join()

	def UI(self, key):  # UI callback
		if key == Key.space:	self.single_step.value = not self.single_step.value		# toggle single_step
		if key == Key.enter and self.single_step.value:	self.next_step.value = True		# set next_step if single_step is active
		if key == "a":
			pass # TODO: open action dialog. here an action from the config can be chosen or made

	# hooks
	@staticmethod
	def memory_invalid_hook(self, access, address, size, value, user_data) -> bool:
		print(f"invalid: {access}, {hex(address)}, {size}, {value}: {hex(value)}")
		return False

	@staticmethod
	def code_hook(self: "Software", address, size, user_data):
		# sync
		if self.single_step.value:
			print(self.regs, end="")
			while not self.next_step.value and self.single_step.value: pass
			self.next_step.value = False
		self.step.value += 1
		# forensics
		f_address = 0; f_name = ""
		for f_address, s, f_name in self.info["functions"][::-1]:
			if f_address < address: break
		opcode = self.mem_read(address, size)
		mnemonics = self.asm.disasm(opcode, address)
		d_address = address - f_address
		for i in mnemonics:
			print(f"{hex(i.address)} ({f_name} + {hex(d_address)}): {i.mnemonic}\t{i.op_str}")
		# breakpoint logic
		for bp in self.breakpoints:
			self.single_step.value |= (
				(bp == f_name and d_address < 2)	# enter function
				or bp == address					# at address
			)

	@staticmethod
	def interrupt_hook(self, address, size, user_data):
		print("interrupt")