from unicorn import Uc
from unicorn.unicorn_const import *
from unicorn.arm_const import *
from capstone import Cs
from os import listdir

# custom includes
from helpers import *


__all__ = [
	"Software"
]


# types
class Software(Uc):
	def __init__(self, arch: int, mode: int, hardware: str, config: dict, load_emu: callable) -> None:
		super(self.__class__, self).__init__(arch, mode)
		self.asm = Cs(arch - 1, mode); self.asm.detail = True
		with open(f"./dev_config/{hardware}.json", "r") as file:
			self.hardware = load_emu(file, emu=self)
		self.config = config

		# map memory
		dmem = self.hardware.mem
		for bank in self.config["flash"]:	self.mem_map(dmem["flash"][bank],			dmem["flash"][f"{bank}_size"])	# memory map flash banks
		if self.config["periph"]:			self.mem_map(dmem["periph"]["start"],		dmem["periph"]["size"])			# memory map peripheral space
		if self.config["var"]:				self.mem_map(dmem["var"]["start"],			dmem["var"]["size"])			# memory map variable space
		if self.config["ROM_table"]:		self.mem_map(dmem["ROM_table"]["start"],	dmem["ROM_table"]["size"])		# memory map ROM_table space

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

	def load_code(self, code: bytes, info: dict) -> None:
		self.code = code; self.info = info
		self.mem_write(self.hardware.mem["load"], code)
		self.reg_write(UC_ARM_REG_SP, info["stack_pointer"])

	def start(self) -> None:
		self.emu_start(self.info["entry_point"], self.hardware.mem["load"] + len(self.code))

	@staticmethod
	def memory_invalid_hook(emu, access, address, size, value, user_data) -> bool:
		print(f"invalid: {access}, {hex(address)}, {size}, {value}: {hex(value)}")
		return False

	@staticmethod
	def code_hook(emu, address, size, user_data):
		f_address = 0; f_name = ""
		for f_address, s, f_name in user_data.info.functions[::-1]:
			if f_address < address: break
		opcode = emu.mem_read(address, size)
		mnemonics = user_data.asm.disasm(opcode, address)
		for i in mnemonics:
			print(f"{hex(i.address)} ({f_name} + {hex(address - f_address)}): {i.mnemonic}\t{i.op_str}")

	@staticmethod
	def interrupt_hook(emu, address, size, user_data):
		print("interrupt")
