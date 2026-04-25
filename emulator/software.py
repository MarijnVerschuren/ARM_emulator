from unicorn import Uc
from unicorn.unicorn_const import *
from unicorn.arm_const import *
from capstone import *
from pynput.keyboard import Key, Listener, Controller
from multiprocessing import Process, Manager
from typing import Iterator
from threading import Lock
from rich import print
from time import sleep

# custom includes
from .UI import Emulator_UI, Emulator_UI_default


__all__ = [
	"IRQ_controller",
	"Software"
]


# types
class IRQ_controller:
	def __init__(self) -> None:
		self.lock = Lock()
		self.pending = set()
		
	def __bool__(self) -> bool:	return bool(self.pending)
	def __len__(self) -> int:	return len(self.pending)
	
	def trigger(self, IRQn: int) -> None:
		with self.lock:
			self.pending.add(IRQn)
	
	def next(self, current: int = None) -> int or None:
		if not self.pending: return None
		irq = min(self.pending)
		if current and current < irq: return None
		self.pending.remove(irq)
		return irq
	
	# TODO: overkill?
	def __iter__(self) -> Iterator[int]: return self
	def __next__(self) -> int:
		with self.lock:
			irq = self.next()
			if not irq: raise StopIteration
			return irq



class Software(Uc):
	IVT = 16
	ADDR_MSK =		0xFFFFFFFE
	THUMB_MSK =		0x00000001
	MEM_ACCESS_TYPES = {
		UC_MEM_READ:			"READ",
		UC_MEM_WRITE:			"WRITE",
		UC_MEM_FETCH:			"FETCH",
		UC_MEM_READ_UNMAPPED:	"READ_UNMAPPED",
		UC_MEM_WRITE_UNMAPPED:	"WRITE_UNMAPPED",
		UC_MEM_FETCH_UNMAPPED:	"FETCH_UNMAPPED",
		UC_MEM_WRITE_PROT:		"WRITE_PROT",
		UC_MEM_READ_PROT:		"READ_PROT",
		UC_MEM_FETCH_PROT:		"FETCH_PROT",
		UC_MEM_READ_AFTER:		"READ_AFTER"
	}
	
	def	__new__(cls, arch: int, mode: int, *args, **kwargs):
		return object.__new__(cls)
	
	def __init__(
			self, arch: int, mode: int, config: dict, actions: list,
			breakpoints: list, hardware: str, load_emu: callable,
			single_step: bool = False, UI_class: Emulator_UI = Emulator_UI_default()
	) -> None:
		# unicorn
		super(Software, self).__init__(arch, mode)
		#TODO: modular like: 	self.asm = Cs(arch - 1, mode); self.asm.detail = True
		self.asm = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); self.asm.detail = True
		
		# flags and variables
		self.manager =		Manager()		# multi core variable manager
		self.single_step =	self.manager.Value("single_step",	single_step)
		self.next_step =	self.manager.Value("next_step",		False)
		self.step =			self.manager.Value("step",			0)
		self.halt =			self.manager.Value("halt",			False)
		self.halted =		self.manager.Value("halted",		False)
		self.end =			None
		
		# code controller
		self.instruction_index =	0
		self.lr_stack =				[]	# used to determine calls and returns
		
		# interrupt controller
		self.IRQ_ctrl =				IRQ_controller()
		self.IRQ_transition =		False
		self.IRQn_active =			None
		self.IRQ_call_stack =		[]
		self.IRQ_stack =			[]
		
		# init component classes
		with open(hardware, "r") as file:
			factory = load_emu(file)
			file.close()
		self.hardware =			factory(self)
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
		
		# UI class
		self.UI = UI_class
		self.keyboard_thread = None
		self.keyboard = Controller()
		
		# add hooks
		self.hook_add(
			UC_HOOK_MEM_READ_UNMAPPED |
			UC_HOOK_MEM_WRITE_UNMAPPED |
			UC_HOOK_MEM_INVALID,
			self.memory_invalid_hook
		)
		self.hook_add(UC_HOOK_INSN_INVALID,	self.instruction_invalid_hook)
		self.hook_add(UC_HOOK_MEM_READ,		self.hardware.memory_read_hook)
		self.hook_add(UC_HOOK_MEM_WRITE,	self.hardware.memory_write_hook)
		self.hook_add(UC_HOOK_CODE,			self.code_hook)
		self.hook_add(UC_HOOK_BLOCK,		self.block_hook)

		# write peripheral reset values
		self.hardware.reset_peripherals()
		
	

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
	
	
	def PC_context(self, address: int) -> tuple[int, str]:
		f_address = 0; f_name = ""
		for f_address, s, f_name in self.info["functions"][::-1]:
			f_address &= self.ADDR_MSK
			if f_address <= address: break
		return address - f_address, f_name


	# control
	def load_code(self, code: bytes, info: dict) -> None:
		self.code = code; self.info = info
		self.mem_write(self.hardware.mem["load"], code)
		self.reg_write(UC_ARM_REG_SP, info["stack_pointer"])
		self.end = self.hardware.mem["load"] + len(self.code)


	def start(self, start: int = None, end: int = None) -> None:
		self.step.value = 0
		if not start:	start = self.info["entry_point"]
		if not end:		end = self.end
		with Listener(on_press=self.keyboard_cb) as self.keyboard_thread:
			self.emu_start(start, end)
		

	def keyboard_cb(self, key):  # UI callback
		ch = getattr(key, "char", None)
		if key == Key.space:	self.single_step.value = not self.single_step.value				# toggle single_step
		if key == Key.enter and self.single_step.value:	self.next_step.value = True				# set next_step if single_step is active
		if ch == "q": self.hardware.shutdown(); self.emu_stop(); self.next_step.value = True	# stop all threads (set next_step.value to quit emulator thread in case of single step)
		if ch == "a":
			pass # TODO: open action dialog. here an action from the config can be chosen or made


	def index_IVT(self, IRQn: int) -> tuple[int, int, str]:
		x = 4 * (IRQn + self.IVT)
		address = int.from_bytes(self.code[x:x+4], "little")
		function = None
		for func in self.info["functions"]:
			if func[0] != address: continue
			function = func; break
		return function
	
	
	def call_stack_update(self, address: int) -> None:
		offset, f_name = self.PC_context(address)
		if offset == 0:
			self.lr_stack.append(self.reg_read(UC_ARM_REG_LR) & self.ADDR_MSK)
			self.UI.log("CALL", f_name)
		elif self.lr_stack and self.lr_stack[-1] == address:
			self.lr_stack.pop()
			self.UI.log("RET", f_name)
	
	
	def IRQ_entry(self, IRQn: int) -> None:
		# preserve non volatile registers
		# TODO: _do_reg_read_batch
		address = self.reg_read(UC_ARM_REG_PC)
		frame = {
			"R0":	self.reg_read(UC_ARM_REG_R0),
			"R1":	self.reg_read(UC_ARM_REG_R1),
			"R2":	self.reg_read(UC_ARM_REG_R2),
			"R3":	self.reg_read(UC_ARM_REG_R3),
			"R12":	self.reg_read(UC_ARM_REG_R12),
			"LR":	self.reg_read(UC_ARM_REG_LR),
			"PC":	self.reg_read(UC_ARM_REG_PC)	| self.THUMB_MSK,
			"xPSC":	self.reg_read(UC_ARM_REG_XPSR)
		}
		self.IRQ_call_stack.append(address) # TODO: in irq ctrl?
		self.IRQ_stack.append(frame) # TODO: in irq ctrl?
		
		IRQ_address, IRQ_size, IRQ_name = self.index_IVT(IRQn)
		
		#self.UI.log("IRQ_CALL", f"{IRQ_name}\t{hex(IRQ_address)} => {hex(IRQ_address + IRQ_size)}")
		self.UI.log("IRQ_CALL", IRQ_name)
		
		self.reg_write(UC_ARM_REG_LR, address | self.THUMB_MSK)
		self.reg_write(UC_ARM_REG_PC, IRQ_address)
		self.IRQ_transition =	True
		self.IRQn_active =		IRQn
		
		
	def IRQ_exit(self) -> None:
		if not self.IRQ_stack:
			self.UI.log("ERROR", "IRQ RETURN with empty stack!")
			return
		
		self.UI.log("IRQ_RET", "IRQ return")
		
		self.IRQ_call_stack.pop()
		frame = self.IRQ_stack.pop()
		# TODO: _do_reg_write_batch
		self.reg_write(UC_ARM_REG_R0,	frame["R0"])
		self.reg_write(UC_ARM_REG_R1,	frame["R1"])
		self.reg_write(UC_ARM_REG_R2,	frame["R2"])
		self.reg_write(UC_ARM_REG_R3,	frame["R3"])
		self.reg_write(UC_ARM_REG_R12,	frame["R12"])
		self.reg_write(UC_ARM_REG_LR,	frame["LR"])
		self.reg_write(UC_ARM_REG_PC,	frame["PC"])
		self.reg_write(UC_ARM_REG_XPSR,	frame["xPSC"])
		self.IRQn_active = None
		
		
		
	# hooks
	@staticmethod
	def memory_invalid_hook(self: "Software", access, address, size, value, user_data) -> bool:
		self.UI.log("ERROR", f"memory invalid: {self.MEM_ACCESS_TYPES[access]}, {size} @{hex(address)} => {hex(value)}")
		
		cont = self.UI.prompt_choice(
			msg="continue",
			choices=["yes", "no"]
		) == "yes"
		
		if not cont: return False
		pc = self.reg_read(UC_ARM_REG_PC)
		self.reg_write(UC_ARM_REG_PC, pc + 2)
		return True
	
	
	@staticmethod
	def instruction_invalid_hook(self: "Software", key: int):
		pc = self.reg_read(UC_ARM_REG_PC)
		opcode = self.mem_read(pc, 4)
		
		self.UI.log("ERROR", f"INVALID INSTRUCTION @{hex(pc)}")
		self.UI.log("ERROR", f"RAW: {opcode.hex()}")
		
		mnemonics = self.asm.disasm(opcode, pc)
		for i in mnemonics:
			self.UI.log("ERROR", f"ASM: {i.mnemonic}\t{i.op_str}")
		
		cont = self.UI.prompt_choice(
			msg="continue",
			choices=["yes", "no"]
		) == "yes"
		if not cont: return False
		self.reg_write(UC_ARM_REG_PC, pc + 2)
		return True


	@staticmethod
	def block_hook(self: "Software", address, size, user_data) -> None:
		if self.IRQ_transition: self.IRQ_transition = False; return None
		if self.IRQ_call_stack and address == self.IRQ_call_stack[-1]: return self.IRQ_exit()
		if IRQn := self.IRQ_ctrl.next(self.IRQn_active): return self.IRQ_entry(IRQn)
		return self.call_stack_update(address)
	
	
	@staticmethod
	def code_hook(self: "Software", address, size, user_data):
		# sync
		if self.single_step.value:
			self.UI.log_regs(self.regs)
			while not self.next_step.value and self.single_step.value: pass
			self.next_step.value = False
		self.step.value += 1
		
		# forensics
		d_address, f_name = self.PC_context(address)
		opcode = self.mem_read(address, size)
		mnemonics = self.asm.disasm(opcode, address)
		
		# breakpoint logic
		for bp in self.breakpoints:
			self.single_step.value |= (
				(bp == f_name and d_address < 2)	# enter function
				or bp == address					# at address
			)
		# halt logic
		if self.halt.value or not self.halted.value:
			self.halted.value =								True
			while self.halt.value:							pass
			self.halted.value =								False
		
		# print (just before return / exec)
		for i in mnemonics:
			self.UI.log("CODE", f"[{self.instruction_index}] {hex(i.address)} ({f_name} + {hex(d_address)}): {i.mnemonic}\t{i.op_str}")
		
		self.instruction_index += 1
