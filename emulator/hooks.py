# TUI includes
from rich import print
# general includes
import json


__all__ = [
	"memory_invalid_hook",
	"memory_read_hook",
	"memory_write_hook",
	"code_hook",
	"interrupt_hook"
]


# emulation hooks
def memory_invalid_hook(emu, access, address, size, value, user_data):
	print(f"invalid: {access}, {hex(address)}, {size}, {value}: {hex(value)}")
	return False

def memory_read_hook(emu, access, address, size, value, user_data):
	print(f"read: {access}, {hex(address)}, {size}, {value}")

def memory_write_hook(emu, access, address, size, value, user_data):
	print(f"write: {access}, {hex(address)}, {size}, {value}")

def code_hook(emu, address, size, user_data):
	f_address = 0; f_name = ""
	for f_address, s, f_name in user_data.info.functions[::-1]:
		if f_address < address: break
	opcode = emu.mem_read(address, size)
	mnemonics = user_data.asm.disasm(opcode, address)
	for i in mnemonics:
		print(f"{hex(i.address)} ({f_name} + {hex(address - f_address)}): {i.mnemonic}\t{i.op_str}")

def interrupt_hook(emu, address, size, user_data):
	print("interrupt")