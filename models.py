import os
import re
import shutil
import subprocess
import shlex
import ctypes
import struct
from os.path import splitext
from typing import Type, Union
from ctypes import memmove, pointer, sizeof

from elftools.elf.elffile import ELFFile
from capstone.arm_const import *


class FirmwareImage():
	"""
	A wrapper class for elf, intel hex, and binary firmware
	"""
	RE_PTRN_DISASM = re.compile((
		r" +(?P<addr>[0-9a-fA-F]+):\s+"
		r"(?P<raw>[0-9a-fA-F]+(?: [0-9a-fA-F]+)?)\s+"
		r"(?P<mnemonic>.+)"))

	def __init__(self, path : str, isa : str = 'armv7e-m'):
		self.path = path
		self.ext = splitext(path)[1]
		self.img = None
		self.disasm = {}
		self.disasm_txt = []
		self.raw = None

		# elf format
		if self.ext == '.elf':
			# load img from file
			self.img = ELFFile.load_from_path(path)

			# disassemble the file using objdump
			self.disasm_txt = subprocess.run(
				shlex.split(f"arm-none-eabi-objdump -D {path}"),
				stdout=subprocess.PIPE,
			).stdout.decode('utf-8').split('\n')

			# construct addr-to-line mapping and disasm dict
			for lineno, line in enumerate(self.disasm_txt):
				match = self.RE_PTRN_DISASM.search(line)
				if match:
					addr = int(match.group('addr'), base=16)
					self.disasm[addr] = {
						'line': lineno,
						'raw': int(''.join(match.group('raw').split()), base=16),
						'raw_str': match.group('raw'),
						'mnemonic': match.group('mnemonic'),
					}

			# construct raw binary
			self.raw = b""
			for segment in sorted(self.img.iter_segments(),
					key=lambda seg: seg['p_paddr']):
				if segment['p_paddr'] > len(self.raw):
					self.raw += b'\x00' * (segment['p_paddr'] - len(self.raw))
				self.raw += segment.data()

		# raw bin format
		elif self.ext == '.bin':
			# load img from file
			with open(path, 'rb') as binfile:
				self.img = binfile.read()
			self.raw = self.img

			# disassemble with objdump
			self.disasm_txt = subprocess.run([
					'arm-none-eabi-objdump', '-D',
					'-bbinary',
					f'-m{isa}',
					'-Mforce-thumb',
					path],
				stdout=subprocess.PIPE,
			).stdout.decode('utf-8').split('\n')

			# construct addr-to-line mapping and disasm dict
			for lineno, line in enumerate(self.disasm_txt):
				match = self.RE_PTRN_DISASM.search(line)
				if match:
					addr = int(match.group('addr'), base=16)
					self.disasm[addr] = {
						'line': lineno,
						'raw': int(''.join(match.group('raw').split()), base=16),
						'raw_str': match.group('raw'),
						'mnemonic': match.group('mnemonic'),
					}

		# intel hex format
		elif self.ext == '.hex':
			assert 0, "not implemented yet"

		else:
			raise Exception("fw image file must be elf, ihex, or binary")


class APSRRegister(ctypes.LittleEndianStructure):
	"""bit fields for apsr register"""
	_pack_ = 1
	_fields_ = [
		('rsvd0', ctypes.c_uint32, 16),
		('ge',    ctypes.c_uint32, 4),
		('rsvd1', ctypes.c_uint32, 7),
		('Q',     ctypes.c_uint32, 1),  # dsp overflow and saturation
		('V',     ctypes.c_uint32, 1),  # overflow
		('C',     ctypes.c_uint32, 1),  # carry or borrow
		('Z',     ctypes.c_uint32, 1),  # zero
		('N',     ctypes.c_uint32, 1),  # negative
	]
	COND_CODE_SUFX = {
		ARM_CC_EQ : lambda apsr: apsr.Z == 1,
		ARM_CC_NE : lambda apsr: apsr.Z == 0,
		ARM_CC_HS : lambda apsr: apsr.C == 1,
		ARM_CC_LO : lambda apsr: apsr.C == 0,
		ARM_CC_MI : lambda apsr: apsr.N == 1,
		ARM_CC_PL : lambda apsr: apsr.N == 0,
		ARM_CC_VS : lambda apsr: apsr.V == 1,
		ARM_CC_VC : lambda apsr: apsr.V == 0,
		ARM_CC_HI : lambda apsr: apsr.C == 1 and apsr.Z == 0,
		ARM_CC_LS : lambda apsr: apsr.C == 0 or  apsr.Z == 1,
		ARM_CC_GE : lambda apsr: apsr.N == apsr.V,
		ARM_CC_LT : lambda apsr: apsr.N != apsr.V,
		ARM_CC_GT : lambda apsr: apsr.Z == 0 and apsr.N == apsr.V,
		ARM_CC_LE : lambda apsr: apsr.Z == 1 and apsr.N != apsr.V,
		ARM_CC_AL : lambda apsr: True,
	}

	def __new__(cls, val : Union[int, bytes, bytearray]):
		if isinstance(val, (bytes, bytearray)):
			assert len(val) == 4, "register is 4 bytes"
			return self.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray]):
		if isinstance(val, int):
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)

	def __copy__(self):
		cls = self.__class__
		result = cls.__new__(cls, int.from_bytes(self, 'little'))
		for k, v in self.__dict__.items():
			setattr(result, k, copy(v))
		return result

	def set(self, val : Union[int, bytes, bytearray]):
		if isinstance(val, (bytes, bytearray)):
			memmove(pointer(self), val, sizeof(self))
		elif isinstance(val, int):
			# value must be 32 bits, trim excess
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)
		else:
			raise Exception(f"APSRRegister: invalid set val {val}")

	def get_cond(self, cond_code):
		"""get current conditional status 
		based on capstone conditional code suffix definitions
		"""
		return self.COND_CODE_SUFX[cond_code](self)