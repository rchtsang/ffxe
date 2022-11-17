import ctypes
import struct
from typing import Union
from ctypes import memmove, pointer, sizeof

from mappings import *

class Thumb32BL(ctypes.LittleEndianStructure):
	"""struct for the thumb bl instruction bit fields
	see ARMv7M technical reference manual Section A7.7.18
	"""
	_pack_ = 1
	_fields_ = [
		('uimm11', ctypes.c_uint32, 11),
		('op1',    ctypes.c_uint32, 5),
		('limm11', ctypes.c_uint32, 11),
		('op2',    ctypes.c_uint32, 5),
	]

	def __new__(cls, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) == 4, 'BL instruction must be 4 bytes'
			return cls.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, int):
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)

	def set(self, val : Union[int, bytes, bytearray]):
		if isinstance(val, Union[bytes, bytearray]):
			memmove(pointer(self), val, sizeof(self))
		elif isinstance(val, int):
			# value must be 32 bits, trim excess
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)
		else:
			raise Exception(f"Thumb32BL: invalid set value {val}")

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

	@property
	def imm32(self):
		val = ((self.uimm11 << 11) + self.limm11) << 1
		return -((val ^ 0x7FFFFF) + 1) if val & 0x400000 else val


class Thumb16BT1(ctypes.LittleEndianStructure):
	"""struct for thumb branch T1 encoding
	see ARMv7M technical reference manual Section A7.7.12
	"""
	_pack_ = 1
	_fields_ = [
		('imm8', ctypes.c_uint16, 8),
		('cond', ctypes.c_uint16, 4),
		('op',   ctypes.c_uint16, 4),
	]

	def __new__(cls, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) == 2, 'T1 encoding must be 2 bytes'
			return cls.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, int):
			val &= 0xFFFF
			struct.pack_into('H', self, 0, val)

	def set(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			memmove(pointer(self), val, sizeof(self))
		elif isinstance(val, int):
			# value must be 16 bits, trim excess
			val &= 0xFFFF
			struct.pack_into('H', self, 0, val)
		else:
			raise Exception(f"Thumb32BT1: invalid set value {val}")

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

	@property
	def imm32(self):
		val = (self.imm8 << 1)
		return -((val ^ 0x1FF) + 1) if val & 0x100 else val


class Thumb16BT2(ctypes.LittleEndianStructure):
	"""struct for thumb branch T2 encoding
	see ARMv7M technical reference manual Section A7.7.12
	outside or last in IT block
	"""
	_pack_ = 1
	_fields_ = [
		('imm11', ctypes.c_uint16, 11),
		('op',    ctypes.c_uint16, 5),
	]

	def __new__(cls, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) == 2, 'T2 encoding must be 2 bytes'
			return cls.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, int):
			val &= 0xFFFF
			struct.pack_into('H', self, 0, val)

	def set(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			memmove(pointer(self), val, sizeof(self))
		elif isinstance(val, int):
			# value must be 16 bits, trim excess
			val &= 0xFFFF
			struct.pack_into('H', self, 0, val)
		else:
			raise Exception(f"Thumb32BT2: invalid set value {val}")

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

	@property
	def imm32(self):
		val = (self.imm11 << 1)
		return -((val ^ 0xFFF) + 1) if val & 0x800 else val


class Thumb32BT3(ctypes.LittleEndianStructure):
	"""struct for thumb branch T3 encoding
	see ARMv7M technical reference manual Section A7.7.12
	"""
	_pack_ = 1
	_fields_ = [
		('uimm6',  ctypes.c_uint32, 6),
		('cond',   ctypes.c_uint32, 4),
		('sign',   ctypes.c_uint32, 1),
		('op0',    ctypes.c_uint32, 5),
		('limm11', ctypes.c_uint32, 11),
		('j2',     ctypes.c_uint32, 1),
		('op1',    ctypes.c_uint32, 1),
		('j1',     ctypes.c_uint32, 1),
		('op2',    ctypes.c_uint32, 2),
	]

	def __new__(cls, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) == 4, 'T3 encoding must be 4 bytes'
			return self.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, int):
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)
		
	def set(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			memmove(pointer(self), val, sizeof(self))
		elif isinstance(val, int):
			# value must be 32 bits, trim excess
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)
		else:
			raise Exception(f"Thumb32BT3: invalid set value {val}")

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

	@property
	def imm32(self):
		val = (self.uimm6 << 12) + (self.limm11 << 1)
		val += (self.j2 << 19) + (self.j1 << 18)
		return -((val ^ 0xFFFFF) + 1) if self.sign else val


class Thumb32BT4(ctypes.LittleEndianStructure):
	"""struct for thumb branch T3 encoding
	see ARMv7M technical reference manual Section A7.7.12
	outside or last in IT block
	"""
	_pack_ = 1
	_fields_ = [
		('uimm10', ctypes.c_uint32, 10),
		('sign',   ctypes.c_uint32, 1),
		('op1',    ctypes.c_uint32, 5),
		('limm11', ctypes.c_uint32, 11),
		('j2',     ctypes.c_uint32, 1),
		('op1',    ctypes.c_uint32, 1),
		('j1',     ctypes.c_uint32, 1),
		('op2',    ctypes.c_uint32, 2),
	]

	def __new__(cls, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) == 4, 'T4 encoding must be 4 bytes'
			return self.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, int):
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)

	def set(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			memmove(pointer(self), val, sizeof(self))
		elif isinstance(val, int):
			# value must be 32 bits, trim excess
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)
		else:
			raise Exception(f"Thumb32BT3: invalid set value {val}")

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

	@property
	def imm32(self):
		val = (self.uimm10 << 12) + (self.limm11 << 1)
		return -((val ^ 0x3FFFFF) + 1) if self.sign else val


class ThumbBranch(ctypes.Union):
	_fields_ = [
		('T1', Thumb16BT1),
		('T2', Thumb16BT2),
		('T3', Thumb32BT3),
		('T4', Thumb32BT4),
	]

	def __new__(cls, val : Union[int, bytes, bytearray]):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) <= 4, 'branch has maximum 4 bytes'
			if len(val) < 4:
				val += b'\x00' * (4 - len(val))
			return cls.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray]):
		if isinstance(val, int):
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)
		# determine encoding
		if self.T1.op == 0b1101:
			self.enc = 'T1'
		elif self.T2.op == 0b11100:
			self.enc = 'T2'
		elif self.T3.op0 == 0b11110:
			if self.T3.op1 == 0:
				self.enc = 'T3'
			else:
				self.enc = 'T4'
		else:
			raise Exception("invalid opcode bits")

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

	@property
	def imm32(self):
		return (getattr(self, self.enc)).imm32
	

class Thumb16CompareBranch(ctypes.LittleEndianStructure):
	"""struct for CBZ and CBNZ instructions
	see ARMv7M technical reference manual Section A7.7.21
	"""
	_pack_ = 1
	_fields_ = [
		('Rn',   ctypes.c_uint16, 3),
		('imm5', ctypes.c_uint16, 5),
		('b1',   ctypes.c_uint16, 1),
		('i',    ctypes.c_uint16, 1),
		('b0',   ctypes.c_uint16, 1),
		('nz',   ctypes.c_uint16, 1),
		('op',   ctypes.c_uint16, 4),
	]
	def __new__(cls, val : Union[int, bytes, bytearray]):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) == 2, 'CBZ and CBNZ encoding must be 2 bytes'
			return cls.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray]):
		if isinstance(val, int):
			val &= 0xFFFF
			struct.pack_into('H', self, 0, val)
		assert (
			self.op == 0b1011
			and self.b1 == 1
			and self.b0 == 0
		), 'wrong opcode'

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

	@property
	def imm32(self):
		return (self.i << 6) + (self.imm5 << 1)


class Thumb32TableBranch(ctypes.LittleEndianStructure):
	"""struct for TBB and TBH instructions
	see ARMv7M technical reference manual Section A7.7.182
	"""
	_pack_ = 1
	_fields_ = [
		('Rn',   ctypes.c_uint32, 4),
		('op1',  ctypes.c_uint32, 12),
		('Rm',   ctypes.c_uint32, 4),
		('half', ctypes.c_uint32, 1),
		('op2',  ctypes.c_uint32, 11)
	]

	def __new__(cls, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			assert len(val) == 4, 'T1 encoding must be 4 bytes'
			return cls.from_buffer_copy(val)
		else:
			return super().__new__(cls)

	def __init__(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, int):
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)

	def set(self, val : Union[int, bytes, bytearray] = None):
		if isinstance(val, Union[bytes, bytearray]):
			memmove(pointer(self), val, sizeof(self))
		elif isinstance(val, int):
			# value must be 32 bits, trim excess
			val &= 0xFFFFFFFF
			struct.pack_into('I', self, 0, val)
		else:
			raise Exception(f"Thumb32BT3: invalid set value {val}")

	@property
	def bytevalue(self):
		return bytes(self)

	@property
	def value(self):
		return int.from_bytes(self, 'little')

