import ctypes
import struct
from typing import Union, Type
from ctypes import memmove, pointer, sizeof

from unicorn import *
from unicorn.arm_const import *

from mappings import *


###########################################################
## BRANCH INSTRUCTIONS
###########################################################


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
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 4, 'BL instruction must be 4 bytes'
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)

    def set(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
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
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 2, 'T1 encoding must be 2 bytes'
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, int):
            val &= 0xFFFF
            struct.pack_into('H', self, 0, val)

    def set(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, (bytes, bytearray)):
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
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 2, 'T2 encoding must be 2 bytes'
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, int):
            val &= 0xFFFF
            struct.pack_into('H', self, 0, val)

    def set(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, (bytes, bytearray)):
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
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 4, 'T3 encoding must be 4 bytes'
            return self.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)
        
    def set(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, (bytes, bytearray)):
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
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 4, 'T4 encoding must be 4 bytes'
            return self.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)

    def set(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, (bytes, bytearray)):
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
        if isinstance(val, (bytes, bytearray)):
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
        if isinstance(val, (bytes, bytearray)):
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
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 4, 'T1 encoding must be 4 bytes'
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)

    def set(self, val : Union[int, bytes, bytearray] = None):
        if isinstance(val, (bytes, bytearray)):
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


###########################################################
## LOAD INSTRUCTIONS
###########################################################


class LDRImmT1(ctypes.LittleEndianStructure):
    """struct for ldr (imm) T1 encoding
    also for ldrb (imm) T1 encoding
    also for ldrh (imm) T1 encoding
    see Section A7.7.42 (ldr)
    see Section A7.7.45 (ldrb)
    see Section A7.7.54 (ldrh)
    """
    _pack_ = 1
    _fields_ = [
        ('Rt',   ctypes.c_uint16, 3),
        ('Rn',   ctypes.c_uint16, 3),
        ('imm5', ctypes.c_uint16, 5),
        ('op',   ctypes.c_uint16, 5),
    ]

    @property
    def valid(self):
        return (
            self.op == 0b01101      # word
            or self.op == 0b01111   # byte
            or self.op == 0b10001   # half
        )

    @property
    def load_size(self):
        if self.op == 0b01101:
            return 4
        elif self.op == 0b01111:
            return 1

    @property
    def n(self):
        return self.Rn

    @property
    def t(self):
        return self.Rt
    
    @property
    def index(self):
        return True

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def imm32(self):
        return self.imm5 << 2


class LDRImmT2(ctypes.LittleEndianStructure):
    """struct for ldr (imm) T2 encoding
    see Section A7.7.42
    """
    _pack_ = 1
    _fields_ = [
        ('imm8', ctypes.c_uint16, 8),
        ('Rt',   ctypes.c_uint16, 3),
        ('op',   ctypes.c_uint16, 5),
    ]

    @property
    def valid(self):
        return self.op == 0b10011

    @property
    def load_size(self):
        return 4

    @property
    def n(self):
        return 13

    @property
    def t(self):
        return self.Rt

    @property
    def index(self):
        return True 

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def imm32(self):
        return self.imm8 << 2


class LDRImmT3(ctypes.LittleEndianStructure):
    """struct for ldr (imm) T3 encoding
    and ldrb (imm) T2 encoding
    and ldrh (imm) T2 encoding
    see Section A7.7.42 (ldr)
    see Section A7.7.45 (ldrb)
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',    ctypes.c_uint32, 4),
        ('op',    ctypes.c_uint32, 12),
        ('imm12', ctypes.c_uint32, 12),
        ('Rt',    ctypes.c_uint32, 4),
    ]

    @property
    def valid(self):
        return (( # ldr
                self.op == 0b111110001101 
            ) or ( # ldrb
                self.op == 0b111110001001 
                and self.Rt != 0xF
            ) or ( # ldrh
                self.op == 0b111110001011
                and self.Rt != 0xF
            )) and ( self.Rn != 0xF )

    @property
    def load_size(self):
        if self.op == 0b111110001101: 
            return 4 # ldr
        elif self.op == 0b111110001011:
            return 2 # ldrh
        elif self.op == 0b111110001001:
            return 1 # ldrb

    @property
    def n(self):
        return self.Rn

    @property
    def t(self):
        return self.Rt

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def imm32(self):
        return self.imm12


class LDRImmT4(ctypes.LittleEndianStructure):
    """struct for ldr(t) (imm) T4 encoding
    also for ldrb(t) (imm) T3 encoding
    also for ldrh(t) (imm) T3 encoding
    see Section A7.7.42
    see Section A7.7.45
    see Section A7.7.54
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',   ctypes.c_uint32, 4),
        ('op',   ctypes.c_uint32, 12),
        ('imm8', ctypes.c_uint32, 8),
        ('W',    ctypes.c_uint32, 1),
        ('U',    ctypes.c_uint32, 1),
        ('P',    ctypes.c_uint32, 1),
        ('op2',  ctypes.c_uint32, 1),
        ('Rt',   ctypes.c_uint32, 4),
    ]

    @property
    def valid(self):
        return (( # ldr
                self.op == 0b111110000101
                and self.op2 
                and self.Rn != 0xF # LDR literal
            # ) and not ( # pop instruction
            #     self.Rn == 0b1101 
            #     and self.P == 0 
            #     and self.U == 1 
            #     and self.W == 1 
            #     and self.imm8 == 0b100
            ) and not ( # undefined
                self.P == 0 
                and self.W == 0
        )) or (( # ldrb
                self.op == 0b111110000001
                and self.Rn != 0xF # LDRB literal
            ) and not ( # pld (imm) instruction
                self.Rt == 0b1111
                and self.P == 1
                and self.U == 0
                and self. W == 0
            ) and not ( # undefined
                self.P == 0
                and self.W == 0
        )) or (( # ldrh
                self.op == 0b111110000011
                and self.Rn != 0xF # LDRH literal
            ) and not ( # pld instruction
                self.Rt == 0xF
                and self.P == 1
                and self.U == 0
                and self. W== 0
            ) and not ( # undefined
                self.P == 0
                and self.W == 0
        ))

    @property
    def load_size(self):
        if self.op == 0b111110000101:
            return 4 # ldr
        elif self.op == 0b111110000011:
            return 2
        elif self.op == 0b111110000001:
            return 1 # ldrb

    @property
    def n(self):
        return self.Rn

    @property
    def t(self):
        return self.Rt

    @property
    def index(self):
        return self.P

    @property
    def add(self):
        return self.U

    @property
    def wback(self):
        return self.W

    @property
    def imm32(self):
        return self.imm8


class LDRImm(ctypes.Union):
    """class for ldr(t) (imm) instructions
    see Section A7.7.[42, 45, 54, 66, 48, 57]
    """
    _pack_ = 1
    _fields_ = [
        ('T1',  LDRImmT1),
        ('T2',  LDRImmT2),
        ('T3',  LDRImmT3),
        ('T4',  LDRImmT4),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) <= 4, "LDR is 2 bytes or 4 bytes"
            if len(val) < 4:
                val += b'\x00' * (4 - len(val))
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)

    @property
    def enc(self):
        for enc in ['T1', 'T2', 'T3', 'T4']:
            if getattr(self, enc).valid:
                return getattr(self, enc)

    @property
    def index(self):
        return self.enc.index

    @property
    def add(self):
        return self.enc.add

    @property
    def valid(self):
        return bool(self.enc)

    @property
    def load_size(self):
        return self.enc.load_size

    def address(self, uc : Type[Uc]):
        Rn = uc.reg_read(UC_REG_MAP[self.enc.n])
        offset_addr = (Rn + (self.enc.imm32 if self.enc.add else -self.enc.imm32))
        return offset_addr if self.enc.index else Rn

    
class LDRLitT1(ctypes.LittleEndianStructure):
    """struct for ldr (literal) T1 encoding
    see Section A.7.743
    """
    _pack_ = 1
    _fields_ = [
        ('imm8', ctypes.c_uint16, 8),
        ('Rt',   ctypes.c_uint16, 3),
        ('op',   ctypes.c_uint16, 5),
    ]

    @property
    def valid(self):
        return self.op == 0b01001

    @property
    def t(self):
        return self.Rt

    @property
    def add(self):
        return True

    @property
    def load_size(self):
        return 4

    @property
    def imm32(self):
        return self.imm8 << 2


class LDRLitT2(ctypes.LittleEndianStructure):
    """struct for ldr (literal) T2 encoding
    also for ldrb (literal) T1 encoding
    also for ldrh (literal) T1 encoding
    see Section A7.7.43
    see Section A7.7.46
    see Section A7.7.55
    """
    _pack_ = 1
    _fields_ = [
        ('op0',   ctypes.c_uint32, 7),
        ('U',     ctypes.c_uint32, 1),
        ('op1',   ctypes.c_uint32, 8),
        ('imm12', ctypes.c_uint32, 12),
        ('Rt',    ctypes.c_uint32, 4),
    ]

    @property
    def valid(self):
        return ( # ldr
                self.op0 == 0x5F and self.op1 == 0xF8
            ) or ( # ldrb
                self.op0 == 0x1F and self.op1 == 0xF8
                and self.Rt != 0xF # pld instruction
            ) or ( # ldrh
                self.op0 == 0x3F and self.op1 == 0xF8
                and self.Rt != 0xF # pld literal
            )

    @property
    def load_size(self):
        if self.op0 == 0x5F:
            return 4 # ldr
        elif self.op0 == 0x3F:
            return 2 # ldrh
        elif self.op0 == 0x1F:
            return 1 # ldrb

    @property
    def t(self):
        return self.Rt

    @property
    def add(self):
        return self.U == 1

    @property
    def imm32(self):
        return self.imm12


class LDRLit(ctypes.Union):
    """union class for ldr (literal) instruction
    see Section A7.7.43
    """
    _pack_ = 1
    _fields_ = [
        ('T1', LDRLitT1),
        ('T2', LDRLitT2),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) <= 4, "LDR is 2 or 4 bytes"
            if len(val) < 4:
                val += b'\x00' * (4 - len(val))
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)

    @property
    def enc(self):
        for enc in ['T1', 'T2']:
            if getattr(self, enc).valid:
                return getattr(self, enc)

    @property
    def load_size(self):
        return self.enc.load_size

    @property
    def valid(self):
        return bool(self.enc)

    @property
    def add(self):
        return self.enc.add

    @property
    def imm32(self):
        return self.enc.imm32

    @property
    def load_size(self):
        return self.enc.load_size

    def address(self, uc : Type[Uc]):
        base = uc.reg_read(UC_ARM_REG_PC)
        base = ((base // 4) + 1) * 4 # word align
        return base + (self.imm32 if self.add else -self.imm32)


class LDRRegT1(ctypes.LittleEndianStructure):
    """struct for ldr (reg) T1 encoding
    also for ldrb (reg) T1 encoding
    also for ldrb (reg) T1 encoding
    see Section A7.7.44
    see Section A7.7.47
    see Section A7.7.56
    """
    _pack_ = 1
    _fields_ = [
        ('Rt', ctypes.c_uint16, 3),
        ('Rn', ctypes.c_uint16, 3),
        ('Rm', ctypes.c_uint16, 3),
        ('op', ctypes.c_uint16, 7),
    ]

    @property
    def valid(self):
        return ( # ldr
                self.op == 0b0101100
            ) or ( # ldrb
                self.op == 0b0101110
            ) or ( # ldrh
                self.op == 0b0101101
            )

    @property
    def load_size(self):
        if self.op == 0b0101100:
            return 4 # ldr
        elif self.op == 0b0101101:
            return 2 # ldrh
        elif self.op == 0b0101110:
            return 1 # ldrb

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def shift_n(self):
        return 0


class LDRRegT2(ctypes.LittleEndianStructure):
    """struct for ldr (reg) T2 encoding
    see Section A7.7.44
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',   ctypes.c_uint32, 4),
        ('op0',  ctypes.c_uint32, 12),
        ('Rm',   ctypes.c_uint32, 4),
        ('imm2', ctypes.c_uint32, 2),
        ('op1',  ctypes.c_uint32, 6),
        ('Rt',   ctypes.c_uint32, 4),
    ]

    @property
    def valid(self):
        return ( # ldr
                self.op0 == 0b111110000101
                and self.op1 == 0
                and self.Rn != 0xF
            ) or ( # ldrb
                self.op0 == 0b111110000001
                and self.op1 == 0
                and self.Rn != 0xF # ldrb (literal)
                and self.Rt != 0xF # pld
            ) or ( # ldrh
                self.op0 == 0b111110000011
                and self.op1 == 0
                and self.Rn != 0xF # ldrh (literal)
                and self.Rt != 0xF # related
            )

    @property
    def load_size(self):
        if self.op0 == 0b111110000101:
            return 4 # ldr
        elif self.op0 == 0b111110000001:
            return 1 # ldrb

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def shift_n(self):
        return self.imm2


class LDRReg(ctypes.Union):
    """union class for ldr (reg) instructions
    see Section A7.7.44
    """
    _pack_ = 1
    _fields_ = [
        ('T1', LDRRegT1),
        ('T2', LDRRegT2),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) <= 4, "LDR is 2 or 4 bytes"
            if len(val) < 4:
                val += b'\x00' * (4 - len(val))
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)

    @property
    def enc(self):
        for enc in ['T1', 'T2']:
            if getattr(self, enc).valid:
                return getattr(self, enc)

    @property
    def valid(self):
        return bool(self.enc)

    @property
    def add(self):
        return self.enc.add

    @property
    def index(self):
        return self.enc.index

    @property
    def shift_n(self):
        return self.enc.shift_n

    @property
    def load_size(self):
        return self.enc.load_size

    def address(self, uc : Type[Uc]):
        Rm = uc.reg_read(UC_REG_MAP[self.enc.Rm])
        if Rm & 0x80000000:
            Rm = -((Rm ^ 0xFFFFFFFF) + 1)
        offset = Rm << self.shift_n
        offset_addr = uc.reg_read(UC_REG_MAP[self.enc.Rn]) + (
            offset if self.add else -offset)
        return offset_addr if self.index else uc.reg_read(UC_REG_MAP[self.enc.Rn])


class ThumbLDR(ctypes.Union):
    """a union class for the ldr instruction (all encodings)
    see Sections A7.7.[42-44]
    """
    _pack_ = 1
    _fields_ = [
        ('imm', LDRImm),
        ('lit', LDRLit),
        ('reg', LDRReg),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) <= 4, "LDR is 2 or 4 bytes"
            if len(val) < 4:
                val += b'\x00' * (4 - len(val))
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)
        self.enc = None
        for enc in ['imm', 'lit', 'reg']:
            if getattr(self, enc).valid:
                self.enc = getattr(self, enc)
                break

    @property
    def valid(self):
        return bool(self.enc)

    @property
    def load_size(self):
        return self.enc.load_size

    def address(self, uc : Type[Uc]):
        return self.enc.address(uc)


class LDMT1(ctypes.LittleEndianStructure):
    """struct for ldm/ldmia/ldmfd T1 encoding
    see Section A7.7.40
    """
    _pack_ = 1
    _fields_ = [
        ('reglist', ctypes.c_uint16, 8),
        ('Rn',      ctypes.c_uint16, 3),
        ('op',      ctypes.c_uint16, 5),
    ]

    @property
    def valid(self):
        return self.op == 0b11001

    @property
    def n(self):
        return self.Rn

    @property
    def regs(self):
        return self.reglist

    @property
    def wback(self):
        return (self.reglist & (1 << self.Rn)) == 0


class LDMT2(ctypes.LittleEndianStructure):
    """struct for ldm/ldmia/ldmfd T2 encoding
    see Section A7.7.40
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',      ctypes.c_uint32, 4),
        ('op',      ctypes.c_uint32, 12),
        ('reglist', ctypes.c_uint32, 16),
    ]

    @property
    def valid(self):
        return (
                (self.op & (~2)) == 0b111010001001
            and not ( # pop instruction
                (self.op & 2) == 2
                and self.Rn == 0b1101
            ))

    @property
    def n(self):
        return self.Rn

    @property
    def regs(self):
        return self.reglist

    @property
    def wback(self):
        return (self.op & 2) == 2


class ThumbLDM(ctypes.Union):
    """union class for ldm instruction
    see Section A7.7.40
    """
    _pack_ = 1
    _fields_ = [
        ('T1', LDMT1),
        ('T2', LDMT2),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) <= 4, "LDM is 2 or 4 bytes"
            if len(val) < 4:
                val += b'\x00' * (4 - len(val))
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)
        self.enc = None
        for enc in ['T1', 'T2']:
            if getattr(self, enc).valid:
                self.enc = getattr(self, enc)
                break

    @property
    def valid(self):
        return bool(self.enc)

    def addresses(self, uc : Type[Uc]):
        Rn = uc.reg_read(UC_REG_MAP[self.enc.n])
        return [Rn + (i * 4) for i in range(15) if self.enc.regs & (1 << i)]

    @property
    def num_regs(self):
        return bin(self.enc.regs).count('1')


class LDRDImm(ctypes.LittleEndianStructure):
    """struct for ldrd instruction (A7.7.49)"""
    _pack_ = 1
    _fields_ = [
        ('Rn',   ctypes.c_uint32, 4),
        ('op',   ctypes.c_uint32, 12),
        ('imm8', ctypes.c_uint32, 8),
        ('Rt2',  ctypes.c_uint32, 4),
        ('Rt',   ctypes.c_uint32, 4),
    ]

    @property
    def P(self):
        return int(bool(self.op & 0x10))

    @property
    def U(self):
        return int(bool(self.op & 0x8))

    @property
    def W(self):
        return int(bool(self.op & 0x2))

    @property
    def valid(self):
        return (
            (self.op & 0xFE5) == 0b111010000101
            and not (self.P == 0 and self.W == 0)
            and self.Rn != 0xF
        )

    @property
    def t(self):
        return self.Rt

    @property
    def t2(self):
        return self.Rt2

    @property
    def n(self):
        return self.Rn

    @property
    def index(self):
        return self.P

    @property
    def add(self):
        return self.U

    @property
    def wback(self):
        return self.W

    @property
    def imm32(self):
        return self.imm8 << 2

    @property
    def load_size(self):
        return 8

    def addresses(self, uc : Type[Uc]):
        Rn = uc.reg_read(UC_REG_MAP[self.n])
        offset_addr = Rn + (self.imm32 if self.add else -self.imm32)
        return [offset_addr, offset_addr + 4] if self.index else [Rn, Rn + 4]


class LDRDLit(ctypes.LittleEndianStructure):
    """struct for ldrd instruction (A7.7.50)"""
    _pack_ = 1
    _fields_ = [
        ('op',   ctypes.c_uint32, 16),
        ('imm8', ctypes.c_uint32, 8),
        ('Rt2',  ctypes.c_uint32, 4),
        ('Rt',   ctypes.c_uint32, 4),
    ]

    @property
    def P(self):
        return int(bool(self.op & 0x100))

    @property
    def U(self):
        return int(bool(self.op & 0x80))

    @property
    def W(self):
        return int(bool(self.op & 0x20))

    @property
    def valid(self):
        return (
            (self.op & 0xFE5F) == 0b1110100001011111
            and not (self.P == 0 and self.W == 0)
        )

    @property
    def t(self):
        return self.Rt

    @property
    def t2(self):
        return self.Rt2

    @property
    def n(self):
        return self.Rn

    @property
    def index(self):
        return self.P

    @property
    def add(self):
        return self.U

    @property
    def wback(self):
        return self.W

    @property
    def imm32(self):
        return self.imm8 << 2

    @property
    def load_size(self):
        return 8

    def addresses(self, uc : Type[Uc]):
        pc = uc.reg_read(UC_ARM_REG_PC)
        return pc + (self.imm32 if self.add else -self.imm32)


class ThumbLDRD(ctypes.Union):
    """union class for ldrd instruction"""
    _pack_ = 1
    _fields_ = [
        ('imm', LDRDImm),
        ('lit', LDRDLit),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 4, "ldrd is 4 bytes"
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)
        self.enc = None
        for e in ['imm', 'lit']:
            if getattr(self, e).valid:
                self.enc = getattr(self, e)
                break

    def addresses(self, uc : Type[Uc]):
        return self.enc.addresses(uc)

###########################################################
## STORE INSTRUCTIONS
###########################################################


class STRImmT1(ctypes.LittleEndianStructure):
    """struct for str (imm) T1 encoding (A7.7.158)
    also for strb (imm) T1 encoding (A7.7.160)
    also for strh (imm) T1 encoding (A7.7.167)
    """
    _pack_ = 1
    _fields_ = [
        ('Rt',   ctypes.c_uint16, 3),
        ('Rn',   ctypes.c_uint16, 3),
        ('imm5', ctypes.c_uint16, 5),
        ('op',   ctypes.c_uint16, 5),
    ]

    @property
    def valid(self):
        return (( # str (imm)
                self.op == 0b01100
            ) or ( # strb
                self.op == 0b01110
            ) or ( # strh
                self.op == 0b10000
        ))

    @property
    def size(self):
        if self.op == 0b01100:
            return 4 # str
        elif self.op == 0b10000:
            return 2 # strh
        elif self.op == 0b01110:
            return 1 # strb

    @property
    def t(self):
        return self.Rt

    @property
    def n(self):
        return self.Rn

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def imm32(self):
        if self.op == 0b01100:
            return self.imm5 << 2
        elif self.op == 0b10000:
            return self.imm5 << 1
        elif self.op == 0b01110:
            return self.imm5


class STRImmT2(ctypes.LittleEndianStructure):
    """struct for str (imm) T2 encoding
    see Section A7.7.158
    """
    _pack_ = 1
    _fields_ = [
        ('imm8', ctypes.c_uint16, 8),
        ('Rt',   ctypes.c_uint16, 3),
        ('op',   ctypes.c_uint16, 5),
    ]

    @property
    def valid(self):
        return (( # str (imm)
                self.op == 0b10010
        ))

    @property
    def size(self):
        if self.op == 0b10010:
            return 4

    @property
    def t(self):
        return self.Rt

    @property
    def n(self):
        return 13

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def imm32(self):
        return self.imm8 << 2


class STRImmT3(ctypes.LittleEndianStructure):
    """struct for str (imm) T3 encoding (A7.7.158)
    also for strb (imm) T2 encoding (A7.7.160)
    also for strh (imm) T2 encoding (A7.7.167)
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',    ctypes.c_uint32, 4),
        ('op',    ctypes.c_uint32, 12),
        ('imm12', ctypes.c_uint32, 12),
        ('Rt',    ctypes.c_uint32, 4),
    ]

    @property
    def valid(self):
        return (( # str
                self.op == 0b111110001100
                and self.Rn != 0xF # undefined
            ) or ( # strb
                self.op == 0b111110001000
                and self.Rn != 0xF # undefined
            ) or ( # strh
                self.op == 0b111110001010
                and self.Rn != 0xF # undefined
        ))

    @property
    def size(self):
        if self.op == 0b111110001100:
            return 4
        elif self.op == 0b111110001010:
            return 2
        elif self.op == 0b111110001000:
            return 1

    @property
    def t(self):
        return self.Rt

    @property
    def n(self):
        return self.Rn

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True

    @property
    def wback(self):
        return False

    @property
    def imm32(self):
        return self.imm12


class STRImmT4(ctypes.LittleEndianStructure):
    """struct for str(t) (imm) T4 encoding (A7.7.158)
    also for strb(t) T3 encoding (A7.7.160)
    also for strh(t) T3 encoding (A7.7.167)
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',   ctypes.c_uint32, 4),
        ('op',   ctypes.c_uint32, 12),
        ('imm8', ctypes.c_uint32, 8),
        ('W',    ctypes.c_uint32, 1),
        ('U',    ctypes.c_uint32, 1),
        ('P',    ctypes.c_uint32, 1),
        ('b1',   ctypes.c_uint32, 1),
        ('Rt',   ctypes.c_uint32, 4),
    ]

    @property
    def valid(self):
        return (( # str (imm)
                self.op == 0b111110000100
                and self.b1 == 1
                and not ( # undefined
                    self.Rn == 0xF
                    or (self.P == 0 and self.W == 0)
                )
            ) or ( # strb
                self.op == 0b111110000000
                and self.b1 == 1
                and not ( # undefined
                    self.Rn == 0xF
                    or (self.P == 0 and self.W == 0)
                )
            ) or ( # strh
                self.op == 0b111110000010
                and self.b1 == 1
                and not ( # undefined
                    self.Rn == 0xF
                    or (self.P == 0 and self.W == 0)
                )
        ))

    @property
    def size(self):
        if self.op == 0b111110000100:
            return 4
        elif self.op == 0b111110000010:
            return 2
        elif self.op == 0b111110000000:
            return 1

    @property
    def t(self):
        return self.Rt

    @property
    def n(self):
        return self.Rn

    @property
    def index(self):
        return self.P == 1

    @property
    def add(self):
        return self.U == 1

    @property
    def wback(self):
        return self.W == 1

    @property
    def imm32(self):
        return self.imm8


class STRImm(ctypes.Union):
    """union class for str(hb) (imm)"""
    _pack_ = 1
    _fields_ = [
        ('T1', STRImmT1),
        ('T2', STRImmT2),
        ('T3', STRImmT3),
        ('T4', STRImmT4),
    ]

    @property
    def enc(self):
        for enc in ['T1', 'T2', 'T3', 'T4']:
            if getattr(self, enc).valid:
                return getattr(self, enc)

    @property
    def valid(self):
        return bool(self.enc)

    def address(self, uc : Type[Uc]):
        enc = self.enc
        if enc:
            Rn = uc.reg_read(UC_REG_MAP[enc.n])
            offset_addr = Rn + (enc.imm32 if enc.add else -enc.imm32)
            return offset_addr if enc.index else Rn


class STRRegT1(ctypes.LittleEndianStructure):
    """struct for str (reg) T1 encoding (A7.7.159)
    also for strb (reg) T1 encoding (A7.7.161)
    also for strh (reg) T1 encoding (A7.7.168)
    """
    _pack_ = 1
    _fields_ = [
        ('Rt',  ctypes.c_uint16, 3),
        ('Rn',  ctypes.c_uint16, 3),
        ('Rm',  ctypes.c_uint16, 3),
        ('op',  ctypes.c_uint16, 7),
    ]

    @property
    def valid(self):
        return (( # str
                self.op == 0b0101000
            ) or (
                self.op == 0b0101010
            ) or (
                self.op == 0b0101001
        ))

    @property
    def size(self):
        if self.op == 0b0101000:
            return 4
        elif self.op == 0b0101001:
            return 2
        elif self.op == 0b0101010:
            return 1

    @property
    def t(self):
        return self.Rt

    @property
    def n(self):
        return self.Rn

    @property
    def m(self):
        return self.Rm

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True 

    @property
    def wback(self):
        return False

    @property
    def shift_n(self):
        return 0


class STRRegT2(ctypes.LittleEndianStructure):
    """struct for str (reg) T2 encoding (A7.7.159)
    also for strb (reg) T2 encoding (A7.7.161)
    also for strh (reg) T2 encoding (A7.7.168)
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',   ctypes.c_uint32, 4),
        ('op0',  ctypes.c_uint32, 12),
        ('Rm',   ctypes.c_uint32, 4),
        ('imm2', ctypes.c_uint32, 2),
        ('op1',  ctypes.c_uint32, 6),
        ('Rt',   ctypes.c_uint32, 4),
    ]

    @property
    def valid(self):
        return (( # str
                self.op0 == 0b111110000100
                and self.op1 == 0
                and self.Rn != 0xF # undefined
            ) or (
                self.op0 == 0b111110000000
                and self.op1 == 0
                and self.Rn != 0xF # undefined
            ) or (
                self.op0 == 0b111110000010
                and self.op1 == 0
                and self.Rn != 0xF # undefined
        ))

    @property
    def size(self):
        if self.op0== 0b111110000100:
            return 4
        elif self.op0 == 0b111110000010:
            return 2
        elif self.op0 == 0b111110000000:
            return 1

    @property
    def t(self):
        return self.Rt

    @property
    def n(self):
        return self.Rn

    @property
    def m(self):
        return self.Rm

    @property
    def index(self):
        return True

    @property
    def add(self):
        return True 

    @property
    def wback(self):
        return False

    @property
    def shift_n(self):
        return self.imm2


class STRReg(ctypes.Union):
    """union class for str(hb) (reg)"""
    _pack_ = 1
    _fields_ = [
        ('T1', STRRegT1),
        ('T2', STRRegT2),
    ]

    @property
    def enc(self):
        for enc in ['T1', 'T2']:
            if getattr(self, enc).valid:
                return getattr(self, enc)

    @property
    def valid(self):
        return bool(self.enc)

    def address(self, uc : Type[Uc]):
        enc = self.enc
        if enc:
            Rm = uc.reg_read(UC_REG_MAP[enc.m])
            if Rm & 0x80000000:
                Rm = (Rm ^ 0xFFFFFFFF) + 1
            offset = Rm << enc.shift_n
            return uc.reg_read(UC_REG_MAP[enc.n]) + offset


class ThumbSTR(ctypes.Union):
    """union class for str instructions"""
    _pack_ = 1
    _fields_ = [
        ('imm', STRImm),
        ('reg', STRReg),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) <= 4, "Thumb is 2 or 4 bytes"
            val += b'\x00' * (4 - len(val))
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)
        self.enc = None
        for e in ['imm', 'reg']:
            if getattr(self, e).valid:
                self.enc = getattr(self, e)
                break
    
    @property
    def valid(self):
        return bool(self.enc)

    @property
    def size(self):
        return self.enc.enc.size

    def address(self, uc : Type[Uc]):
        return self.enc.address(uc)

    def access(self, uc : Type[Uc]):
        Rt = uc.reg_read(UC_REG_MAP[self.enc.enc.t])
        mask = int.from_bytes(b'\xff' * self.enc.enc.size, 'little')
        return {
            self.enc.address(uc): Rt & mask
        }


class STMT1(ctypes.LittleEndianStructure):
    """struct for stm T1 encoding (A7.7.156)
    """
    _pack_ = 1
    _fields_ = [
        ('reglist', ctypes.c_uint16, 8),
        ('Rn',      ctypes.c_uint16, 3),
        ('op',      ctypes.c_uint16, 5),
    ]

    @property
    def valid(self):
        return self.op == 0b11000

    @property
    def n(self):
        return self.Rn

    @property
    def regs(self):
        return [i for i in range(8) if self.reglist & (1 << i)]

    @property
    def wback(self):
        return True


class STMT2(ctypes.LittleEndianStructure):
    """struct for stm T2 encoding (A7.7.156)
    """
    _pack_ = 1
    _fields_ = [
        ('Rn',      ctypes.c_uint32, 4),
        ('op',      ctypes.c_uint32, 12),
        ('reglist', ctypes.c_uint32, 16),
    ]

    @property
    def valid(self):
        return (self.op & ~2) == 0b111010001000

    @property
    def n(self):
        return self.Rn

    @property
    def regs(self):
        return [i for i in range(16) \
            if self.reglist & (1 << i) and i not in [13, 15]]

    @property
    def wback(self):
        return bool(self.op0 & 2)


class ThumbSTM(ctypes.Union):
    """union class for stm instruction"""
    _pack_ = 1
    _fields_ = [
        ('T1', STMT1),
        ('T2', STMT2),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) <= 4, "Thumb is 2 or 4 bytes"
            val += b'\x00' * (4 - len(val))
            return cls.from_buffer_copy(val)
        else:
            return super().__init__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)

    @property
    def enc(self):
        for e in ['T1', 'T2']:
            if getattr(self, e).valid:
                return getattr(self, e)

    @property
    def regs(self):
        return self.enc.regs

    def addresses(self, uc : Type[Uc]):
        base = uc.reg_read(UC_REG_MAP[self.enc.n])
        return [base + (i * 4) for i in range(len(self.regs))]

    def accesses(self, uc : Type[Uc]):
        base = uc.reg_read(UC_REG_MAP[self.enc.n])
        return {
            base + (i * 4): uc.reg_read(UC_REG_MAP[r]) \
                for i, r in enumerate(self.regs)
        }


class ThumbSTRD(ctypes.LittleEndianStructure):
    """struct for ldrd instruction (A7.7.163)"""
    _pack_ = 1
    _fields_ = [
        ('Rn',   ctypes.c_uint32, 4),
        ('op',   ctypes.c_uint32, 12),
        ('imm8', ctypes.c_uint32, 8),
        ('Rt2',  ctypes.c_uint32, 4),
        ('Rt',   ctypes.c_uint32, 4),
    ]

    def __new__(cls, val : Union[int, bytes, bytearray]):
        if isinstance(val, (bytes, bytearray)):
            assert len(val) == 4, "strd is 4 bytes"
            return cls.from_buffer_copy(val)
        else:
            return super().__new__(cls)

    def __init__(self, val : Union[int, bytes, bytearray]):
        if isinstance(val, int):
            val &= 0xFFFFFFFF
            struct.pack_into('I', self, 0, val)
        self.P = (self.op >> 4) & 1
        self.U = (self.op >> 3) & 1
        self.W = (self.op >> 1) & 1

    @property
    def valid(self):
        return (
            (self.op & 0xFE5) == 0b111010000100
            and not (self.P == 0 and self.W)
        )

    @property
    def imm32(self):
        return self.imm8 << 2

    def addresses(self, uc : Type[Uc]):
        Rn = uc.reg_read(UC_REG_MAP[self.Rn])
        offset_addr = Rn + (self.imm32 if self.U else -self.imm32)
        return [offset_addr, offset_addr + 4] if self.P else [Rn, Rn + 4]

    def accesses(self, uc : Type[Uc]):
        Rn = uc.reg_read(UC_REG_MAP[self.Rn])
        offset_addr = Rn + (self.imm32 if self.U else -self.imm32)
        address = offset_addr if self.P else Rn
        return {
            address: uc.reg_read(UC_REG_MAP[self.Rt]),
            address + 4: uc.reg_read(UC_REG_MAP[self.Rt2])
        }