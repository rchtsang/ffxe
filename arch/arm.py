import ctypes
import struct
from typing import Union, Type
from ctypes import memmove, pointer, sizeof

import capstone as CS
from unicorn import *
from unicorn.arm_const import *

from mappings import *
from arch.armv7e import *

"""
wrapper objects for capstone instructions
"""

###########################################################
## BRANCH INSTRUCTIONS
###########################################################

class ArmBL():
    __slots__ = ['cs_insn']

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn

    @property
    def bytevalue(self):
        return self.cs_insn.bytes

    @property
    def value(self):
        return int.from_bytes(self.cs_insn.bytes, 'little')

    @property
    def imm32(self):
        return self.cs_insn.op_find(ARM_OP_IMM, 1).imm - 8


class ArmBranch():
    __slots__ = ['cs_insn']

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn

    @property
    def enc(self):
        return 'A1'

    @property
    def bytevalue(self):
        return self.cs_insn.bytes

    @property
    def value(self):
        return int.from_bytes(self.cs_insn.bytes, 'little')

    @property
    def imm32(self):
        return self.cs_insn.op_find(ARM_OP_IMM, 1).imm - 8


###########################################################
## LOAD INSTRUCTIONS
###########################################################

class ArmLDR():
    __slots__ = ['cs_insn', 'valid', 'load_size']
    LDR_IDS = [
        ARM_INS_LDR,
        ARM_INS_LDRH,
        ARM_INS_LDRB,
        ARM_INS_LDRT,
        ARM_INS_LDRHT,
        ARM_INS_LDRBT,
    ] 

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn
        self.valid = cs_insn.id in self.LDR_IDS
        match cs_insn.id:
            case CS.arm_const.ARM_INS_LDRB | CS.arm_const.ARM_INS_LDRBT:
                self.load_size = 1
            case CS.arm_const.ARM_INS_LDRH | CS.arm_const.ARM_INS_LDRHT:
                self.load_size = 2
            case CS.arm_const.ARM_INS_LDR  | CS.arm_const.ARM_INS_LDRT:
                self.load_size = 4
            case _ :
                raise Exception("Wrong instruction type: {}".format(cs_insn.id))

    @property
    def enc(self):
        return 'A1'

    def address(self, uc : Type[Uc]):
        mem_op = self.cs_insn.op_find(ARM_OP_MEM, 1)
        if mem_op.mem.index:
            # register-based offset
            assert mem_op.shift.type == 2, \
                "shift type is not lsl"
            abs_offset = uc.reg_read(mem_op.mem.index) << mem_op.shift.value
            offset = -abs_offset if mem_op.subtracted else abs_offset
        else:
            # immediate offset
            offset = mem_op.mem.disp
        address = uc.reg_read(mem_op.mem.base) + offset
        return address


class ArmLDRD():
    __slots__ = ['cs_insn', 'valid', 'load_size']

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn
        self.valid = cs_insn.id == ARM_INS_LDRD
        self.load_size = 8

    @property
    def enc(self):
        return 'A1'

    def addresses(self, uc : Type[Uc]):
        mem_op = self.cs_insn.op_find(ARM_OP_MEM, 1)
        if mem_op.mem.index:
            # register based offset
            abs_offset = uc.reg_read(mem_op.mem.index)
            offset = -abs_offset if mem_op.subtracted else abs_offset
        else:
            offset = mem_op.mem.disp
        address = uc.reg_read(mem_op.mem.base) + offset
        return [address, address + 4]


# note: capstone recognizes POP as a separate instruction,
# not a special case of the LDM instruction
class ArmLDM():
    __slots__ = ['cs_insn', 'valid', 'regs']

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn
        self.valid = cs_insn.id == ARM_INS_LDM
        self.regs = [op.reg for op in cs_insn.operands if op.access & CS_AC_WRITE]

    @property
    def enc(self):
        return 'A1'

    @property
    def writes_pc(self):
        return ARM_REG_PC in self.regs

    @property    
    def num_regs(self):
        return len(self.regs)

    def addresses(self, uc : Type[Uc]):
        base_reg_op = self.cs_insn.operands[0]
        base = uc.reg_read(base_reg_op.reg)
        return [base + (i * 4) for i in range(self.num_regs)]


class ArmLDMDB():
    __slots__ = ['cs_insn', 'valid', 'regs']

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn
        self.valid = cs_insn.id == ARM_INS_LDMDB
        self.regs = [op.reg for op in cs_insn.operands if op.access & CS_AC_WRITE]

    @property
    def enc(self):
        return 'A1'

    @property
    def writes_pc(self):
        return ARM_REG_PC in self.regs

    @property
    def num_regs(self):
        return len(self.regs)

    def addresses(self, uc : Type[Uc]):
        base_reg_op = self.cs_insn.operands[0]
        base = uc.reg_read(base_reg_op.reg)
        return [base + (i * 4) for i in range(self.num_regs)]




###########################################################
## STORE INSTRUCTIONS
###########################################################

class ArmSTR():
    __slots__ = ['cs_insn', 'valid', 'size']
    STR_IDS = [
        ARM_INS_STR,
        ARM_INS_STRH,
        ARM_INS_STRB,
        ARM_INS_STRT,
        ARM_INS_STRHT,
        ARM_INS_STRBT,
    ] 

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn
        self.valid = cs_insn.id in self.STR_IDS
        match cs_insn.id:
            case CS.arm_const.ARM_INS_STRB | CS.arm_const.ARM_INS_STRBT:
                self.size = 1
            case CS.arm_const.ARM_INS_STRH | CS.arm_const.ARM_INS_STRHT:
                self.size = 2
            case CS.arm_const.ARM_INS_STR  | CS.arm_const.ARM_INS_STRT:
                self.size = 4
            case _ :
                raise Exception("Wrong instruction type: {}".format(cs_insn.id))

    @property
    def enc(self):
        return 'A1'

    def address(self, uc : Type[Uc]):
        mem_op = self.cs_insn.op_find(ARM_OP_MEM, 1)
        if mem_op.mem.index:
            # register-based offset
            # assert mem_op.shift.type == 2, \
            #     "shift type is not lsl: {}".format(mem_op)
            abs_offset = uc.reg_read(mem_op.mem.index) << mem_op.shift.value
            offset = -abs_offset if mem_op.subtracted else abs_offset
        else:
            # immediate offset
            offset = mem_op.mem.disp
        address = uc.reg_read(mem_op.mem.base) + offset
        return address

    def access(self, uc : Type[Uc]):
        reg_op = self.cs_insn.op_find(ARM_OP_REG, 1)
        write_val = uc.reg_read(reg_op.reg)
        mask = int.from_bytes(b'\xff' * self.size, 'little')
        return { 
            self.address(uc) : write_val & mask
        }        


class ArmSTRD():
    __slots__ = ['cs_insn', 'valid', 'size']

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn
        self.valid = cs_insn.id == ARM_INS_STRD
        self.size = 8

    @property
    def enc(self):
        return 'A1'

    def addresses(self, uc : Type[Uc]):
        mem_op = self.cs_insn.op_find(ARM_OP_MEM, 1)
        if mem_op.mem.index:
            # register based offset
            abs_offset = uc.reg_read(mem_op.mem.index)
            offset = -abs_offset if mem_op.subtracted else abs_offset
        else:
            offset = mem_op.mem.disp
        address = uc.reg_read(mem_op.mem.base) + offset
        return [address, address + 4]

    def accesses(self, uc : Type[Uc]):
        reg1 = self.cs_insn.op_find(ARM_OP_REG, 1).reg
        reg2 = self.cs_insn.op_find(ARM_OP_REG, 2).reg
        address = self.addresses(uc)[0]
        return {
            address : uc.reg_read(reg1),
            address + 4 : uc.reg_read(reg2),
        }


class ArmSTM():
    __slots__ = ['cs_insn', 'valid', 'regs']

    def __init__(self, cs_insn):
        self.cs_insn = cs_insn
        self.valid = cs_insn.id == ARM_INS_LDM
        self.regs = [op.reg for op in cs_insn.operands[1:]]

    @property
    def enc(self):
        return 'A1'

    @property
    def writes_pc(self):
        return ARM_REG_PC in self.regs

    @property    
    def num_regs(self):
        return len(self.regs)

    def addresses(self, uc : Type[Uc]):
        base_reg_op = self.cs_insn.operands[0]
        base = uc.reg_read(base_reg_op.reg)
        return [base + (i * 4) for i in range(self.num_regs)]

    def accesses(self, uc : Type[Uc]):
        return dict(zip(self.addresses(uc), [uc.reg_read(r) for r in self.regs]))




