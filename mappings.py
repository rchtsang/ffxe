from unicorn import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm_const import *

UC_REG_MAP = [
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_R13,
    UC_ARM_REG_R14,
    UC_ARM_REG_R15,
]

REGS = {
    UC_ARM_REG_APSR  : "APSR",
    UC_ARM_REG_IPSR  : "IPSR",
    UC_ARM_REG_CPSR  : "CPSR",
    UC_ARM_REG_LR    : "LR",
    UC_ARM_REG_PC    : "PC",
    UC_ARM_REG_SP    : "SP",
    UC_ARM_REG_R0    : "R0",
    UC_ARM_REG_R1    : "R1",
    UC_ARM_REG_R2    : "R2",
    UC_ARM_REG_R3    : "R3",
    UC_ARM_REG_R4    : "R4",
    UC_ARM_REG_R5    : "R5",
    UC_ARM_REG_R6    : "R6",
    UC_ARM_REG_R7    : "R7",
    UC_ARM_REG_R8    : "R8",
    UC_ARM_REG_R9    : "R9",
    UC_ARM_REG_R10   : "R10",
    UC_ARM_REG_R11   : "R11",
    UC_ARM_REG_R12   : "R12",
}