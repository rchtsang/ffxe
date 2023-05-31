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

# ARM interrupt/exception codes for hook_intr
EXCP_UDEF           =  1    # undefined instruction
EXCP_SWI            =  2    # software interrupt
EXCP_PREFETCH_ABORT =  3
EXCP_DATA_ABORT     =  4
EXCP_IRQ            =  5
EXCP_FIQ            =  6
EXCP_BKPT           =  7
EXCP_EXCEPTION_EXIT =  8    # Return from v7M exception. 
EXCP_KERNEL_TRAP    =  9    # Jumped to kernel code page. 
EXCP_HVC            = 11    # HyperVisor Call
EXCP_HYP_TRAP       = 12
EXCP_SMC            = 13    # Secure Monitor Call
EXCP_VIRQ           = 14
EXCP_VFIQ           = 15
EXCP_SEMIHOST       = 16    # semihosting call
EXCP_NOCP           = 17    # v7M NOCP UsageFault
EXCP_INVSTATE       = 18    # v7M INVSTATE UsageFault
EXCP_STKOF          = 19    # v8M STKOF UsageFault
EXCP_LAZYFP         = 20    # v7M fault during lazy FP stacking
EXCP_LSERR          = 21    # v8M LSERR SecureFault
EXCP_UNALIGNED      = 22    # v7M UNALIGNED UsageFault