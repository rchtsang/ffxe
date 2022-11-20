import os
import sys
import logging
import itertools
import traceback
from os.path import splitext
from typing import Union, Type
from copy import copy, deepcopy

import yaml
import unicorn
import elftools
import capstone

from unicorn import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm_const import *

from models import *
from inst import *
from mappings import *

def chunks(n, iterable : Union[bytes, bytearray]):
    it = iter(iterable)
    while True:
        chunk = bytes(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk

class BBlock():
    """
    A class for basic block information
    """
    def __init__(self, address, size, fn_addr, parent=None):
        self.addr = address
        self.size = size
        self.quota = 1
        self.contrib = 0
        self.fn_addr = None
        self.parents = [parent] if parent else []
        self.children = []
        self.mem_log = []
        # mem log format:
        # (inst addr, access type, value, mem addr)

    def contains(self, addr):
        if isinstance(addr, int):
            return self.addr <= addr < (self.addr + size)
        return False

    def __contains__(self, item):
        return self.contains(item)

    def accesses_mem(self):
        return len(self.mem_log)

    def __repr__(self):
        return "<efxe.BBlock @ 0x{:08X} : 0x{:08X}>".format(
            self.addr, self.addr + self.size)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.addr == other.addr
        return False

    def fmt_mem_log(self):
        return '\n'.join(["pc:0x{:x} {} 0x{:08X} @ 0x{:08X}".format(
            *entry) for entry in self.mem_log])

    def __copy__(self):
        # a basic block is unique and cannot be copied
        return self



class EmFXContext():
    """
    A Context class for implementing backup and restores of the engine
    """
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

    def __init__(self, pc, apsr, callstack, uc_context, bblock, vtentry=0):
        self.pc = pc
        self.apsr = apsr
        self.callstack = callstack
        self.uc_context = uc_context
        self.bblock = bblock
        self.mem_state = {}
        self.stack_state = b""
        self.vtentry = vtentry # is an ISR if nonzero
        self.age = 0

    def __copy__(self):
        cls = self.__class__
        result = cls.__new__(cls)
        for k, v in self.__dict__.items():
            setattr(result, k, copy(v))
        return result

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
            and self.pc == other.pc
            and self.apsr == other.apsr
            and self.bblock == other.bblock
            and self.vtentry == other.vtentry
            and self.stack_state == other.stack_state
            and self.callstack == other.callstack
            and self.mem_state == other.mem_state
            and bytes(self.uc_context) == bytes(other.uc_context))

    def log_write(self, addr, data):
        """log word writes (expect 4 byte data)"""
        self.mem_state[addr] = data



class EmFXEngine():
    """
    An Engine class for implementing forced execution on ARM Cortex-M4 Architectures
    """

    def __init__(self,
            pd         : Union[str, dict],
            mmio       : dict = None,
            fw_path    : str = None,
            log_dir    : str = 'logs',
            log_fn     : str = 'efxe.log',
            log_stdout : bool = False,
            log_insn   : bool = False):
        """
        params:
        - pd        platform description (path or dict)
        - mmio      if dict provided, use as args for mmio_map
        - fw_path   path to firmware file (elf, hex, or bin)
        """

        # setup logging
        self.logger = logging.getLogger('efxe.eng')
        self.mem_logger = logging.getLogger('efxe.mem')
        self.logger.setLevel(logging.DEBUG)
        self.mem_logger.setLevel(logging.DEBUG)
        if not os.path.isdir(log_dir):
            os.mkdir(log_dir)
        i = 2
        fn, ext = splitext(log_fn)
        while os.path.exists(f"{log_dir}/{log_fn}"):
            log_fn = f"{fn}-{i}{ext}"
            i += 1
        mem_log_fn = "{}_mem{}".format(*splitext(log_fn))
        formatter = logging.Formatter("%(asctime)s : %(message)s")
        fhandler = logging.FileHandler(f"{log_dir}/{log_fn}", mode='a')
        fhandler.setLevel(logging.DEBUG)
        fhandler.setFormatter(formatter)
        self.logger.addHandler(fhandler)
        mem_formatter = logging.Formatter("%(message)s")
        mem_fhandler = logging.FileHandler(f"{log_dir}/{mem_log_fn}", mode='a')
        mem_fhandler.setLevel(logging.DEBUG)
        mem_fhandler.setFormatter(mem_formatter)
        self.mem_logger.addHandler(mem_fhandler)
        if log_stdout:
            shandler = logging.StreamHandler(sys.stdout)
            shandler.setLevel(logging.DEBUG)
            shandler.setFormatter(formatter)
            self.logger.addHandler(shandler)
            mem_shandler = logging.StreamHandler(sys.stdout)
            mem_shandler.setLevel(logging.DEBUG)
            mem_shandler.setFormatter(formatter)
            self.mem_logger.addHandler(mem_shandler)
        self.log_insn = log_insn

        # create emulator instance
        # mode updated automatically on emu_start
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

        # create disassembler instance
        # mode updated in callbacks
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.cs.detail = 1 # enable detailed disassembly (slower)

        # platform description will be dictionary
        if isinstance(pd, str):
            if splitext(pd)[1] in ['.yml', '.yaml']:
                # load the platform description from file
                with open(pd, 'r') as pd_file:
                    pd = yaml.load(pd_file, yaml.Loader)

        assert isinstance(pd, dict), \
            "platform description is not a dictionary"
        assert 'mmap' in pd, \
            "platform description must provide 'mmap'"

        self.pd = pd

        # map memory in unicorn emulator
        for region, kwargs in self.pd['mmap'].items():
            # make everything read/write-able
            kwargs['perms'] |= 0b011
            self.uc.mem_map(**kwargs)

        # map io in unicorn emulator
        if isinstance(mmio, dict):
            # if user provided mmio argument, 
            # update the platform description and use mmio_map
            self.pd['mmio'] = mmio
            for peripheral, kwargs in mmio.items():
                self.uc.mmio_map(**kwargs)
        else:
            # if not provided, map defaults as memory
            for region, kwargs in self.pd['mmio'].items():
                self.uc.mem_map(**kwargs)

        # additional helpful instance variables
        self.stack_base = None
        self.entry = None
        self.context = EmFXContext(
            pc=None,
            apsr=APSRRegister(self.uc.reg_read(UC_ARM_REG_APSR)),
            callstack=[],
            uc_context=self.uc.context_save(),
            bblock=None
        )

        # load firmware if path provided
        self.fw = None
        if isinstance(fw_path, str):
            self.load_fw(fw_path)

        self.bblocks = {}
        self.jobs = [self.context]
        self.mem_reads = set()
        self.volatile_addrs = {}
        self.vtcontexts = {}

        # setup basic block hooks
        self.uc.hook_add(
            UC_HOOK_BLOCK,
            self._hook_block,
            begin=self.pd['mmap']['flash']['address'],
            end=self.pd['mmap']['flash']['address'] + self.pd['mmap']['flash']['size'],
            user_data={},
        )

        # setup instruction hooks
        self.uc.hook_add(
            UC_HOOK_CODE,
            self._hook_code,
            begin=self.pd['mmap']['flash']['address'],
            end=self.pd['mmap']['flash']['address'] + self.pd['mmap']['flash']['size'],
            user_data={},
        )

        # setup mem access hooks
        self.uc.hook_add(
            (UC_HOOK_MEM_READ | 
                UC_HOOK_MEM_READ_PROT |
                UC_HOOK_MEM_READ_AFTER |
                UC_HOOK_MEM_WRITE |
                UC_HOOK_MEM_WRITE_PROT),
            self._hook_mem,
            begin=0x0,
            end=0xFFFFFFFF,
            user_data={},
        )


    def load_fw(self, path):
        self.fw = FirmwareImage(path)

        # load firmware image to unicorn flash
        self.uc.mem_write(self.pd['mmap']['flash']['address'], self.fw.raw)

        # setup stack pointer and program counter
        # specific for Cortex-M4 for now
        self.stack_base = int.from_bytes(self.uc.mem_read(0x0, 4), 'little')
        self.entry = int.from_bytes(self.uc.mem_read(0x4, 4), 'little')
        self.context.pc = self.entry
        self.uc.reg_write(UC_ARM_REG_SP, self.stack_base)
        self.uc.reg_write(UC_ARM_REG_PC, self.entry)
        self.context.uc_context = self.uc.context_save()
        self.context.callstack.append((
            self.entry,                         # function address
            self.uc.reg_read(UC_ARM_REG_SP),    # frame pointer
            None,                               # return address
        ))

    def _hook_block(self, uc, address, size, user_data):
        """basic block callback"""
        # this should construct the block and add it to the 
        # block list if never seen before
        # otherwise check the block quota
        # continue execution if quota > 0,
        # else stop (new context loaded in run())
        
        try:
            # check if valid instruction
            next(self.cs.disasm(uc.mem_read(address, size), size))
        except Exception as e:
            raise UcError(UC_ERR_INSN_INVALID)

        # check if a data locations (based on if address has been read)
        if address in self.mem_reads:
            raise UcError(UC_ERR_FETCH_PROT)

        if (address < 0x200 or address > self.fw.size):
            # invalid instruction fetch
            # protect the vector table
            raise UcError(UC_ERR_FETCH_PROT)

        # check if returning
        if self.context.callstack \
                and address == self.context.callstack[-1][-1]:
            self.context.callstack.pop(-1)

        # decrement quota of previously executed block
        if self.context.bblock:
            # not the first block

            self.context.bblock.quota -= 1

            if address not in self.bblocks:
                self.bblocks[address] = BBlock(
                    address, 
                    size, 
                    self.context.callstack[-1][0], 
                    self.context.bblock.addr)
                # self.bblocks[self.context.bblock.addr].children.append(address)
                self.context.bblock = self.bblocks[address]
                self.logger.info(f"new basic block @ {hex(address)}")
            elif self.bblocks[address].accesses_mem():
                self.context.bblock = self.bblocks[address]
                self.context.bblock.quota += 1
                self.logger.info(f"old block writes mem @ {hex(address)}")

            if self.bblocks[address].quota <= 0:
                self.uc.emu_stop()
        else:
            self.bblocks[address] = BBlock(address, size, self.context.callstack[-1][0])
            self.context.bblock = self.bblocks[address]
            self.logger.info(f"new basic block @ {hex(address)}")


    def _hook_code(self, uc, address, size, user_data):
        """single instruction callback"""

        self.cs.mode = uc.ctl_get_mode()
        self.context.pc = address
        self.context.pc |= 1 if uc.reg_read(UC_ARM_REG_CPSR) & (1 << 5) else 0
        self.context.age += 1
        self.context.apsr.set(uc.reg_read(UC_ARM_REG_APSR))
        cs_insn = next(self.cs.disasm(uc.mem_read(address, size), size))
        if self.log_insn:
            # self.logger.info("0x{:x}: {:<9} {}\t{}".format(
            #   address, 
            #   ' '.join(['%04x' % int.from_bytes(c, 'little') \
            #       for c in chunks(2, cs_insn.bytes)]),
            #   cs_insn.mnemonic,
            #   cs_insn.op_str,
            # ))
            if address not in self.fw.disasm:
                # insttruction not in disassembly, probably invalid
                # delete the block too
                del self.bblocks[self.context.bblock.addr]
                raise UcError(UC_ERR_INSN_INVALID)
            self.logger.info("0x{:x}: {:<10} {}".format(
                address, 
                self.fw.disasm[address]['raw_str'],
                self.fw.disasm[address]['mnemonic']))
        itstate = uc.reg_read(UC_ARM_REG_ITSTATE)

        # logic for different branch insns
        # a lot of this was necessary because capstone 4.0.2 doesn't 
        # calculate branch immediates correctly
        if cs_insn.group(ARM_GRP_CALL):
            # branch and link instructions are function calls
            # should prob also consider stmdb to sp and push instructions
            if cs_insn.id == ARM_INS_BL:
                # calculate branch target manually
                bl_insn = Thumb32BL(cs_insn.bytes)
                target = self.context.pc + 4 + bl_insn.imm32
            elif cs_insn.id == ARM_INS_BLX:
                dest_reg = cs_insn.op_find(ARM_OP_REG, 1)
                target = uc.reg_read(dest_reg.reg)
            else:
                raise Exception("this shouldn't happen")

            stack_info = (
                target,                             # function address
                uc.reg_read(UC_ARM_REG_SP),         # frame pointer
                uc.reg_read(UC_ARM_REG_PC) + size,  # return address
            )
            if itstate & 0xF:
                # call in IT block
                cs_cond = (((itstate >> 4) & 0xF) + 1) % 16
                context = self.backup()
                if self._get_cond_status(cs_cond):
                    # branch taken, backup context for next instruction
                    context.pc = self.context.pc + size
                    context.callstack.append(stack_info)
                else:
                    # branch not taken, backup context for jump target
                    context.pc = target
                    context.callstack.append(stack_info)
                self.jobs.append(context)
                self.context.callstack.append(stack_info)
            else:
                # unconditional call, just add to callstack
                self.context.callstack.append(stack_info)
                # self.logger.info('appended to stack')

                # add return address to jobs in case function never returns
                context = self.backup()
                context.pc = self.context.pc + size
                self.jobs.append(context)

        elif cs_insn.id == ARM_INS_B:
            # handle forking of context on conditional branches
            b_insn = ThumbBranch(cs_insn.bytes)
            if ((b_insn.enc in ['T1', 'T3'])
                    and (ARM_CC_INVALID < cs_insn.cc < ARM_CC_AL)):
                # check if a conditional code flag is set
                # add context to job queue for path not taken
                context = self.backup()
                if self._get_cond_status(cs_insn.cc):
                    # branch taken, backup context for next instruction
                    context.pc = self.context.pc + size
                else:
                    # branch not taken, backup context for jump target
                    context.pc = address + 4 + b_insn.imm32
                self.jobs.append(context)
            else:
                # T2 or T4 encoding is conditional only in an IT block
                # itstate is nonzero if in IT block
                if itstate & 0xF:
                    # branch is conditional if IT block active
                    cs_cond = (((itstate >> 4) & 0xF) + 1) % 16
                    if self._get_cond_status(cs_cond):
                        # branch taken, backup context for next instruction
                        context.pc = self.context.pc + size
                    else:
                        # branch not taken, backup context for jump target
                        context.pc = address + 4 + b_insn.imm32
                    self.jobs.append(context)

        elif cs_insn.id == ARM_INS_BX:
            if itstate & 0xF:
                # branch is conditional
                cs_cond = (((itstate >> 4) & 0xF) + 1) % 16
                context = self.backup()
                target = uc.read_reg(cs_insn.op_find(CS_OP_REG, 1).reg)
                if self._get_cond_status(cs_cond):
                    # branch taken
                    context.pc = self.context.pc + size
                else:
                    # branch not taken
                    context.pc = target
                self.jobs.append(context)

        elif (cs_insn.id == ARM_INS_CBNZ 
                or cs_insn.id == ARM_INS_CBZ):
            # also a conditional branch, so handle forking
            cb_insn = Thumb16CompareBranch(cs_insn.bytes)
            cmp_reg = cs_insn.op_find(ARM_OP_REG, 1)
            cmp_val = uc.reg_read(cmp_reg.reg)
            context = self.backup()
            if (cb_insn.nz and cmp_val) or not (cb_insn.nz or cmp_val):
                # branch taken, backup context for next instruction
                context.pc = self.context.pc + size
            else:
                # branch not taken, backup context for jump target
                context.pc = address + 4 + cb_insn.imm32
            self.jobs.append(context)

        elif (cs_insn.id == ARM_INS_TBB
                or cs_insn.id == ARM_INS_TBH):
            # essentially a jump table instruction. 
            # handle by adding all valid addresses in table to job list
            tb_insn = Thumb32TableBranch(cs_insn.bytes)
            tbl_base = uc.reg_read(UC_REG_MAP[tb_insn.Rn])
            if tb_insn.Rn == 15:
                # if base register is PC, base starts after instruction
                tbl_base += size
            tbl_offset = uc.reg_read(UC_REG_MAP[tb_insn.Rm])
            read_size = 1
            if tb_insn.half:
                tbl_offset <<= 1
                read_size = 2

            # add table addresses to jobs except for target
            # stop when hit invalid address or maximum offset
            # set an upper limit on the offset size as maximum size of flash region
            for i in range(0, self.pd['mmap']['flash']['size'], read_size):
                if i == tbl_offset:
                    continue
                jump_rel = uc.mem_read(tbl_base + i, read_size)
                jump_target = address + 4 + (jump_rel * 2)
                # specific to cortex m4
                if ((jump_target < 0x200) 
                        or (jump_target > self.pd['mmap']['flash']['size'])):
                    # invalid jump target
                    break
                # create backup context for valid jump target
                context = self.backup()
                context.pc = jump_target
                self.jobs.append(context)

            # can also be last instruction in IT block, so need to handle
            # IT condition code if this is the case
            if itstate & 0xF:
                # branch is conditional
                context = self.backup()
                cs_cond = (((itstate >> 4) & 0xF) + 1) % 16
                if self._get_cond_status(cs_cond):
                    # branch taken, backup context for next instruction
                    context.pc = address + size
                else:
                    # branch not taken, backup context for jump target
                    context.pc = address + 4 + b_insn.imm32
                self.jobs.append(context)


        ## LOAD INSTRUCTIONS
        # also need to deal with ldr intructions that aren't being hooked by
        # unicorn correctly...
        elif (cs_insn.id in [
                ARM_INS_LDR, ARM_INS_LDRH, ARM_INS_LDRB,
                ARM_INS_LDRT, ARM_INS_LDRHT, ARM_INS_LDRBT,
                ARM_INS_LDRD, ARM_INS_LDM]):
            load_size = 4
            if cs_insn.id == ARM_INS_LDM:
                ldm_insn = ThumbLDM(cs_insn.bytes)
                addrs = ldm_insn.addresses(uc)
            elif cs_insn.id == ARM_INS_LDRD:
                ldrd_insn = ThumbLDRD(cs_insn.bytes)
                addrs = ldrd_insn.addresses(uc)
            else:
                ld_insn = ThumbLDR(cs_insn.bytes)
                addrs = [ld_insn.address(uc)]
                load_size = ld_insn.load_size
            
            for read_addr in addrs:
                self.mem_reads.add(read_addr)
                read_info = (
                    uc.reg_read(UC_ARM_REG_PC), # inst addr
                    'r',                        # access type
                    int.from_bytes(uc.mem_read(read_addr, load_size), 'little'),
                    read_addr,
                )
                if read_info in self.context.bblock.mem_log:
                    # already read exact same value. punish this block and stop
                    self.context.bblock.quota -= 1
                    self.uc.emu_stop()
                else:
                    self.context.bblock.mem_log.append(read_info)
                self.mem_logger.info("pc @ 0x{:08X} : {} 0x{:>08x} @ 0x{:08X}".format(
                    *self.context.bblock.mem_log[-1]))

                # if in interrupt, mark memory location as volatile
                # make backup of this context to resume from here next time it is written
                if self.context.vtentry or read_addr in self.volatile_addrs:
                    if read_addr not in self.volatile_addrs:
                        self.volatile_addrs[read_addr] = {'contexts': [], 'writes': []}
                    context = self.backup()
                    if context not in self.volatile_addrs[read_addr]['contexts']:
                        self.volatile_addrs[read_addr]['contexts'].append(context)
                        if context.vtentry not in self.vtcontexts:
                            self.vtcontexts[context.vtentry] = []
                        self.vtcontexts[context.vtentry].append(context)
                        self.logger.info(
                            "PC @ 0x{:x} : volatile {} 0x{:>08X} @ 0x{:08X}".format(
                                *self.context.bblock.mem_log[-1]))

        ## STORE INSTRUCTIONS
        # because some str instructions are also not getting hooked dammit
        elif cs_insn.id in [
                ARM_INS_STR, ARM_INS_STRH, ARM_INS_STRB,
                ARM_INS_STRT, ARM_INS_STRHT, ARM_INS_STRBT,
                ARM_INS_STRD, ARM_INS_STM]:
            # get addresses written to by insn
            size = 4
            if cs_insn.id == ARM_INS_STM:
                stm_insn = ThumbSTM(cs_insn.bytes)
                accesses = stm_insn.accesses(uc)
            elif cs_insn.id == ARM_INS_STRD:
                strd_insn = ThumbSTRD(cs_insn.bytes)
                accesses = strd_insn.accesses(uc)
            else:
                st_insn = ThumbSTR(cs_insn.bytes)
                accesses = st_insn.access(uc)
                size = st_insn.size

            # iterate over addresses (only 1 in most cases)
            for addr, val in accesses.items():
                info = (
                    uc.reg_read(UC_ARM_REG_PC), # inst addr
                    'w',                        # access type
                    val,
                    addr,
                )
                self.context.bblock.mem_log.append(info)
                self.mem_logger.info("pc @ 0x{:08X} : {} 0x{:>08x} @ 0x{:08X}".format(
                    *self.context.bblock.mem_log[-1]))
                self.context.mem_state[addr] = val.to_bytes(size, 'little')

                # when interrupts enabled for a peripheral, alter the mem state of all the 
                # contexts associated with the IRQ for that peripheral
                # also add the contexts back to the job list
                if (addr & 0xFFF) == 0x304 and (addr & 0xFFFFF000) in self.pd['peri']:
                    vtentry = 0x40 + (4 * self.pd['peri'][addr & 0xFFFFF000])
                    for context in self.vtcontexts[vtentry]:
                        self.logger.info("overwriting context: <PC@{:08X} | VTE {}>".format(
                            context.pc, context.vtentry))
                        context.age = self.context.age
                        context.mem_state = deepcopy(self.context.mem_state)
                        context.bblock.quota += 1
                        self.jobs.append(copy(context))

                if addr in self.volatile_addrs:
                    # write to a volatile address, trigger execution from dependent blocks
                    self.logger.info("PC@{:08X} write to volatile address! (insn)".format(self.context.pc))
                    # write to a volatile location
                    # queue up all the contexts that read from that location
                    # that are in the opposite vtentry state
                    if val not in self.volatile_addrs[addr]['writes']:
                        self.volatile_addrs[addr]['writes'].append(val)
                        for context in self.volatile_addrs[addr]['contexts']:
                            self.logger.info(f"current vtentry: {self.context.vtentry} processing context: {context.vtentry}")
                            if context.vtentry != self.context.vtentry:
                                self.logger.info(
                                    "write @ 0x{:08X} queue context <PC@{:08X} | vtentry {:d}>".format(
                                        addr, context.pc, context.vtentry))
                                int_context = copy(context)
                                # int_context.mem_state = deepcopy(self.context.mem_state)
                                if int_context.age >= self.context.age:
                                    int_context.mem_state[addr] = self.context.mem_state[addr]
                                else:
                                    for k in self.context.mem_state:
                                        int_context.mem_state[k] = self.context.mem_state[k]
                                self.jobs.append(int_context)
                elif self.context.vtentry:
                    # if address isn't in volatile list but write occurs asynchronously
                    # add address to volatile
                    self.volatile_addrs[addr] = {'contexts':[], 'writes':[]}
                    if self.context.vtentry not in self.vtcontexts:
                        self.vtcontexts[self.context.vtentry] = []



    def _hook_mem(self, uc, access, address, size, value, user_data):
        """mem access callback"""
        # add writes to current context
        info = (
            uc.reg_read(UC_ARM_REG_PC),             # inst addr
            'w' if access in [UC_MEM_WRITE, UC_MEM_WRITE_PROT] else 'r', # access type
            value,
            address,
        )
        if (access != UC_MEM_WRITE_PROT 
                and self.context.bblock.mem_log 
                and self.context.bblock.mem_log[-1] == info):
            return 
        self.context.bblock.mem_log.append(info)
        self.mem_logger.info("pc @ 0x{:08X} : {} 0x{:>8x} @ 0x{:08X}".format(
            *self.context.bblock.mem_log[-1]))

        if access == UC_MEM_WRITE:
            self.context.mem_state[address] = bytes(self.uc.mem_read(address, size))

            # when interrupts enabled for a peripheral, alter the mem state of all the 
            # blocks associated with the IRQ for that peripheral
            if (address & 0xFFF) == 0x304 and (address & 0xFFFFF000) in self.pd['peri']:
                vtentry = 0x40 + (4 * self.pd['peri'][address & 0xFFFFF000])
                for context in self.vtcontexts[vtentry]:
                    context.age = self.context.age
                    context.mem_state = deepcopy(self.context.mem_state)
                    context.bblock.quota += 1
                    self.jobs.append(copy(context))


            if address in self.volatile_addrs:
                self.logger.info("PC@{:08X} write to volatile address!".format(self.context.pc))
                # write to a volatile location
                # queue up all the contexts that read from that location
                # that are in the opposite vtentry state
                if value not in self.volatile_addrs[address]['writes']:
                    self.volatile_addrs[address]['writes'].append(value)
                    for context in self.volatile_addrs[address]['contexts']:
                        if context.vtentry != self.context.vtentry:
                            self.logger.info(
                                "write @ 0x{:08X} queue context <PC@{:08X} | vtentry {:d}>".format(
                                    address, context.pc, context.vtentry))
                            int_context = copy(context)
                            # int_context.mem_state = deepcopy(self.context.mem_state)
                            if int_context.age >= self.context.age:
                                int_context.mem_state[address] = self.context.mem_state[address]
                            else:
                                for k in self.context.mem_state:
                                    int_context.mem_state[k] = self.context.mem_state[k]
                            
                            self.jobs.append(int_context)

        elif access == UC_MEM_WRITE_PROT:
            # can't write so skip
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            (_, sz, _, _) = next(self.cs.disasm_lite(
                self.uc.mem_read(pc, 4)))
            self.mem_logger.info("pc @ {:x} illegal write @ {:08X}, advance pc + {:d}".format(
                pc, address, sz))
            self.uc.reg_write(UC_ARM_REG_PC, self.context.pc + sz)
        else:
            self.mem_reads.add(address)
            if self.context.vtentry or address in self.volatile_addrs:
                if address not in self.volatile_addrs:
                    self.volatile_addrs[address] = {'contexts':[], 'writes':[]}
                context = self.backup()
                if context not in self.volatile_addrs[address]['contexts']:
                    self.volatile_addrs[address]['contexts'].append(context)
                    if context.vtentry not in self.vtcontexts:
                        self.vtcontexts[context.vtentry] = []
                    self.vtcontexts[context.vtentry].append(context)
                    self.logger.info(
                        "PC @ 0x{:x} : volatile {} 0x{:>08X} @ 0x{:08X}".format(
                            *self.context.bblock.mem_log[-1]))


    def _get_cond_status(self, uc_cond):
        self.context.apsr.set(self.uc.reg_read(UC_ARM_REG_APSR))
        return self.context.apsr.get_cond(uc_cond)


    def backup(self):
        """save the cpu and mem state"""
        self.logger.info("backup context @ 0x{:x}".format(self.context.pc))
        context = copy(self.context)
        context.uc_context = self.uc.context_save()
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        if sp < self.stack_base:
            context.stack_state = self.uc.mem_read(sp, self.stack_base - sp)
        else:
            context.stack_state = b''
        return context


    def restore(self, context : Type[EmFXContext]):
        """restore cpu and mem state"""
        # zero out locations that were written to after snapshot was taken
        for addr in self.context.mem_state.keys():
            if addr not in context.mem_state:
                self.uc.mem_write(addr, b'\x00\x00\x00\x00')

        # restore register state
        self.uc.context_restore(context.uc_context)
        self.context = context

        # restore memory state
        for addr, val in context.mem_state.items():
            self.uc.mem_write(addr, val)

        # restore stack
        if context.stack_state:
            self.uc.mem_write(
                context.uc_context.reg_read(UC_ARM_REG_SP), bytes(context.stack_state))

        if context.uc_context.reg_read(UC_ARM_REG_CPSR) & (1 << 5):
            self.context.pc |= 1

        self.logger.info("restore context @ 0x{:x}".format(context.pc))


    def run(self):
        """
        run the cfg recovery algorithm until timeout or completion
        """
        assert self.fw, "no firmware loaded"

        # load all addresses in vector table first
        # see section 2.3.4 of Cortex M4 generic user guide
        # exclude sp and entry point
        vector_table = self.uc.mem_read(0x8, 0x200)
        table_entry = 0x8
        for word in chunks(4, vector_table):
            word = int.from_bytes(word, 'little')
            if word:
                context = self.backup()
                context.pc = word | 1 # force thumb mode
                context.vtentry = table_entry
                self.jobs.append(context)
            table_entry += 4

        while self.jobs:
            context = self.jobs.pop(-1)
            self.restore(context)
            try:
                self.uc.emu_start(self.context.pc, 
                    self.pd['mmap']['flash']['address'] + self.pd['mmap']['flash']['size'])
            except UcError as e:
                regs = {name: self.uc.reg_read(reg) \
                    for reg, name in self.context.REGS.items()}
                self.logger.warning("PC @ 0x{:x} {}\n{}\n{}".format(
                    self.context.pc, str(e), 
                    traceback.format_exc(),
                    '\n'.join(['{:<4} = {}'.format(
                            name, hex(val)
                        ) for name, val in regs.items()]),
                ))

                # if e.args[0] in [UC_ERR_READ_PROT, UC_ERR_WRITE_PROT]:
                #     # pass read/write protections
                #     (_, size, _, _) = next(self.cs.disasm_lite(
                #         self.uc.mem_read(self.uc.reg_read(UC_ARM_REG_PC), 4), 4))
                #     self.context.pc += size
                #     self.jobs.append(self.context)
            except Exception as e:
                self.logger.error("{}\n{}\n".format(
                    str(e),
                    traceback.format_exc()))
                raise e



    def print_regs(self):
        """
        print current registers (not using logger)
        """
        regs = {name: self.uc.reg_read(reg) for reg, name in self.context.REGS.items()}
        for name, val in regs.items():
            print("{:<4} : {}".format(name, hex(val)))


