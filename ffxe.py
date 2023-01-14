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
from arch.armv7e import *
from mappings import *
from utils import *


class FContext():
    """
    class for context backup and restores
    """
    def __init__(self, pc, apsr, callstack, uc_context, bblock, isr=0):
        self.pc = pc 
        self.apsr = apsr
        # callstack is list of tuples of (func_addr, frame_ptr, ret_addr)
        self.callstack = callstack
        self.uc_context = uc_context
        self.bblock = bblock
        self.isr = isr
        self.mem_state = {}
        self.stack_state = b""
        self.newblock = True

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
            and self.isr == other.isr
            and self.stack_state == other.stack_state
            and self.callstack == other.callstack
            and self.mem_state == other.mem_state
            and bytes(self.uc_context) == bytes(other.uc_context))


class FBranch():
    """
    base class for branches
    """
    def __init__(self, addr, raw, target, bblock, context, 
            btype='cond', 
            ret=None, 
            isr=0):
        self.addr = addr        # address of branch instruction
        self.raw = raw          # raw of branch instruction
        self.target = target    # target's address
        self.bblock = bblock    # branch's basic block
        self.context = context  # restore context
        self.ret_addr = ret     # return address if call branch
        self.unexplored = True  # true if alt path still unexplored
        self.isr = isr          # interrupt service number

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
            and self.addr == other.addr)


class FFXEngine():
    """
    An engine class for implementing forced execution
    """

    def __init__(self,
            pd         : Union[str, dict],
            mmio       : dict = None,
            path       : str = None,
            log_dir    : str = 'logs',
            log_name   : str = 'fxe.log',
            log_stdout : bool = False,
            log_insn   : bool = False,
            log_time   : bool = True):
        
        # setup logging
        self.logger = logging.getLogger('efxe.eng')
        self.logger.setLevel(logging.DEBUG)
        self.log_insn = log_insn
        
        # setup log file directory
        # if log filename exists, rename
        if not os.path.isdir(log_dir):
            os.mkdir(log_dir)
        i = 2
        fn, ext = splitext(log_name)
        while os.path.exists(f"{log_dir}/{log_name}"):
            log_name = f"{fn}-{i}{ext}"
            i += 1

        formatter = logging.Formatter(
            "%(asctime)s : %(message)s" if log_time else "%(message)s")
        fhandler = logging.FileHandler(f"{log_dir}/{log_name}", mode = 'a')
        fhandler.setFormatter(formatter)
        self.logger.addHandler(fhandler)

        if log_stdout:
            shandler = logging.StreamHandler(sys.stdout)
            shandler.setFormatter(formatter)
            self.logger.addHandler(shandler)

        # create emulator instance
        # unicorn updates mode automatically on emu_start
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

        # create disassembler instance
        # mode updated in callbacks
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.cs.detail = 1 # enable detailed disassembly (slower)

        # platform description will be dictionary
        if isinstance(pd, str):
            if splitext(pd)[1] in ['.yml', '.yaml']:
                # load platform description from file
                with open(pd, 'r') as pd_file:
                    pd = yaml.load(pd_file, yaml.Loader)

        assert isinstance(pd, dict), \
            "platform description is not a dictionary"
        assert 'mmap' in pd, \
            "platform description must provide 'mmap'"

        self.pd = pd

        # map memory in unicorn emulator
        for region, kwargs in self.pd['mmap'].items():
            # make everything read/write-able for simplicity
            kwargs['perms'] |= 0b011
            self.uc.mem_map(**kwargs)

        # map io in unicorn emulator
        if isinstance(mmio, dict):
            # if user provided mmio argument
            # update platform description and use mmio_map
            self.pd['mmio'] = mmio
            for peri, kwargs in mmio.items():
                self.uc.mmio_map(**kwargs)
        else:
            # assume memory behavior of memory-mapped peripherals
            for region, kwargs in self.pd['mmio'].items():
                self.uc.mem_map(**kwargs)

        # helpful instance variables
        self.stack_base = None
        self.entry = None
        self.context = FContext(
            pc = None,
            apsr=APSRRegister(self.uc.reg_read(UC_ARM_REG_APSR)),
            callstack=[],
            uc_context=self.uc.context_save(),
            bblock=None,
        )
        self.cfg = CFG()
        self.unexplored = []
        self.explored = []
        self.branches = []
        self.ibtargets = {} # track targets for indirect branches
        self.mem_reads = []
        self.mem_writes = {}
        self.voladdrs = {}
        self.isr_entries = {}
        self.breakpoints = set()
        self.break_on_inst = False
        self.protected_edges = set()

        # load firmware if path provided
        self.fw = None
        if isinstance(path, str):
            self.load_fw(path)


    def load_fw(self, path):
        self.fw = FirmwareImage(path)

        # load firmware image to unicorn
        self.uc.mem_write(self.pd['mmap']['flash']['address'], self.fw.raw)

        # setup stack pointer and program counter
        # currently specific to Cortex M4, generalize later
        self.stack_base = int.from_bytes(self.fw.raw[0:4], 'little')
        self.entry = int.from_bytes(self.fw.raw[4:8], 'little')

        self.context.pc = self.entry
        self.uc.reg_write(UC_ARM_REG_SP, self.stack_base)
        self.uc.reg_write(UC_ARM_REG_PC, self.entry)
        self.context.uc_context = self.uc.context_save()
        self.context.callstack.append((
            self.entry,         # function address
            self.stack_base,    # frame pointer
            None,               # return address
        ))

        self.logger.info("loaded firmware: {}".format(path))


    def add_breakpoint(self, bp : int):
        """add debugging breakpoint"""
        self.breakpoints.add(bp)


    def addr_in_region(self, addr : int, region : str):
        """true if address is in specified mmap region(s)"""
        if region in self.pd['mmap'].keys():
            mm = 'mmap'
        elif region in self.pd['mmio'].keys():
            mm = 'mmio'
        else:
            return False

        raddr = self.pd[mm][region]['address']
        rsize = self.pd[mm][region]['size']
        if (addr >= raddr and addr < raddr + rsize):
            return True

        return False

    def addr_valid(self, addr : int):
        """true if address is in a mapped region"""
        if (any([self.addr_in_region(addr, r) for r in self.pd['mmap']])
                or any([self.addr_in_region(addr, r) for r in self.pd['mmio']])):
            return True
        return False


    def backup(self):
        """save cpu and mem state"""
        self.logger.info("backup context @ 0x{:x}".format(self.context.pc))
        context = copy(self.context)
        context.uc_context = self.uc.context_save()

        # explicitly save the current contents of the stack
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        if sp < self.stack_base:
            context.stack_state = self.uc.mem_read(sp, self.stack_base - sp)
        else:
            context.stack_state = b''

        return context


    def restore(self, context : Type[FContext]):
        """restore cpu and mem state"""
        # zero out locations that were written to after snapshot was taken
        for addr in self.context.mem_state.keys():
            if addr not in context.mem_state.keys():
                try:
                    self.uc.mem_write(addr, b'\x00\x00\x00\x00')
                except UcError as e:
                    if e.args[0] == UC_ERR_WRITE_UNMAPPED:
                        # don't care if write was unmapped
                        continue
                    else:
                        self.logger.warning(
                            f"UcError({e.args}) caught in memory wipe "
                            f"during context restore @ {hex(context.pc)}")
                        raise e

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
            # set thumb mode if necessary
            self.context.pc |= 1

        self.logger.info("restore context @ 0x{:x}".format(context.pc))


    def _get_cond_status(self, uc_cond):
        self.context.apsr.set(self.uc.reg_read(UC_ARM_REG_APSR))
        return self.context.apsr.get_cond(uc_cond)


    def _queue_isr(self, isr):
        """add isr entry point to unexplored branch queue"""
        context = self.backup()
        context.isr = isr
        context.pc = self.isr_entries[isr]['target']
        # explicitly deal with registered functions
        # for addr, info in self.voladdrs.items():
        #     for val, inst in info['w'].keys():
        #         if self.addr_in_region(val, 'flash'):
        #             # this is likely a registered function, write it into mem state
        #             context.mem_state[addr] = val.to_bytes(4, 'little')
        branch_info = {
            'addr'    : isr * 4,
            'raw'     : b'',
            'target'  : context.pc,
            'bblock'  : None,
            'context' : context,
            'ret'     : isr * 4,
            'isr'     : isr,
        }
        branch = FBranch(**branch_info)
        self.unexplored.append(branch)
        self.logger.info("isr {:d} queued".format(isr))


    def _hook_block(self, uc, address, size, user_data):
        """callback at beginning of new basic block"""
        # this should construct the block and connect it to the CFG as needed

        try:
            # # check if valid instruction
            # next(self.cs.disasm(uc.mem_read(address, size), offset=address))

            # check if all block instructions valid
            insn_addrs = [ins.address for ins in self.cs.disasm(
                uc.mem_read(address, size), offset=address)]
        except StopIteration as e:
            raise UcError(UC_ERR_INSN_INVALID)

        # check if block is at a data location
        # check if block is in vector table
        if ((address in self.mem_reads)
                or (address < 0x200)):
            raise UcError(UC_ERR_FETCH_PROT)

        block_kwargs = {}
        connected = False

        self.logger.info("### TRANSLATION BLOCK @ 0x{:x}".format(address) + '-'*20)

        if (address & (~1)) in self.breakpoints:
            breakpoint()

        # add block to cfg
        if not self.context.bblock:
            # handle the first block specially
            bblock = BBlock(
                address=address, 
                size=size, 
                insn_addrs=insn_addrs,
                fn_addr=(self.context.callstack[-1][0] | 1) ^ 1, 
                bytedata=self.uc.mem_read(address, size),
                isr=self.context.isr,
                parent=NullBlock)
            connected = self.cfg.connect_block(bblock)
        else:
            # check if returning block
            if (self.context.callstack 
                    and address == self.context.callstack[-1][-1]):
                self.context.callstack.pop(-1)
                # potential bug here
                self.context.bblock.returns = True

            # decrement quota of previously executed block
            self.context.bblock.quota -= 1 

            # add block if not already in cfg
            if self.cfg.is_new_block(address):
                bblock = BBlock(
                    address=address,
                    size=size,
                    insn_addrs=insn_addrs,
                    fn_addr=(self.context.callstack[-1][0] | 1) ^ 1,
                    bytedata=self.uc.mem_read(address, size),
                    isr=self.context.isr,
                    **block_kwargs)
                connected = self.cfg.connect_block(bblock, parent=self.context.bblock)
            else:
                bblock = self.cfg.bblocks[address] 

                if self.context.isr not in bblock.isrs:
                    # if already in cfg and different isr context, 
                    # add to block's known isrs
                    bblock.isrs.add(self.context.isr)

                # check if block has right function address
                # this bit is added because some functions end with unconditional
                # branches that are for some reason treated as conditional...
                if ((self.context.callstack[-1][0] | 1) != (bblock.fn_addr | 1)
                        # block parent did not use call instruction
                        and bblock.fn_addr ^ bblock.addr > 1 
                        # block must not be a func start
                        and (self.context.bblock.direct_target == None
                            or address ^ self.context.bblock.direct_target > 1)
                            # block must not be direct target of another branch
                        ):

                    # if previous block is a known parent of current block 
                    # and parents mismatch, just fix this block's fn_addr
                    # without doing any edge removal
                    if self.context.bblock not in bblock.parents:
                        # breakpoint()
                        # if block's fn address conflicts, update it
                        # only if the block isn't already the start of a function
                        # and increment its quota if necessary
                        # also remove any edges from blocks that were 
                        # labelled with the incorrect function address
                        # since those are likely mistaken connections
                        # ok, apparently not always. so don't do it if the 
                        # edge is from a direct branch
                        # darn there's other cases where this doesn't apply...
                        # breakpoint()

                        # this will only remove edges from bblock
                        self.cfg.remove_block_func_edges(bblock, bblock.fn_addr,
                            protected=self.protected_edges)
                    bblock.fn_addr = self.context.callstack[-1][0]

                    if bblock.quota < 1:
                        bblock.quota = 1

                connected = False
                # why is this necessary?
                # in order to not track edges between volatile loads
                if self.context.newblock:
                    connected = self.cfg.connect_block(bblock, parent=self.context.bblock)
                else:
                    self.context.newblock = True

        # update current block
        self.context.bblock = bblock

        # check execution quota
        if self.cfg.bblocks[address].quota <= 0:
            # check if calling block and do forward reachability if needed
            current = self.explored[-1]
            if (current.ret_addr
                    and current.target == self.context.pc
                    and current.ret_addr in self.cfg.bblocks):
                # if the block is the start of a function call
                # and there is a valid return address
                # do forward reachability on the existing function
                # and connect the return block to each return point
                ret_blocks = self.cfg.forward_reachability(
                    self.cfg.bblocks[address])
                for block in ret_blocks:
                    self.cfg.connect_block(
                        bblock=self.cfg.bblocks[current.ret_addr],
                        parent=block)
            self.uc.emu_stop()

        # logging
        if connected:
            self.logger.info(f"new basic block @ {hex(address)}")

    def _hook_code(self, uc, address, size, user_data):
        """callback after every instruction execution"""
        self.cs.mode = uc.ctl_get_mode()
        self.context.pc = address
        self.context.pc |= 1 if uc.reg_read(UC_ARM_REG_CPSR) & (1 << 5) else 0
        self.context.apsr.set(uc.reg_read(UC_ARM_REG_APSR))
        try:
            cs_insn = next(self.cs.disasm(uc.mem_read(address, size), offset=address))
        except StopIteration as e:
            # if hit a bad instruction, the block isn't valid
            self.context.bblock.delete = True
            self.cfg.remove_block(self.context.bblock)
            raise UcError(UC_ERR_INSN_INVALID)

        if address not in self.fw.disasm:
            # instruction not in pre-computed disassembly,
            # probably invalid, delete block and raise error
            self.context.bblock.delete = True
            self.cfg.remove_block(self.context.bblock)
            raise UcError(UC_ERR_INSN_INVALID)

        if self.log_insn:
            self.logger.info("0x{:x}: {:<10} {}".format(
                address,
                self.fw.disasm[address]['raw_str'],
                self.fw.disasm[address]['mnemonic']))

        if (address & (~1)) in self.breakpoints or self.break_on_inst:
            breakpoint()

        # it state for it conditionals
        itstate = uc.reg_read(UC_ARM_REG_ITSTATE)

        # logic for different branch instructions
        # because capstone 4.0.2 doesn't calculate 
        # branch immediates correctly
        if cs_insn.group(ARM_GRP_CALL):
            # branch and link instructions are function calls
            # TODO: should prob also consider stmdb to sp and push insns
            if cs_insn.id == ARM_INS_BL:
                # calculate branch target manually
                bl_insn = Thumb32BL(cs_insn.bytes)
                target = self.context.pc + 4 + bl_insn.imm32

                # little hack: if target is in mem_reads for some reason, remove it
                while target & (~1) in self.mem_reads:
                    self.mem_reads.remove((target | 1) ^ 1)

            elif cs_insn.id == ARM_INS_BLX:
                # indirect branch
                dest_reg = cs_insn.op_find(ARM_OP_REG, 1)
                target = uc.reg_read(dest_reg.reg)

                # tracking indirect branches
                if address not in self.ibtargets:
                    self.context.bblock.indirect = True
                    self.ibtargets[address] = []

                if (target not in self.ibtargets[address]
                        and (self.addr_in_region(target, 'flash')
                            or self.addr_in_region(target, 'codeRAM'))):
                    self.ibtargets[address].append(target)
                    self.logger.info("backward reachability @ 0x{:x}".format(self.context.pc))
                    self.cfg.backward_reachability(self.context.bblock)
            else:
                raise Exception("this shouldn't happen")

            stack_info = (
                target,                             # function address
                uc.reg_read(UC_ARM_REG_SP),         # frame pointer
                uc.reg_read(UC_ARM_REG_PC) + size,  # return address
            )

            # context always backed up
            context = self.backup()

            if (itstate & 0xF and not self._get_cond_status(
                    ((((itstate >> 4) & 0xF) + 1) % 16))):
                # it conditional and branch not taken
                # backup context for jump target
                context.pc = target
                context.callstack.append(stack_info)
            else:
                # unconditional call or branch taken
                # backup context for next instruction
                context.pc = self.context.pc + size 
                self.context.callstack.append(stack_info)

            branch = FBranch(
                addr=address,
                raw=cs_insn.bytes,
                target=context.pc,
                bblock=self.context.bblock,
                context=context,
                ret=self.context.pc + size)
            if branch not in self.unexplored:
                self.unexplored.append(branch)

        elif cs_insn.id == ARM_INS_B:
            # handle forking of context on conditional branches
            b_insn = ThumbBranch(cs_insn.bytes)
            context = self.backup()
            cs_cond = ARM_CC_AL
            if ((b_insn.enc in ['T1', 'T3'])
                    and (ARM_CC_INVALID < cs_insn.cc < ARM_CC_AL)):
                # check if conditional code flag set
                cs_cond = cs_insn.cc
            elif itstate & 0xF:
                # T2 and T4 encoding only conditional in IT block
                cs_cond = (((itstate >> 4) & 0xF) + 1) % 16

            if cs_cond != ARM_CC_AL:
                # only do backups for conditional branches

                if self._get_cond_status(cs_cond):
                    # branch taken, backup context for next instruction
                    context.pc = self.context.pc + size
                else:
                    # branch not taken, backup context for jump target
                    context.pc = address + 4 + b_insn.imm32

                    # protect edge from accidental removal
                    self.protected_edges.add((self.context.bblock.addr, address + size))

                branch = FBranch(
                    addr=address,
                    raw=cs_insn.bytes,
                    target=context.pc,
                    bblock=self.context.bblock,
                    context=context)
                if branch not in self.unexplored:
                    self.unexplored.append(branch)
            
            # always protect the direct target edge
            self.protected_edges.add(
                (self.context.bblock.addr, (address + 4 + b_insn.imm32) & (~1)))

            # keep track of the explicit target to prevent over-pruning of edges
            self.context.bblock.direct_target = (address + 4 + b_insn.imm32) & (~1)


        elif cs_insn.id == ARM_INS_BX:
            # update for indirect branch block
            target = uc.reg_read(cs_insn.op_find(CS_OP_REG, 1).reg)

            # indirect branch target tracking
            if address not in self.ibtargets:
                self.context.bblock.indirect = True
                self.ibtargets[address] = []

            if (target not in self.ibtargets[address]
                    and (self.addr_in_region(target, 'flash')
                        or self.addr_in_region(target, 'codeRAM'))):
                self.ibtargets[address].append(target)
                self.logger.info("backward reachability @ 0x{:x}".format(self.context.pc))
                self.cfg.backward_reachability(self.context.bblock)

            # only matters in IT conditional
            if itstate & 0xF:
                cs_cond = (((itstate >> 4) & 0xF) + 1) % 16
                context = self.backup()
                if self._get_cond_status(cs_cond):
                    # branch taken
                    context.pc = self.context.pc + size
                else:
                    # branch not taken
                    context.pc = target

                branch = FBranch(
                    addr=address,
                    raw=cs_insn.bytes,
                    target=context.pc,
                    bblock=self.context.bblock,
                    context=context)
                if branch not in self.unexplored:
                    self.unexplored.append(branch)

        elif (cs_insn.id == ARM_INS_CBNZ 
                or cs_insn.id == ARM_INS_CBZ):
            # also a conditional branch
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

                # protect edge from accidental removal
                self.protected_edges.add((self.context.bblock.addr, address + size))

            # keep track of the explicit target to prevent over-pruning of edges
            self.context.bblock.direct_target = (address + 4 + cb_insn.imm32) & (~1)

            branch = FBranch(
                addr=address,
                raw=cs_insn.bytes,
                target=context.pc,
                bblock=self.context.bblock,
                context=context)
            if branch not in self.unexplored:
                self.unexplored.append(branch)

        elif (cs_insn.id == ARM_INS_TBB
                or cs_insn.id == ARM_INS_TBH):
            # TODO: also needs to be handled like an indirect branch block

            # essentially a jump table instruction. 
            # handle by adding all valid addresses in table to job list
            tb_insn = Thumb32TableBranch(cs_insn.bytes)
            tbl_base = uc.reg_read(UC_REG_MAP[tb_insn.Rn])
            if tb_insn.Rn == 15:
                # if base register is PC, base starts after instruction
                tbl_base += 4
            tbl_offset = uc.reg_read(UC_REG_MAP[tb_insn.Rm])
            read_size = 1
            if tb_insn.half:
                tbl_offset <<= 1
                # tbl_offset &= 0xFFFFFFFF
                read_size = 2

            # deal with overflow (very stupid)
            mem_target = (tbl_base + tbl_offset) & 0xFFFFFFFF
            target = int.from_bytes(uc.mem_read(mem_target, read_size), 'little')

            # add table addresses to jobs except for target
            # stop when hit invalid address or maximum offset
            # set an upper limit on the offset size as maximum size of flash region
            # also skip duplicate targets
            jump_targets = set()
            for i in range(0, self.pd['mmap']['flash']['size'] - address, read_size):
                # if i == tbl_offset:
                #     continue
                # breakpoint()
                mem_loc = tbl_base + i
                jump_rel = int.from_bytes(uc.mem_read(mem_loc, read_size), 'little')
                jump_target = address + 4 + (jump_rel * 2)
                # self.mem_reads.append(mem_loc)

                if jump_target in jump_targets:
                    continue

                # if the mem_loc in jump_targets, it's definitely the end of the table
                # if the table is embedded in the code
                if mem_loc in jump_targets:
                    break

                # specific to cortex m4
                if ((jump_target < 0x200) 
                        or (jump_target > self.pd['mmap']['flash']['size'])):
                    # invalid jump target
                    break

                # check validity of jump target
                target_bytes = uc.mem_read(jump_target & (~1), 4)
                if not int.from_bytes(target_bytes, 'little'):
                    # if the jump target is to zeroed out data, it's probably invalid
                    break
                try:
                    target_insn = next(self.cs.disasm(target_bytes, 0))
                except StopIteration as e:
                    # stop iteration means failed to disassemble. probably invalid inst
                    break

                jump_targets.add(jump_target)

                # create backup context for valid jump target
                context = self.backup()
                context.pc = jump_target
                self.unexplored.append(
                    FBranch(
                        addr=address, 
                        raw=cs_insn.bytes, 
                        target=context.pc,
                        bblock=self.context.bblock,
                        context=context))

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
                    context.pc = target
                self.unexplored.append(
                    FBranch(
                        addr=address, 
                        raw=cs_insn.bytes, 
                        target=context.pc,
                        bblock=self.context.bblock,
                        context=context))

        ## WFE/WFI
        # because Unicorn doesn't recognize these for some reason
        elif cs_insn.id in [ARM_INS_WFE, ARM_INS_WFI]:
            # deal with these as branches to all possible interrupts
            # with the current context
            self.logger.info("wait-for instruction, calling all ISRs")
            for isr, branch_info in self.isr_entries.items():
                branch_info['context'] = self.backup()
                branch_info['context'].pc = branch_info['target']
                branch_info['context'].isr = isr
                self.unexplored.append(FBranch(**branch_info))

            # treat wfi/wfe as end of basic block
            context = self.backup()
            context.pc = self.context.pc + size
            branch = FBranch(
                addr=address,
                raw=cs_insn.bytes,
                target=context.pc,
                bblock=self.context.bblock,
                context=context)
            if branch not in self.unexplored:
                self.unexplored.append(branch)


        ## LOAD INSTRUCTIONS
        # because Unicorn doesn't hook LDR instructions correctly
        elif (cs_insn.id in [
                ARM_INS_LDR, ARM_INS_LDRH, ARM_INS_LDRB,
                ARM_INS_LDRT, ARM_INS_LDRHT, ARM_INS_LDRBT,
                ARM_INS_LDRD, ARM_INS_LDM, ARM_INS_LDMDB]):
            load_size = 4
            if cs_insn.id == ARM_INS_LDM:
                ldm_insn = ThumbLDM(cs_insn.bytes)
                addrs = ldm_insn.addresses(uc)
            elif cs_insn.id == ARM_INS_LDMDB:
                ldmdb_insn = ThumbLDMDB(cs_insn.bytes)
                addrs = ldmdb_insn.addresses(uc)
            elif cs_insn.id == ARM_INS_LDRD:
                ldrd_insn = ThumbLDRD(cs_insn.bytes)
                addrs = ldrd_insn.addresses(uc)
            else:
                ld_insn = ThumbLDR(cs_insn.bytes)
                addrs = [ld_insn.address(uc)]
                load_size = ld_insn.load_size

            for read_addr in addrs:
                self.mem_reads.append(read_addr)
                try:
                    val = int.from_bytes(uc.mem_read(read_addr, load_size), 'little')
                except UcError as e:
                    if e.args[0] == UC_ERR_READ_UNMAPPED:
                        # if read is unmapped, stop here and execute this block
                        # later (increment backward reachability)
                        self.cfg.backward_reachability(self.context.bblock, ib=False)
                        uc.emu_stop()
                        return
                read_info = (
                    uc.reg_read(UC_ARM_REG_PC), # instruction address
                    'r',                        # access type
                    val,                        # read data
                    read_addr,
                )
                if read_info not in self.context.bblock.mem_log:
                    self.context.bblock.mem_log.append(read_info)
                self.logger.info("pc @ 0x{:>08X} : {} 0x{:>08X} @ 0x{:>08X}".format(
                    *self.context.bblock.mem_log[-1]))

                # if in isr, mark memory location as volatile
                if self.context.isr:
                    # check if known volatile addr
                    if read_addr not in self.voladdrs:
                        self.voladdrs[read_addr] = { 'r':{}, 'w':{}, 'm': set() }

                        # if not known volatile addr, check if written to before
                        if read_addr in self.mem_writes:
                            # if written to before, set up forks with all the known values
                            for wval in self.mem_writes[read_addr]:
                                resume_context = copy(self.context)
                                resume_context.mem_state[read_addr] = wval
                                resume_context.newblock = False
                                self.voladdrs[read_addr]['w'][wval] = resume_context

                                branch_info = {
                                    'addr'    : address,
                                    'raw'     : b'',
                                    'target'  : resume_context.pc,
                                    'bblock'  : None,
                                    'context' : resume_context,
                                    'ret'     : address,
                                    'isr'     : resume_context.isr,
                                }
                                self.unexplored.append(FBranch(**branch_info))

                    self.voladdrs[read_addr]['r'][(val, address)] = copy(self.context)

                    # if encountering for first time and there are already logged reads,
                    # need to resume with those memory contexts.

        ## STORE INSTRUCTIONS
        # because Unicorn also doesn't hook some STR instructions
        elif cs_insn.id in [
                ARM_INS_STR, ARM_INS_STRH, ARM_INS_STRB,
                ARM_INS_STRT, ARM_INS_STRHT, ARM_INS_STRBT,
                ARM_INS_STRD, ARM_INS_STM]:
            # get addresses written by insn
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

            # iterate over write addresses
            for addr, val in accesses.items():
                if not self.addr_valid(addr):
                    self.cfg.backward_reachability(self.context.bblock, ib=False)
                    uc.emu_stop()
                    return
                info = (
                    uc.reg_read(UC_ARM_REG_PC), # instruction address
                    'w',                        # access type
                    val,                        # written value
                    addr,                       # write location
                )
                self.context.bblock.mem_log.append(info)
                if addr not in self.mem_writes:
                    self.mem_writes[addr] = []
                self.mem_writes[addr].append(val)
                self.logger.info("pc @ 0x{:>08X} : {} 0x{:>08x} @ {:>08X}".format(*info))
                self.context.mem_state[addr] = val.to_bytes(size, 'little')

                # when interrupts enabled for peripheral, 
                # do fxe on that peripheral's isr with current context
                if (((addr & 0xFFF) == 0x304) 
                        and ((addr & 0xFFFFF000) in self.pd['peri'])
                        and val):
                    # 0x304 is interrupt enable register offset for peripheral
                    # peripheral is determined by base address (in platform description)
                    # this is specific to nrf52
                    isr = (0x40 + (4 * self.pd['peri'][addr & 0xFFFFF000])) // 4
                    self.logger.info("peripheral enabled: IRQn {:d}".format(isr - 16))
                    self._queue_isr(isr)

                if self.context.isr and addr not in self.voladdrs:
                    # register volatile address
                    self.voladdrs[addr] = { 'r':{}, 'w':{}, 'm': set() }

                if addr in self.voladdrs:
                    # log write to volatile addres
                    self.voladdrs[addr]['w'][(val, address)] = copy(self.context)

                    # resume from any points that rely on this block
                    # (will only happen if the resume point is a contributing block)
                    # (also only do this if the volatile mem state is unique)
                    # (also only consider it for writes to changes in the dataRAM)
                    vol_ram_state = []
                    for maddr, mval in sorted(self.context.mem_state.items()):
                        if (maddr in self.voladdrs
                                and self.addr_in_region(maddr, 'dataRAM')):
                            vol_ram_state.append(
                                "{:x}:{:x}".format(maddr, int.from_bytes(mval, 'little')))
                    mem_hash = '_'.join(vol_ram_state)

                    if (not any([val == v for (v, i) in self.voladdrs[addr]['r'].keys()])
                            and mem_hash not in self.voladdrs[addr]['m']):
                        self.voladdrs[addr]['m'].add(mem_hash)

                        for (rval, inst), rcontext in self.voladdrs[addr]['r'].items():
                            if (rcontext.bblock.contrib):
                                resume_context = copy(rcontext)
                                resume_context.mem_state = self.context.mem_state
                                resume_context.newblock = False
                                branch_info = {
                                    'addr'    : addr,
                                    'raw'     : b'',
                                    'target'  : resume_context.pc,
                                    'bblock'  : None,
                                    'context' : resume_context,
                                    'ret'     : addr,
                                    'isr'     : resume_context.isr,
                                }
                                self.unexplored.append(FBranch(**branch_info))


        # ## STACK STUFF
        # # ensure functions only execute when explicitly called by call instruction (bl, blx)
        # elif cs_insn.id in [ARM_INS_PUSH, ARM_INS_STMDB]:
        #     # note: stmdb when used with the stack pointer is identical to push T2
        #     push_insn = ThumbPush(cs_insn.bytes)
        #     if push_insn.valid:
        #         # assume push insn in the block implies start of function
        #         # check the callstack to see if this block is actually 
        #         # the start of a function call
        #         # if it isn't, delete this block and stop emulation
        #         # otherwise continue
        #         if (self.context.callstack[-1][0] ^ self.context.bblock.addr) > 1:
        #             # thumb bit difference doesn't matter
        #             self.cfg.remove_block(self.context.bblock)
        #             self.uc.emu_stop()


    # def _hook_mem(self, uc, access, address, size, value, user_data):
    #     """callback after every memory access"""
    #     # tracking memory accesses
    #     info = (
    #         uc.reg_read(UC_ARM_REG_PC),             # inst addr
    #         'w' if access in [UC_MEM_WRITE, UC_MEM_WRITE_PROT] else 'r', # access type
    #         value,
    #         address,
    #     )
    #     self.context.bblock.mem_log.append(info)
    #     self.logger.info("pc @ 0x{:08X} : {} 0x{:>8x} @ 0x{:08X}".format(
    #         *self.context.bblock.mem_log[-1]))

    def _hook_stop_before_call(self, uc, address, size, user_data):
        """
        used to update context and stop emulation on function call
        """
        cs_insn = next(self.cs.disasm(uc.mem_read(address, size), offset=address))
        if cs_insn.group(ARM_GRP_CALL):
            self.uc.emu_stop()

        ## STORE INSTRUCTIONS
        # because Unicorn also doesn't hook some STR instructions
        elif cs_insn.id in [
                ARM_INS_STR, ARM_INS_STRH, ARM_INS_STRB,
                ARM_INS_STRT, ARM_INS_STRHT, ARM_INS_STRBT,
                ARM_INS_STRD, ARM_INS_STM]:
            # get addresses written by insn
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

            # iterate over write addresses
            for addr, val in accesses.items():
                self.context.mem_state[addr] = val.to_bytes(size, 'little')


    def run(self):
        """
        fun FXE recovery algorithm until timeout or completion
        """
        assert self.fw, "no firmware loaded"

        self.logger.info(f"input path: {self.fw.path}")

        # need to prime the system by doing dynamic execution of the reset handler
        tmphook = self.uc.hook_add(
            UC_HOOK_CODE,
            self._hook_stop_before_call,
            begin=self.pd['mmap']['flash']['address'],
            end=self.pd['mmap']['flash']['address'] + self.pd['mmap']['flash']['size'],
            user_data={},
        )
        # execute just reset handler
        self.uc.emu_start(
            self.entry,
            self.pd['mmap']['flash']['address'] + self.pd['mmap']['flash']['size'])
        # should have stopped before calling next function
        # deregister stop hook
        self.uc.hook_del(tmphook)

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

        # # setup mem access hooks
        # self.uc.hook_add(
        #     (UC_HOOK_MEM_READ | 
        #         UC_HOOK_MEM_READ_PROT |
        #         UC_HOOK_MEM_READ_AFTER |
        #         UC_HOOK_MEM_WRITE |
        #         UC_HOOK_MEM_WRITE_PROT),
        #     self._hook_mem,
        #     begin=0x0,
        #     end=0xFFFFFFFF,
        #     user_data={},
        # )

        # load all addresses in vector table first
        # see section 2.3.4 of Cortex M4 generic user guide
        # exclude sp and entry point
        vector_table = self.uc.mem_read(0x4, 0x200 - 4)
        table_offset = 0x4
        for word in chunks(4, vector_table):
            word = int.from_bytes(word, 'little')
            if word:
                context = self.backup()
                context.pc = word | 1 # force thumb mode
                stack_info = (
                    context.pc,                         # function address
                    self.uc.reg_read(UC_ARM_REG_SP),    # frame pointer
                    None,                               # return address
                )
                context.callstack.append(stack_info)

                branch_info = {
                    'addr'    : table_offset,
                    'raw'     : b'',
                    'target'  : word,
                    'bblock'  : None,
                    'context' : context,
                    'ret'     : table_offset,
                    'isr'     : table_offset // 4,
                }
                if word != self.entry:
                    # any entry point that isn't main entry i
                    # is treated as ISR entry point
                    context.isr = table_offset // 4
                    self.isr_entries[context.isr] = branch_info
                self.unexplored.append(
                    FBranch(**branch_info))
            table_offset += 4

        visited = []

        while self.unexplored:
            branch = self.unexplored.pop(-1)
            self.explored.append(branch)

            # restore from unexplored branch
            branch.unexplored = False
            self.restore(branch.context)
            if branch.bblock:
                # restore correct current block so edges aren't screwed up
                self.context.bblock = branch.bblock
            try:
                self.logger.info(f"unexplored branches: {len(self.unexplored)}")
                self.uc.emu_start(self.context.pc, 
                    self.pd['mmap']['flash']['address'] + self.pd['mmap']['flash']['size'])
            except UcError as e:
                regs = {name: self.uc.reg_read(reg) \
                    for reg, name in REGS.items()}
                self.logger.warning("PC @ 0x{:x} {}\n{}\n{}".format(
                    self.context.pc, str(e), 
                    traceback.format_exc(),
                    '\n'.join(['{:<4} = {}'.format(
                            name, hex(val)
                        ) for name, val in regs.items()]),
                ))
                # if block has invalid instruction, mark for delete
                if e.args == UC_ERR_INSN_INVALID:
                    self.context.bblock.delete = True
                # # if block tried to access unmapped data, let it try to execute again
                # if e.args in [UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED]:
                #     self.cfg.backward_reachability(self.context.bblock)

            except Exception as e:
                self.logger.error("{}\n{}\n".format(
                    str(e),
                    traceback.format_exc()))
                raise e

        self.logger.info("resolving overlapping blocks...")
        self.cfg.resolve_blocks()
        self.logger.info("finished.")

    def print_regs(self):
        """
        print current registers (not using logger)
        """
        regs = {name: self.uc.reg_read(reg) for reg, name in REGS.items()}
        for name, val in regs.items():
            print("{:<4} : {}".format(name, hex(val)))

    def print_mem(self, address, size):
        """
        print memory region in 4 byte big-endian chunks
        (not using logger)
        """
        for i, chunk in enumerate(chunks(4, self.uc.mem_read(address, size))):
            print("0x{:<4x} : {:08x}".format(address + i * 4, int.from_bytes(chunk, 'little')))




