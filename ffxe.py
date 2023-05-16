import os
import sys
import logging
import itertools
import traceback
from os.path import splitext
from typing import Union, Type
from copy import copy, deepcopy
from collections import namedtuple

import yaml
import unicorn
import elftools
import capstone
from IPython import embed

from unicorn import *
from unicorn.arm_const import *
from capstone import *
from capstone.arm_const import *

from models import *
from arch.armv7e import *
from mappings import *
from utils import *


CallStackEntry = namedtuple('CallStackEntry', 
    ['fn_addr', 'frame_ptr', 'ret_addr'])

class FContext():
    """
    class for context backup and restores
    """
    __slots__ = [
        'pc',           # program counter state
        'apsr',         # application program status register state
        'callstack',    # function call stack (list of CallStackEntry objects)
        'uc_context',   # unicorn context (from context_save())
        'bblock',       # pointer to current BBlock instance
        'isr',          # current ISR thread
        'mem_state',    # memory state dictionary
        'stack_state',  # current stack data
        'newblock'      # whether the next block should be added to cfg
    ]
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
        for k in self.__slots__:
            v = getattr(self, k)
            if k == 'uc_context':
                setattr(result, k, deepcopy(v))
            else:
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
    __slots__ = [
        'addr', 'raw', 'target', 'bblock', 'context', 
        'ret_addr', 'unexplored', 'isr'
    ]

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
            and self.addr == other.addr
            and self.target == other.target
            and self.bblock == other.bblock)


class FFXEngine():
    """
    An engine class for implementing forced execution
    """

    def __init__(self,
            pd         : Union[str, dict],
            mmio       : dict = None,
            path       : str = None,
            vtbases  : list[int] = [0x0],
            log_dir    : str = 'logs',
            log_name   : str = 'ffxe.log',
            log_stdout : bool = False,
            log_insn   : bool = False,
            log_time   : bool = True):
        
        # setup logging
        self.logger = logging.getLogger('ffxe.eng')
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

        self.log_path = f"{log_dir}/{log_name}"

        formatter = logging.Formatter(
            "%(asctime)s : %(message)s" if log_time else "%(message)s")
        fhandler = logging.FileHandler(self.log_path, mode = 'a')
        fhandler.setFormatter(formatter)
        self.logger.addHandler(fhandler)

        if log_stdout:
            shandler = logging.StreamHandler(sys.stdout)
            shandler.setFormatter(formatter)
            self.logger.addHandler(shandler)

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

        self.uc_arch = globals()[f"UC_ARCH_{pd['cpu']['arch']}"]
        self.uc_model = globals()[f"UC_CPU_{pd['cpu']['arch']}_{pd['cpu']['model']}"]

        self.cs_arch = globals()[f"CS_ARCH_{pd['cpu']['arch']}"]
        
        self.cpu_mode = 0
        for mode in pd['cpu']['mode']:
            self.cpu_mode |= globals()[f"UC_MODE_{mode}"]
        # for whatever reason, capstone and unicorn mode values are shared,
        # but arch values are not, hence, shared mode, but different arch

        # create emulator instance
        # unicorn updates mode automatically on emu_start
        self.uc = Uc(self.uc_arch, self.cpu_mode)
        self.uc.ctl_set_cpu_model(self.uc_model)

        # create disassembler instance
        # mode updated in callbacks
        self.cs = Cs(self.cs_arch, self.cpu_mode)
        self.cs.detail = 1 # enable detailed disassembly (slower)

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
            self.load_fw(path, vtbases)


    def load_fw(self, path, 
            vtbases : list[int]):
        """instantiate firmware image and load into unicorn"""
        self.fw = FirmwareImage(path, self.pd, vtbases,
            cs=self.cs)

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
        self.context.callstack.append(CallStackEntry(
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

    def addr_in_vtable(self, addr : int):
        """true if address is in any vector table"""
        return any([off <= addr < off + self.pd['vt']['size'] \
            for off in self.fw.vector_tables.keys()])

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


    def _queue_branch(self, branch : Type[FBranch]):
        """make it easier to change branch queueing logic"""
        if branch in self.explored:
            # # if branch already been visited, connect the current block 
            # # to the branch's target block
            # for explored_branch in self.explored:
            #     if branch == explored_branch:
            #         target_block = self.cfg.bblocks[explored_branch.target & (~1)]
            #         self.cfg.connect_block(target_block, parent=branch.bblock)
            
            # check if the branch actually leads to a block.
            # if not, don't queue it. 
            # this can happen if a previously explored branch led
            # to an invalid location.
            if (branch.target & (~1)) not in self.cfg.bblocks:
                return

            target_block = self.cfg.bblocks[branch.target & (~1)]
            if target_block.contrib:
                self.unexplored.append(branch)

        elif branch not in self.unexplored:
            self.unexplored.append(branch)

    def _hook_block(self, uc, address, size, user_data):
        """callback at beginning of new basic block"""
        # this should construct the block and connect it to the CFG as needed

        try:
            # # check if valid instruction
            # next(self.cs.disasm(uc.mem_read(address, size), offset=address))

            # check if all block instructions valid
            insns = {
                insn.address: insn for insn in self.cs.disasm(
                uc.mem_read(address, size), offset=address) 
            }
        except StopIteration as e:
            raise UcError(UC_ERR_INSN_INVALID)

        # check if block is at a data location
        # check if block is in vector table
        if (any([insn.address in self.mem_reads for insn in insns.values()])):
            raise UcError(UC_ERR_FETCH_PROT)
        if (self.addr_in_vtable(address)):
            raise UcError(UC_ERR_FETCH_PROT)

        # check if block beyond end of fw
        if (address > self.fw.size + self.pd['mmap']['flash']['address']):
            raise UcError(UC_ERR_INSN_INVALID)

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
                insns=insns,
                fn_addr=(self.context.callstack[-1].fn_addr | 1) ^ 1, 
                bytedata=self.uc.mem_read(address, size),
                isr=self.context.isr,
                parent=NullBlock)
            connected = self.cfg.connect_block(bblock)
        else:
            # check if returning block
            if (self.context.callstack 
                    and address == self.context.callstack[-1].ret_addr):
                self.context.callstack.pop(-1)
                # potential bug here
                self.context.bblock.returns = True

            # decrement quota of previously executed block
            if self.context.newblock:
                self.context.bblock.quota -= 1 

            # add block if not already in cfg
            if self.cfg.is_new_block(address) and self.context.newblock:
                bblock = BBlock(
                    address=address,
                    size=size,
                    insns=insns,
                    fn_addr=(self.context.callstack[-1].fn_addr | 1) ^ 1,
                    bytedata=self.uc.mem_read(address, size),
                    isr=self.context.isr,
                    **block_kwargs)
                connected = self.cfg.connect_block(bblock, parent=self.context.bblock)
            else:
                if not self.context.newblock:
                    bblock = self.context.bblock
                else:
                    bblock = self.cfg.bblocks[address] 

                if self.context.isr not in bblock.isrs:
                    # if already in cfg and different isr context, 
                    # add to block's known isrs
                    bblock.isrs.add(self.context.isr)

                # check if block has right function address
                # this bit is added because some functions end with unconditional
                # branches that are for some reason treated as conditional...
                if ((self.context.callstack[-1].fn_addr | 1) != (bblock.fn_addr | 1)
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
                    bblock.fn_addr = self.context.callstack[-1].fn_addr

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
        if self.context.bblock.quota <= 0:
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
                    self.context.bblock)
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

        # if address not in self.fw.disasm:
        #     # instruction not in pre-computed disassembly,
        #     # probably invalid, delete block and raise error
        #     self.context.bblock.delete = True
        #     self.cfg.remove_block(self.context.bblock)
        #     raise UcError(UC_ERR_INSN_INVALID)

        ## TODO: getting rid of predisasm means this needs to be dealt with.
        ## will likely need to disasm on block encounter...
        # if self.log_insn:
        #     self.logger.info("0x{:x}: {:<10} {}".format(
        #         address,
        #         self.fw.disasm[address]['raw_str'],
        #         self.fw.disasm[address]['mnemonic']))

        if self.log_insn:
            self.logger.info(str(self.context.bblock.insns[address]))

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

                self.context.bblock.indirect = True
                self.context.bblock.contrib = True

                # tracking indirect branches
                if address not in self.ibtargets:
                    self.ibtargets[address] = []

                # need to account for case where indirect block reached, but
                # state is invalid and so not getting marked properly

                # limiting the backwarrd reachability might be causing 
                # cases where quotas not getting incremented and legit
                # memory states are being ignored.
                if (target not in self.ibtargets[address]
                        and (self.addr_in_region(target, 'flash')
                            or self.addr_in_region(target, 'codeRAM'))):
                    self.ibtargets[address].append(target)
                    self.logger.info("backward reachability @ 0x{:x}".format(self.context.pc))
                    self.context.bblock.quota -= 1
                    self.cfg.backward_reachability(self.context.bblock)

            else:
                raise Exception("this shouldn't happen")

            stack_info = CallStackEntry(
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
            self._queue_branch(branch)

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
                self._queue_branch(branch)
            
            # always protect the direct target edge
            self.protected_edges.add(
                (self.context.bblock.addr, (address + 4 + b_insn.imm32) & (~1)))

            # keep track of the explicit target to prevent over-pruning of edges
            self.context.bblock.direct_target = (address + 4 + b_insn.imm32) & (~1)


        elif cs_insn.id == ARM_INS_BX:
            # update for indirect branch block
            target = uc.reg_read(cs_insn.op_find(CS_OP_REG, 1).reg)

            self.context.bblock.indirect = True
            self.context.bblock.contrib = True

            # indirect branch target tracking
            if address not in self.ibtargets:
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
                self._queue_branch(branch)

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
                if (self.addr_in_vtable(jump_target) 
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
                                resume_context = self.backup()
                                resume_context.mem_state[read_addr] = wval.to_bytes(4, 'little')
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

                    if (val, address) not in self.voladdrs[read_addr]['r']:
                        self.voladdrs[read_addr]['r'][(val, address)] = []

                    self.voladdrs[read_addr]['r'][(val, address)].append(self.backup())

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
                # requires mapping of interrupt enable register addrs to 
                # corresponding vector table entry              
                if addr in self.pd['intenable']:
                    for intenable in self.pd['intenable'][addr]:
                        if val & intenable['mask']:
                            vtoffset = intenable['offset']
                            self.logger.info("peripheral enabled: IRQn {:x}".format(vtoffset // 4))

                            for vtbase in self.fw.vector_tables.keys():
                                self._queue_isr(vtbase + vtoffset)


                if self.context.isr and addr not in self.voladdrs:
                    # register volatile address
                    self.voladdrs[addr] = { 'r':{}, 'w':{}, 'm': set() }

                if addr in self.voladdrs:
                    # log write to volatile addrs
                    if (val, address) not in self.voladdrs[addr]['w']:
                        self.voladdrs[addr]['w'][(val, address)] = []
                    self.voladdrs[addr]['w'][(val, address)].append(self.backup())

                        # try not allowing overwrite
                        # self.voladdrs[addr]['w'][(val, address)] = copy(self.context)

                    # resume from any points that rely on this block 
                    # only if this block isn't in isr and the resume point is or vice versa
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
                    # could try adding arg reg state to hash

                    if (not any([val == v for (v, i) in self.voladdrs[addr]['r'].keys()])
                            and mem_hash not in self.voladdrs[addr]['m']):
                        self.voladdrs[addr]['m'].add(mem_hash)

                        for (rval, inst), rcontexts in self.voladdrs[addr]['r'].items():
                            for rcontext in rcontexts:
                                if (rcontext.bblock.contrib
                                        and self.context.isr != rcontext.isr):
                                    resume_context = copy(rcontext)
                                    if (resume_context.bblock.quota < 1
                                            and resume_context.bblock.contrib):
                                        self.cfg.inc_quota_forward(resume_context.bblock)
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

        # ffxe goes through ISRs first, then main threads.
        # if there are multiple vector tables, there may be 
        # multiple defined entry points. in this case, we need to
        # queue these entry points first, since the algorithm pops
        # the last branch/job in the queue, starting with the
        # absolute entry point, as defined by the processor 
        # architecture. in ffxe, we have hard-coded it for ARM 
        # since ARM processors always start at 0x4 of the loaded
        # firmware image.


        # load absolute entry point (last to be executed)
        # only if the vector table gets relocated at runtime
        # NOTE: for whatever reason, adding it regardlessly leads to more
        # resolved blocks...
        # raw entry point is 0x4 offset of the actual firmware binary,
        # if True:
        if 0x0 not in self.fw.vector_tables.keys():
            branch_info = {
                'addr'      : 0x4,
                'raw'       : b'',
                'target'    : self.entry,
                'bblock'    : None,
                'context'   : self.backup(),
                'ret'       : 0x4,
                'isr'       : 0x4,
            }
            self.unexplored.append(FBranch(**branch_info))

        for vtbase, vector_table in self.fw.vector_tables.items():
            # now queue all the Reset handlers in each vector table
            # making sure to reinitialize the sp with the associated
            # vector table's stack base pointer
            context = self.backup()
            sp = int.from_bytes(vector_table[:4], 'little')
            context.uc_context.reg_write(UC_ARM_REG_SP, sp)
            target = int.from_bytes(vector_table[4:8], 'little')

            branch_info = {
                'addr'      : vtbase + 0x4,
                'raw'       : b'',
                'target'    : target,
                'bblock'    : None,
                'context'   : context,
                'ret'       : vtbase + 0x4,
                'isr'       : 0x4,
            }

            self.unexplored.append(FBranch(**branch_info))

        # now load all isr addresses in vector tables
        # see section 2.3.4 of Cortex M4 generic user guide
        
        for vtbase, vector_table in self.fw.vector_tables.items():
            table_offset = 0x8
            for word in chunks(4, vector_table[8:]):
                word = int.from_bytes(word, 'little')
                if word:
                    context = self.backup()
                    context.pc = word | 1 # force thumb mode
                    stack_info = CallStackEntry(
                        context.pc,                         # function address
                        self.uc.reg_read(UC_ARM_REG_SP),    # frame pointer
                        None,                               # return address
                    )
                    context.callstack.append(stack_info)

                    branch_info = {
                        'addr'    : vtbase + table_offset,
                        'raw'     : b'',
                        'target'  : word,
                        'bblock'  : None,
                        'context' : context,
                        'ret'     : vtbase + table_offset,
                        'isr'     : table_offset,   # based on IRQn
                    }

                    # indicate context is isr, not main thread
                    context.isr = vtbase + table_offset
                    self.isr_entries[context.isr] = branch_info

                    self.unexplored.append(
                        FBranch(**branch_info))
                table_offset += 4


        while self.unexplored:
            branch = self.unexplored.pop(-1)
            self.explored.append(branch)

            # reset quotas after all isrs
            if (branch.target == self.entry):
                self.logger.info("RESETTING QUOTAS")
                self.cfg.reset_quotas()

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
                
                # if block tried to access unmapped data, let it try to execute again
                # elif (e.args in [UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED]
                #         and self.context.bblock.contrib):
                #     self.cfg.backward_reachability(self.context.bblock)

                # if block errored out but was a contibuting block, need to reset the quotas
                # elif self.context.newblock and self.context.bblock.contrib:
                #     # the current block never got decremented, so don't
                #     # increment it
                #     self.context.bblock.quota -= 1
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




