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


class Context():
    """
    class for context backup and restores
    """
    def __init__(self, pc, apsr, callstack, uc_context, bblock):
        self.pc = pc 
        self.apsr = apsr
        # callstack is list of tuples of (func_addr, frame_ptr, ret_addr)
        self.callstack = callstack
        self.uc_context = uc_context
        self.bblock = bblock
        self.mem_state = {}
        self.stack_state = b""

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
            and self.stack_state == other.stack_state
            and self.callstack == other.callstack
            and self.mem_state == other.mem_state
            and bytes(self.uc_context) == bytes(other.uc_context))


class Branch():
    """
    base class for branches
    """
    def __init__(self, addr, raw, target, bblock, context, btype='cond', ret=None):
        self.addr = addr        # address of branch instruction
        self.raw = raw          # raw of branch instruction
        self.target = target    # target's address
        self.bblock = bblock    # branch's basic block
        self.context = context  # restore context
        self.ret_addr = ret     # return address if call branch
        self.unexplored = True  # true if alt path still unexplored

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
            and self.addr == other.addr)


class FXEngine():
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
            log_insn   : bool = False):
        
        # setup logging
        self.logger = logging.getLogger('fxe.eng')
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

        formatter = logging.Formatter("%(asctime)s : %(message)s")
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
        self.context = Context(
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

        # load firmware if path provided
        self.fw = None
        if isinstance(path, str):
            self.load_fw(path)

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


    def load_fw(self, path):
        self.fw = FirmwareImage(path)

        # load firmware image to unicorn
        self.uc.mem_write(self.pd['mmap']['flash']['address'], self.fw.raw)

        # setup stack pointer and program counter
        # currently specific to Cortex M4, generalize later
        self.stack_base = int.from_bytes(self.fw.raw[0:4], 'little')
        self.entry = int.from_bytes(self.fw.raw[4:8], 'little')

        self.mem_reads = []
        self.context.pc = self.entry
        self.uc.reg_write(UC_ARM_REG_SP, self.stack_base)
        self.uc.reg_write(UC_ARM_REG_PC, self.entry)
        self.context.uc_context = self.uc.context_save()
        self.context.callstack.append((
            self.entry,         # function address
            self.stack_base,    # frame pointer
            None,               # return address
        ))

    def addr_in_region(self, addr : int, region : str):
        """true if address is in specified mmap region(s)"""
        if region in self.pd['mmap'].keys():
            raddr = self.pd['mmap'][region]['address']
            rsize = self.pd['mmap'][region]['size']
            if (addr >= raddr and addr < raddr + rsize):
                return True

        return False


    def _hook_block(self, uc, address, size, user_data):
        """callback at beginning of new basic block"""
        # this should construct the block and connect it to the CFG as needed

        try:
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

        # check if block beyond end of fw
        if (address > self.fw.size):
            raise UcError(UC_ERR_INSN_INVALID)

        block_kwargs = {}
        connected = False

        # add block to cfg
        if not self.context.bblock:
            # handle the first block specially
            bblock = BBlock(
                address=address, 
                size=size, 
                insn_addrs=insn_addrs,
                fn_addr=self.context.callstack[-1][0], 
                bytedata=self.uc.mem_read(address, size),
                parent=NullBlock)
            connected = self.cfg.connect_block(bblock)
        else:
            # check if returning block
            if (self.context.callstack 
                    and address == self.context.callstack[-1][-1]):
                self.context.callstack.pop(-1)
                self.context.bblock.returns = True

            # decrement quota of previously executed block
            self.context.bblock.quota -= 1 

            # add block if not already in cfg
            if self.cfg.is_new_block(address):    
                bblock = BBlock(
                    address=address,
                    size=size,
                    insn_addrs=insn_addrs,
                    fn_addr=self.context.callstack[-1][0],
                    bytedata=self.uc.mem_read(address, size),
                    **block_kwargs)
            else:
                bblock = self.cfg.bblocks[address]

        connected = self.cfg.connect_block(bblock, parent=self.context.bblock)
        
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

        # it state for it conditionals
        itstate = uc.reg_read(UC_ARM_REG_ITSTATE)

        # logic for different branch instructions
        # because capstone 4.0.2 doesn't calculate 
        # branch immediates correctly
        if cs_insn.group(ARM_GRP_CALL):
            # branch and link instructions are function calls
            # should prob also consider stmdb to sp and push insns
            if cs_insn.id == ARM_INS_BL:
                # calculate branch target manually
                bl_insn = Thumb32BL(cs_insn.bytes)
                target = self.context.pc + 4 + bl_insn.imm32
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
                    self.context.bblock.quota -= 1
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

            branch = Branch(
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
                if self._get_cond_status(cs_cond):
                    # branch taken, backup context for next instruction
                    context.pc = self.context.pc + size
                else:
                    # branch not taken, backup context for jump target
                    context.pc = address + 4 + b_insn.imm32

                branch = Branch(
                    addr=address,
                    raw=cs_insn.bytes,
                    target=context.pc,
                    bblock=self.context.bblock,
                    context=context)
                if branch not in self.unexplored:
                    self.unexplored.append(branch)

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

                branch = Branch(
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

            branch = Branch(
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
                tbl_base += size
            tbl_offset = uc.reg_read(UC_REG_MAP[tb_insn.Rm])
            read_size = 1
            if tb_insn.half:
                tbl_offset <<= 1
                read_size = 2

            # add table addresses to jobs except for target
            # stop when hit invalid address or maximum offset
            # set an upper limit on the offset size as maximum size of flash region
            # also skip duplicate targets
            jump_targets = set()
            for i in range(0, self.pd['mmap']['flash']['size'], read_size):
                # if i == tbl_offset:
                #     continue
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
                    Branch(
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
                    Branch(
                        addr=address, 
                        raw=cs_insn.bytes, 
                        target=context.pc,
                        bblock=self.context.bblock,
                        context=context))

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

    def _get_cond_status(self, uc_cond):
        self.context.apsr.set(self.uc.reg_read(UC_ARM_REG_APSR))
        return self.context.apsr.get_cond(uc_cond)

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

    def restore(self, context : Type[Context]):
        """restore cpu and mem state"""
        # zero out locations that were written to after snapshot was taken
        for addr in self.context.mem_state.keys():
            if addr not in context.mem_state.keys():
                try:
                    self.uc.mem_write(addr, b'\x00\x00\x00\x00')
                except UcError as e:
                    if e.args == UC_ERR_WRITE_UNMAPPED:
                        # don't care if write was unmapped
                        pass
                    else:
                        self.logger.warning(
                            f"UcDerror({e.args}) caught in memory wipe "
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


    def run(self):
        """
        run FXE recovery algorithm until timeout or completion
        """
        assert self.fw, "no firmware loaded"

        self.logger.info(f"input path: {self.fw.path}")

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
                self.unexplored.append(
                    Branch(
                        addr=table_offset,
                        raw=b'',
                        target=word,
                        bblock=None,
                        context=context,
                        ret=table_offset))
            table_offset += 4

        while self.unexplored:
            branch = self.unexplored.pop(-1)
            self.explored.append(branch)

            # restore from unexplored branch
            branch.unexplored = False
            self.restore(branch.context)
            if branch.bblock:
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




