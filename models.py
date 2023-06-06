import os
import re
import shutil
import binascii
import subprocess
import shlex
import ctypes
import struct
from os.path import splitext
from copy import deepcopy
from typing import Type, Union
from ctypes import memmove, pointer, sizeof
from tempfile import NamedTemporaryFile
from collections import OrderedDict

import capstone
from capstone import Cs
from capstone.arm_const import *
from elftools.elf.elffile import ELFFile

from utils import *
from ihex import IHex


class FirmwareImage():
    """
    A wrapper class for elf, intel hex, and binary firmware
    """
    RE_PTRN_DISASM = re.compile((
        r" +(?P<addr>[0-9a-fA-F]+):\s+"
        r"(?P<raw>[0-9a-fA-F]+(?: [0-9a-fA-F]+)?)\s+"
        r"(?P<mnemonic>.+)"))

    def __init__(self, path : str, pd : dict,
                base_addr : int,        # base address
                vtbases : list[int],    # list of known vector table offsets
                isa : str = 'armv7e-m', # isa for arm-none-eabi-objdump
                cs : Type[Cs] = None,   # optionally pass in a capstone instance
            ):
        self.path = path
        self.ext = splitext(path)[1]
        self.img = None
        self.disasm = {}
        self.disasm_txt = []
        self.raw = None
        self.isa = isa
        # note: the platform description should be the same as 
        # the one passed to the FFXEngine
        self.pd = pd
        self.cs = cs
        if not cs:
            arch = getattr(capstone, f"CS_ARCH_{pd['cpu']['arch']}")
            mode = 0
            for m in pd['cpu']['mode']:
                mode |= getattr(capstone, f"CS_MODE_{m}")
            self.cs = Cs(arch, mode)

        # elf format
        if self.ext == '.elf':
            # load img from file
            self.img = ELFFile.load_from_path(path)

            # disassemble the file using objdump
            self.disasm_txt = subprocess.run(
                shlex.split(f"arm-none-eabi-objdump -d -m{isa} {path}"),
                stdout=subprocess.PIPE,
            ).stdout.decode('utf-8').split('\n')

            # convert tabs to spaces (maintaining visual spacing)
            for i, line in enumerate(self.disasm_txt):
                newline = []
                for j, char in enumerate(line):
                    if char == '\t':
                        newline.append(' '*(4 - (j % 4)))
                    else:
                        newline.append(char)
                self.disasm_txt[i] = ''.join(newline)


            # construct addr-to-line mapping and disasm dict
            # useful for pretty printing later
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
                    
                    # NOTE: specific to nRF52832 elf.
                    # deal with the delay block specially
                    # objdump doesn't treat it as instructions
                    # when disassembling from elf since it's in .data
                    # only relevant for unit testing purposes (not using elf for real-world)
                    if (("3803 d8fd" in match.group('raw')
                            and "4770 0000" in match.group('mnemonic'))
                            or "d8fd3803 00004770" in match.group('raw')):
                        self.disasm[addr + 2] = self.disasm[addr]
                        self.disasm[addr + 4] = self.disasm[addr]

            # construct raw binary
            self.raw = b""
            for seg in sorted(self.img.iter_segments(),
                    key=lambda seg: seg['p_paddr']):
                if seg['p_paddr'] >= len(self.raw):
                    self.raw += b'\x00' * (seg['p_paddr'] - len(self.raw))
                    self.raw += seg.data()
                elif seg['p_paddr'] < len(self.raw):
                    if (seg['p_paddr'] + seg['p_memsz']) < len(self.raw):
                        # segment goes in area already defined
                        self.raw[seg['p_paddr']:seg['p_paddr'] + seg['p_memsz']] = seg.data()
                    else:
                        self.raw = self.raw[:seg['p_paddr']] + seg.data()

        # raw bin format
        elif self.ext == '.bin':
            # load img from file
            with open(path, 'rb') as binfile:
                self.img = binfile.read()
            self.raw = self.img

        # intel hex format
        elif self.ext == '.hex':
            self.img = IHex(path)
            self.raw = self.img.raw

        else:
            raise Exception("fw image file must be elf, ihex, or binary")

        self.size = len(self.raw)

        self.base_addr = base_addr
        self.vector_tables = {
            base: self.raw[base-self.base_addr:base-self.base_addr+self.pd['vt']['size']] \
            for base in vtbases
        }


    def disasm_chunk(self, address : int, size : int):
        """disassemble only the indicated chunk and return the
        disassembly as a list of strings
        using arm-none-eabi-objdump
        """
        assert 0 <= address < self.size, "invalid address"
        assert address + size < self.size, "block out of bounds"

        # make sure address is even
        address = address & (~1)

        # binary chunk to disassemble
        chunk = self.raw[address:address + size]

        # # disassembling with objdump, but this is extremely slow...
        # # going to need to default to capstone despite its obvious bugs
        # with NamedTemporaryFile() as ntf:
        #     # write block to temporary file for objdump
        #     ntf.write(self.raw[address:address + size])
        #     ntf.flush()

        #     block_txt = subprocess.run([
        #             'arm-none-eabi-objdump', 
        #             '-bbinary',
        #             f'-m{self.isa}',
        #             '-Mforce-thumb',
        #             f'--adjust-vma={hex(address)}',
        #             '-D', ntf.name],
        #         stdout=subprocess.PIPE,
        #     ).stdout.decode('utf-8').split('\n')

        # disasm_txt = []
        # for line in block_txt:
        #     if not self.RE_PTRN_DISASM.search(line):
        #         # found actual disassembly line
        #         continue

        #     # convert tabs to spaces (maintaining visual spacing)
        #     newline = []
        #     for j, char in enumerate(line):
        #         if char == '\t':
        #             newline.append(' '*(4 - (j % 4)))
        #         else:
        #             newline.append(char)
        #     disasm_txt.append(''.join(newline))

        # helper function to format bytes
        format_bytes = lambda b: b''.join([c[::-1] for c in chunks(2, b)]).hex(' ', 2)

        disasm_txt = []
        for (offset, insn_size, mnemonic, opstring) in self.cs.disasm_lite(chunk, offset=0):
            disasm_txt.append("{:>8x}: {:<10} {:<5} {}".format(
                address + offset,
                format_bytes(chunk[offset:offset+insn_size]),
                mnemonic,
                opstring
            ))

        return disasm_txt


    def disassemble(self, cfg : dict):
        """disassemble all blocks in cfg 
        and update current disasm properties
        """
        # assuming that no blocks overlap
        disasm_txt = []
        # add the vector table to the disassembly
        for i, chunk in enumerate(chunks(4, self.raw[:0x200])):
            val = int.from_bytes(chunk, 'little')
            disasm_txt.append(
                "{:>8x}: {:08x}  .word    0x{:08x}".format(
                    i * 4, # table offset
                    val,
                    val,
            ))

        # add all disassembled basic blocks to disasm_txt
        for (addr, size) in sorted(cfg['nodes']):
            disasm_txt.extend(self.disasm_chunk(addr-self.base_addr, size))
            disasm_txt.append('')

        self.disasm_txt = disasm_txt
        self.disasm = {}

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


    def annotated_disasm(self, cfg : dict):
        """print the disassembly with CFG edge representation
        expects edges to be instruction addr to instruction addr
            instead of block to block
        """
        assert 'nodes' in cfg and 'edges' in cfg, \
            "cfg missing nodes and edges"
        assert isinstance(cfg['nodes'], set) and isinstance(cfg['edges'], set), \
            "cfg nodes and edges should be sets of tuples"

        if not self.disasm_txt:
            # disassemble using cfg if not done so yet
            self.disassemble(cfg)

        edges = deepcopy(cfg['edges'])
        nodes = deepcopy(cfg['nodes'])
        base_addr = self.pd['mmap']['flash']['address']

        remove = []
        for n in [n for n in nodes if None in n]:
            print(f'cannot print bad node: {n}')
            nodes.remove(n)

        iedges = list(edges)

        # create an arrows matrix that runs accross the side of the 
        # disassembly. fill in the small arrows at the bottom and work up
        arrows = [{addr: '\u2500' for addr in sorted(self.disasm.keys())}]
        iedges.sort(key=lambda e: (max(e) - min(e), min(e)))

        for edge in iedges:

            start = min(edge) - base_addr
            end = max(edge) - base_addr

            if start not in self.disasm or end not in self.disasm:
                print(f"invalid edge: ({hex(edge[0])}, {hex(edge[1])})")
                continue

            i = start
            col = 0
            # determine which column arrow can go in
            while i <= end:
                if i in arrows[col]:
                    # valid address, check for collision
                    while arrows[col][i] != '\u2500':
                        # collision, go up a column
                        if col == len(arrows) - 1:
                            arrows.append({addr: '\u2500' for addr in sorted(self.disasm.keys())})
                        col += 1
                        i = start
                i += 2

            # now draw the arrow
            i = start
            direction = 'down' if start == edge[0] else 'up'

            if start == end:
                # handle the self loop case
                arrows[col][start] = '\u25c9'
            else:
                while i <= end:
                    if i in arrows[col]:
                        sym = '\u2503' # arrow shaft
                        if i == start:
                            if direction == 'down':
                                sym = '\u2533' # down end
                            else:
                                sym = '\u25b2' # up arrowhead
                        elif i == end:
                            if direction == 'down':
                                sym = '\u25bc' # down arrowhead
                            else:
                                sym = '\u253b' # up end
                        arrows[col][i] = sym
                    i += 2

        # now transpose the arrows matrix
        vert_arrows = {
            addr: ''.join([col[addr] for col in reversed(arrows)]) for addr in arrows[0]
        }

        # now append to all the lines of the disassembly text
        blank = '\u2500' * len(arrows)
        prepend = blank
        disptxt = []
        p = re.compile(r'^ +')
        for i, line in enumerate(self.disasm_txt):
            match = self.RE_PTRN_DISASM.search(line)
            if match:
                addr = int(match.group('addr'), base=16)
                if addr in vert_arrows:
                    prepend = vert_arrows[addr]
            else:
                tmp = []
                for c in prepend:
                    if c in ['\u2533', '\u25b2']:
                        tmp.append('\u2503')
                    elif c in ['\u253b', '\u25bc', '\u25c9']:
                        tmp.append('\u2500')
                    else:
                        tmp.append(c)
                prepend = ''.join(tmp)
            line = p.sub(lambda x: x.group().replace(' ', '\u2500'), line)
            disptxt.append(f"{prepend}{line}")

        return disptxt

    def print_cfg(self, cfg : dict):
        disptxt = self.annotated_disasm(cfg)
        print('\n'.join(disptxt))


class BBlock():
    """
    A class for basic block information
    """
    __slots__ = [
        'addr',             # starting address of the block
        'size',             # block size in bytes
        'insns',            # dict of capstone instructions in block
        'quota',            # execution quota
        'contrib',          # contributes to indirect branch
        'indirect',         # is indirect branch block
        'returns',          # ends in return (sp change then bx)
        'fn_addr',          # starting address of the block's function
        'direct_target',    # if a direct branch (conditional or otherwise)
        'isrs',             # set of isrs the block belongs to
        'parents',          # set of parent (precursor) blocks (actual instances)
        'children',         # set of child (successor) blocks (actual isntances)
        'mem_log',          # list of memory access tuples
        'bytes',            # block data bytes (bytearray)
        'delete',           # whether block is marked for delete
    ]

    def __init__(self, address, size, insns, fn_addr, bytedata, 
            parent : Type['BBlock']=None, 
            isr : int=0,
            contrib : bool=False, 
            indirect : bool=False, 
            target : int=None,
            returns : bool=False):
        self.addr = address             
        self.size = size                
        self.insns = insns    
        self.quota = 1                  
        self.contrib = contrib          
        self.indirect = indirect        
        self.returns = returns          
        self.fn_addr = fn_addr          
        self.direct_target = target     
        self.isrs = {isr}               
        # parents and children are lists of basic blocks, not addresses
        self.parents = {parent} if parent else set()
        self.children = set()
        self.mem_log = []
        self.bytes = bytedata
        self.delete = False
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
        return "<BBlock @ 0x{:08X} : 0x{:08X}>".format(
            self.addr, self.addr + self.size)

    def __str__(self):
        return (
            "[ BBlock @ 0x{:08X}\n".format(self.addr) +
            "    size     : {}\n".format(hex(self.size)) +
            "    fn_addr  : {}\n".format(hex(self.fn_addr)) +
            "    contrib  : {}\n".format(str(self.contrib)) +
            "    indirect : {}\n".format(str(self.indirect)) +
            "    returns  : {}\n".format(str(self.returns)) + 
            "    delete   : {}\n".format(str(self.delete)) +
            "    parents  : [ {} ]\n".format((',\n' + ' '*16).join([repr(b) for b in self.parents])) +
            "    children : [ {} ]\n".format((',\n' + ' '*16).join([repr(b) for b in self.children])) +
            "]"
        )

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.addr == other.addr
        return False

    def __hash__(self):
        return self.addr

    def fmt_mem_log(self):
        return '\n'.join(["pc:0x{:x} {} 0x{:08X} @ 0x{:08X}".format(
            *entry) for entry in self.mem_log])

    def __copy__(self):
        # a basic block is unique and cannot be copied
        return self

NullBlock = BBlock(address=0, size=0, insns={}, fn_addr=0, bytedata=b'')


class CFG():
    """
    class for CFG
    """
    def __init__(self):
        self.bblocks = {}   # BBlock objects referenced by address
        self.edges = set()  # tuples of bblock addresses
        self.removed_edges = []
        self.removed_blocks = []

    def is_new_block(self, address):
        """check if block has not yet been added to cfg"""
        return address not in self.bblocks

    def connect_block(self, bblock : Union[BBlock], parent : Type[BBlock] = None):
        """add a basic block to the cfg. returns true if successful"""
        connected = False
        if bblock.addr not in self.bblocks:
            self.bblocks[bblock.addr] = bblock
            connected = True
        if isinstance(parent, BBlock):
            self.edges.add((parent.addr, bblock.addr))
            bblock.parents.add(parent)
            parent.children.add(bblock)
            connected = True
        return connected

    def remove_block(self, bblock : Union[BBlock, int]):
        """remove a block from the cfg"""
        # remove the block from the bblocks dict
        # remove any edge connecting the block in the cfg
        address = bblock
        if isinstance(bblock, BBlock):
            address = bblock.addr
        if address in self.bblocks:
            # remove block from bblock list
            bblock = self.bblocks.pop(address)
            self.removed_blocks.append(bblock)
            # remove edges from edge list
            for e in [e for e in self.edges if bblock.addr in e]:
                self.edges.remove(e)
            # remove from parents' child list
            for parent in bblock.parents:
                if bblock in parent.children:
                    parent.children.remove(bblock)
            # remove from children's parent list
            for child in bblock.children:
                if bblock in child.parents:
                    child.parents.remove(bblock)

    def remove_block_func_edges(self, bblock : Union[BBlock, int], fn_addr : int,
            protected : set = set()):
        """used to remove parent edges with the given function address"""
        # get block
        if isinstance(bblock, int):
            if bblock not in self.bblocks:
                return
            bblock = self.bblocks[bblock]
        # get parent blocks that match fn_addr
        invalid_parents = [
            parent for parent in bblock.parents \
                if parent.fn_addr == fn_addr]
        # remove found edges
        for parent in invalid_parents:
            edge = (parent.addr, bblock.addr)
            if parent == NullBlock or edge in protected:
                continue
            self.edges.remove(edge)
            bblock.parents.remove(parent)
            parent.children.remove(bblock)
            self.removed_edges.append(edge)

    def backward_reachability(self, bblock : Type[BBlock], ib=True):
        """find all intraprocedural contributing blocks for given block"""
        # explore predecessors in BFS fashion
        queue = [bblock]
        fn_addr = bblock.fn_addr
        visited = []
        current = None
        # breakpoint()
        while queue:
            current = queue.pop(0)

            if current in visited:
                continue

            # print(current)
            if ib:
                current.contrib = 1
            # if current.quota <= 0:
            #     current.quota = 1
            # else:
            #     current.quota += 1
            current.quota += 1
            visited.append(current)
            for parent in current.parents:
                if (parent.fn_addr == fn_addr 
                        and parent not in queue
                        and parent not in visited):
                    queue.append(parent)

    def forward_reachability(self, bblock : Type[BBlock]):
        """find all return points for given block's function"""
        fn_addr = bblock.fn_addr
        ret_blocks = []
        for block in self.bblocks.values():
            if (block != bblock
                    and block.fn_addr == fn_addr
                    and block.returns):
                ret_blocks.append(block)

        return ret_blocks

    def inc_quota_forward(self, bblock : Type[BBlock]):
        """find intraprocedural contributing forward blocks"""
        queue = [bblock]
        fn_addr = bblock.fn_addr
        visited = []
        current = None

        while queue:
            current = queue.pop(0)
            current.quota += 1
            if current.quota > 1:
                current.quota = 1
            visited.append(current)
            for child in current.children:
                if (child.fn_addr == fn_addr 
                        and child not in visited
                        and (child.contrib or child.indirect)):
                    queue.append(child)

    def reset_quotas(self):
        """reset quotas for all blocks in cfg"""
        for addr, block in self.bblocks.items():
            block.quota = 1

    def split_block(self, bblock : Type[BBlock], subblock : Type[BBlock]):
        """bblock overlaps with subblock. split bblock and make subblock its child"""
        # remove overlap
        bblock.size = subblock.addr - bblock.addr
        # bblock no longer ends in a branch, so cannot be indirect or return block
        bblock.indirect = False
        bblock.returns = False
        # bblock now has edge to former subblock
        # subblock's children is union'ed with bblock
        # bblock's only child is now subblock, 
        # add bblock as parent to subblock in addition to existing parents
        self.edges.add((bblock.addr, subblock.addr))
        subblock.children.union(
            set([b for b in bblock.children if b not in subblock.children]))
        bblock.children = [subblock]
        subblock.parents.add(bblock)

    def resolve_blocks(self):
        """resolve all overlapping blocks and remove hanging blocks"""
        addrs = list(sorted(self.bblocks.keys()))
        for i, addr1 in enumerate(addrs):
            if (i < len(addrs) - 1):
                block1 = self.bblocks[addr1]
                block2 = self.bblocks[addrs[i+1]]
                if (block1 != block2
                        and block2.addr < block1.addr + block1.size):
                    # found overlapping blocks, split bigger one (always block 1)
                    self.split_block(block1, block2)

        for addr in addrs:
            # remove floating blocks and blocks marked for delete
            if ((not self.bblocks[addr].parents
                    and not self.bblocks[addr].children)
                    or self.bblocks[addr].delete):
                self.remove_block(self.bblocks[addr])


    # def to_networkx(self):
    #     """convert the cfg to a networkx digraph"""


