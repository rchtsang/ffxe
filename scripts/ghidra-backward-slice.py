#Construct a backward slice of function arguments for a target function
#@author    rchtsang
#@category  Analysis
#@keybinding 
#@menupath 
#@toolbar 

import os
import argparse
from os.path import splitext, realpath, dirname, exists
from pathlib import Path
from itertools import islice
from time import perf_counter
from collections import namedtuple
from copy import copy

import dill
import yaml

from java.awt import Color
from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import PcodeOp


# Backward slice is constructed based on Pcode Varnodes of disassembled instructions
# Address of target function is provided to script
# Scan target function for varnode input parameters
#   - DFS sequentially scan Pcode input and output varnodes. 
#       Any inputs that appear that do not already appear in outputs are likely parameters
#   - with identified input varnodes, backward slice along global CFG
#       instruction-level backward reachability on identified varnodes
#       make sure to also backtrack along write references for reads
#   - backward slices are identified when there are no non-special registers or unique varnodes
#       in the current set of unresolved input varnodes

# NOTE: it's hard to figure out which arguments were passed on stack,
# so I won't bother with it in this script. It should be doable with 
# varnodes as well, but harder to find, since it involves logic based
# on SP varnode and constant varnode inputs to LOAD. 

REG_VARNODE_OFFSETS = {
    0x20: 'r0',
    0x24: 'r1',
    0x28: 'r2',
    0x2c: 'r3',
    0x30: 'r4',
    0x34: 'r5',
    0x38: 'r6',
    0x3c: 'r7',
    0x40: 'r8',
    0x44: 'r9',
    0x48: 'r10',
    0x4c: 'r11',
    0x50: 'r12',
    0x54: 'sp',
    0x58: 'lr',
    0x5c: 'pc',
}

ARG_REG_OFFSETS = [0x20, 0x24, 0x28, 0x2c]


def iterate(iterable):
    """utility for iterating over java iterable"""
    while iterable.hasNext():
        yield iterable.next()
    return


def getFunctionInputVarnodes(func, sbmodel, listing):
    """gets all non-constant input varnodes to function"""
    # during forward traversal of function basic blocks, determine input varnodes
    # used (sequentially)
    # exclude any intermediate varnodes (varnodes that have previously appeared as outputs)
    func_addresses = func.getBody()
    func_blocks = list(iterate(sbmodel.getCodeBlocksContaining(func_addresses, monitor)))
    SearchState = namedtuple('SearchState', ['block', 'outputs'])

    # initialize DFS with function entry block
    visited = []
    inputs = set()
    queue = [
        SearchState(
            sbmodel.getCodeBlockAt(func.getEntryPoint(), monitor),
            set(),
        )
    ]

    while queue:
        state = queue.pop(-1)
        visited.append(state.block)
        outputs = copy(state.outputs)

        # scan block for actual varnode inputs
        # update the outputs list
        block_insns = list(iterate(listing.getInstructions(state.block, True)))
        for insn in block_insns:
            for pcode_op in insn.getPcode():
                for varnode in pcode_op.getInputs():
                    if varnode not in outputs:
                        inputs.add(varnode)
                    outputs.add(pcode_op.getOutput())

        # add successor blocks to search list
        for block_ref in iterate(state.block.getDestinations(monitor)):
            successor_block = block_ref.getDestinationBlock()
            if (successor_block in func_blocks
                    and successor_block not in visited):
                queue.append(SearchState(successor_block, outputs))

    # keep only function argument varnodes
    inputs = set([varnode for varnode in inputs if (
        varnode.isRegister() and varnode.getOffset() in ARG_REG_OFFSETS)])

    return inputs


def isUnresolvedRegister(varnode):
    """helper function to check if varnode corresponds to r0-12 (needs to be resolved)"""
    return varnode.isRegister() and 0x20 <= varnode.getOffset() <= 0x50


def inputsResolved(input_varnodes):
    """
    helper function to check if any varnodes are still unresolved
    returns false if any varnode corresponds to registers r0-12 or is unique
    returns true otherwise
    """
    return not any([(
        varnode.isUnique() or isUnresolvedRegister(varnode)
        ) for varnode in input_varnodes])



parser = argparse.ArgumentParser(prog='ghidra-backward-slice.py', description=__doc__)
parser.add_argument('fn_start_address', type=lambda arg: int(arg, base=0), nargs='?', default=None,
    help="starting address of sink function")
parser.add_argument('--headless', dest='headless', action='store_true', 
    help="add flag if running script in headless mode. (fn_start_address required)")

if __name__ == '__main__':
    args = parser.parse_args(getScriptArgs())

    if args.headless:
        assert args.fn_start_address, "function start address argument required in headless mode"
        args.fn_start_address = toAddr(args.fn_start_address)
    else:
        args.fn_start_address = askAddress(
            "Sink Function Address", "Enter sink function start address:")

    SearchState = namedtuple('SearchState', 
        ['blockPath', 'currentInsn', 'currentInputs', 'dataPath'])

    sink_function = getFunctionAt(args.fn_start_address)
    sbmodel = SimpleBlockModel(currentProgram, True)
    listing = currentProgram.getListing()

    sink_inputs = getFunctionInputVarnodes(sink_function, sbmodel, listing)
    sink_entry_block = sbmodel.getCodeBlockAt(sink_function.getEntryPoint(), monitor)

    calling_blocks = []
    for ref in iterate(sink_entry_block.getSources(monitor)):
        calling_blocks.append(
            sbmodel.getFirstCodeBlockContaining(ref.getReferent(), monitor))

    # conduct BFS to generate backward slice
    initial_states = [
        SearchState(
            [block], 
            None,
            copy(sink_inputs), 
            [getInstructionAt(sink_function.getEntryPoint())],
        ) for block in calling_blocks
    ]

    # visited_blocks = []
    queue = initial_states
    slices = []

    while queue:
        state = queue.pop(0)
        # print(state.blockPath[0])

        # parse block in reverse order
        for insn in iterate(listing.getInstructions(state.blockPath[0], False)):
            if state.currentInsn and insn != state.currentInsn:
                # if starting from within block, iterate until 
                # current instruction is reached
                continue

            refs = insn.getReferencesFrom()
            refs = list(refs) if refs else []

            for op in reversed(insn.getPcode()):
                output_varnode = op.getOutput()
                input_varnodes = list(op.getInputs())
                
                if output_varnode in state.currentInputs:
                    state.currentInputs.remove(output_varnode)

                    if state.dataPath[-1] != insn:
                        state.dataPath.append(insn)

                    for input_varnode in input_varnodes:
                        if (input_varnode.isRegister()
                                or input_varnode.isUnique()):
                            state.currentInputs.add(input_varnode)

                match op.getOpcode():
                    case PcodeOp.LOAD if refs:
                        # load instructions may reference an address
                        for ref in refs:
                            data_addr = ref.getToAddress()

                            if not data_addr.getAddressSpace().isMemorySpace():
                                break

                            for data_ref in getReferencesTo(data_addr):
                                if data_ref.getReferenceType().isWrite():
                                    print("Found data reference!", data_ref)
                                    new_path = copy(state.blockPath)
                                    new_path.insert(0, 
                                        sbmodel.getFirstCodeBlockContaining(data_ref.getFromAddress(), monitor))
                                    queue.insert(0, SearchState(
                                        new_path,
                                        getInstructionAt(data_ref.getFromAddress()),
                                        copy(state.currentInputs),
                                        copy(state.dataPath)
                                    ))

                    case PcodeOp.STORE:
                        # store instructions have no outputs
                        # but can be part of the datapath. consider separately
                        state.dataPath.append(insn)

                        for input_varnode in input_varnodes:
                            if (input_varnode.isUnique() 
                                    and input_varnode in state.currentInputs
                                    and state.dataPath[-1] != insn):
                                state.dataPath.append(insn)

                        for input_varnode in input_varnodes:
                            if (input_varnode.isRegister()
                                    or input_varnode.isUnique()):
                                state.currentInputs.add(input_varnode)

        # if all input varnodes resolved (no r0-r12 or unique varnodes in currentInputs)
        # add current datapath to list of slices and explore next path
        # otherwise, continue backward search to predecessors in graph
        if inputsResolved(state.currentInputs):
            slices.append(copy(state))
        else:
            for source_block_ref in iterate(state.blockPath[0].getSources(monitor)):
                source_block = source_block_ref.getSourceBlock()
                if source_block in state.blockPath:
                    continue
                new_path = copy(state.blockPath)
                new_path.insert(0, source_block)
                queue.insert(0, SearchState(
                    new_path,
                    None,
                    copy(state.currentInputs),
                    copy(state.dataPath)
                ))

    print("Data Slices:")
    for i, slice_state in enumerate(slices):
        # highlight basic blocks involved
        for block in slice_state.blockPath:
            setBackgroundColor(block, Color(245, 227, 66, 32))
            
        print(f"Slice {i}")
        for insn in reversed(slice_state.dataPath):
            refs = insn.getReferencesFrom()
            refs = list(refs) if refs else []
            print('\t', insn.getAddress(), '\t', insn)
            setBackgroundColor(insn.getAddress(), Color(245, 144, 66, 96))
            if refs:
                for ref in refs:
                    print('\t\t', ref)
        print()
