#Save minimal cfg of full program
#@author    rchtsang
#@category  Analysis
#@keybinding 
#@menupath 
#@toolbar 

import os
from os.path import splitext, realpath, dirname
from pathlib import Path

import dill

from ghidra.program.model.block import SimpleBlockModel

def iterate(iterable):
    while iterable.hasNext():
        yield iterable.next()
    return

def buildCFG(program):
    sbmodel = SimpleBlockModel(program)
    listing = currentProgram.getListing()

    cfg = {
        'nodes': set(),
        'edges': set()
    }

    # iterate over all the simple blocks found in the model
    blockIterator = sbmodel.getCodeBlocks(monitor)
    for block in iterate(blockIterator):

        # add block to cfg
        cfg['nodes'].add((
            block.getMinAddress().getOffset(),
            block.getNumAddresses()
        ))

        # get insn edges (CodeBlockReferences)
        for cbref in iterate(block.getDestinations(monitor)):
            cfg['edges'].add((
                cbref.getReferent().getOffset(),
                cbref.getReference().getOffset()
            ))

        # # get block edges (CodeBlockReferences)
        # for cbref in iterate(block.getDestinations(monitor)):
        #   cfg['edges'].add((
        #       cbref.getSourceAddress().getOffset(),
        #       cbref.getDestinationAddress().getOffset()
        #   ))

    return cfg

if __name__ == "__main__":
    # setup directory for results
    cfg_dir = Path(dirname(realpath(__file__))) /'..'/'tests'/'cfgs'
    cfg_dir.mkdir(parents=True, exist_ok=True)

    # name cfg
    fw_filename = currentProgram.getName()
    (fw_name, ext) = splitext(fw_filename)
    cfg_name = f"{fw_name}-ghidra-cfg"

    # construct cfg dict
    cfg = buildCFG(currentProgram)

    # save cfg to directory
    with open(f"{str(cfg_dir)}/{cfg_name}.pkl", 'wb') as pklfile:
        dill.dump(cfg, pklfile)
