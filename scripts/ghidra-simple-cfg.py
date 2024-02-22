#Save minimal cfg of full program using SimpleBlockModel
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

import dill
import yaml

from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.symbol import SourceType

"""
a Ghidrathon script to generate normalized CFGs.

expects some platform description information to locate entry points
"""


def chunks(n, b):
    """generator utility func for iterating over chunks of a byte string"""
    it = iter(b)
    while True:
        chunk = bytes(islice(it, n))
        if not chunk:
            return
        yield chunk

def iterate(iterable):
    """utility for iterating over java iterable"""
    while iterable.hasNext():
        yield iterable.next()
    return


def load_pd(path):
    """utility for loading platform description file"""
    assert exists(path), "file doesn't exist: {}".format(path)
    assert splitext(path)[1] in ['.yml', '.yaml'], \
        "file not YAML: {}".format(path)

    with open(path, 'r') as yf:
        return yaml.load(yf, yaml.Loader)


def get_entrypoints(pd=None, base_addr=None, vtbases=[0]):
    """utility for getting firmware entrypoints from vector table"""
    filepath = currentProgram().getExecutablePath()
    base = 0        # assume flash base address is 0
    vtsize = 8      # this gets only the entrypoint at offset 0x4

    if pd:
        base = pd['mmap']['flash']['address'] if not base_addr else base_addr
        vtsize = pd['vt']['size']

    if 'MCLASS' in pd['cpu']['mode']:
        vector_tables = []
        with open(filepath, 'rb') as f:
            for vtbase in sorted(vtbases):
                f.seek(vtbase - base_addr)
                vector_tables.append(f.read(vtsize))

        entrypoints = []
        for vector_table_bytes in vector_tables:
            for chunk in chunks(4, vector_table_bytes[4:]):
                word = int.from_bytes(chunk, 'little')
                if word:
                    entrypoints.append(word)
    else: # assume ARM
        entrypoints = [base + offset for offset in range(0, 0x1c+1, 4)]

    return list(set(entrypoints))


def buildCFG(program):
    """
    construct the CFG from the disassembly
    exclude any blocks that have no incoming or outgoing edges
    """
    sbmodel = SimpleBlockModel(program)
    # listing = currentProgram().getListing()

    cfg = {
        'nodes': set(),
        'edges': set()
    }

    # iterate over all the simple blocks found in the model
    blockIterator = sbmodel.getCodeBlocks(monitor())
    for block in iterate(blockIterator):
        # if block is isolated (no sources or destinations)
        # do not include it in the cfg
        if (block.getNumSources(monitor()) == block.getNumDestinations(monitor()) == 0):
            continue

        # add block to cfg
        cfg['nodes'].add((
            block.getMinAddress().getOffset(),
            block.getNumAddresses()
        ))

        # get insn edges (CodeBlockReferences)
        for cbref in iterate(block.getDestinations(monitor())):
            cfg['edges'].add((
                cbref.getReferent().getOffset(),
                cbref.getReference().getOffset()
            ))

        # # get block edges (CodeBlockReferences)
        # for cbref in iterate(block.getDestinations(monitor())):
        #   cfg['edges'].add((
        #       cbref.getSourceAddress().getOffset(),
        #       cbref.getDestinationAddress().getOffset()
        #   ))

    return cfg


def buildConnectedCFG(program, entrypoints):
    """
    construct CFG from disassembly, but only save block if 
    it is known to be reachable from an entrypoint
    """
    sbmodel = SimpleBlockModel(program)

    cfg = {
        'nodes': set(),
        'edges': set()
    }

    # starting at each entrypoint, do bfs to get all reachable nodes
    for entrypoint in entrypoints:
        start = sbmodel.getCodeBlockAt(toAddr(entrypoint & (~1)), monitor())
        print("start:", start)
        if not start:
            start = sbmodel.getCodeBlockAt(toAddr(entrypoint), monitor())
            print("new start:", start)
        queue = [start]

        while queue:
            block = queue.pop(0)

            if not block:
                print(f"{hex(entrypoint)} not a block!")
                continue

            blocktuple = (
                block.getMinAddress().getOffset(), 
                block.getNumAddresses()
            )

            if blocktuple in cfg['nodes']:
                continue

            cfg['nodes'].add(blocktuple)

            for cbref in iterate(block.getDestinations(monitor())):
                cfg['edges'].add((
                    cbref.getReferent().getOffset(),
                    cbref.getReference().getOffset()
                ))
                queue.append(cbref.getDestinationBlock())

    return cfg

OUT_DIR = f"{dirname(realpath(__file__))}/../test/cfgs"

parser = argparse.ArgumentParser(prog="ghidra-simple-cfg.py", description=__doc__)
parser.add_argument('outdir', type=str, default=OUT_DIR,
    help="path to output directory")
parser.add_argument('pd', type=str, default=None,
    help="path to platform description file")
parser.add_argument('base_addr', type=lambda v: int(v, 0),
    help="must provide base address. if not known, supply -1")
parser.add_argument('vtbases', nargs='*', type=lambda v: int(v, 0), default=[0],
    help="list of vector table base locations/offsets (assumes 0 otherwise)")


if __name__ == "__main__":
    args = parser.parse_args(getScriptArgs())

    # log_stream = open("/tmp/ghidra-analyze.log", 'a', encoding='utf-8')

    # setup directory for results
    cfg_dir = Path(args.outdir)
    cfg_dir.mkdir(parents=True, exist_ok=True)

    # name cfg
    fw_filename = currentProgram().getName()
    (fw_name, ext) = splitext(fw_filename)
    simple_cfg_name = f"{fw_name}-ghidra_simple-cfg"
    cnnctd_cfg_name = f"{fw_name}-ghidra_cnnctd-cfg"

    print("building cfg for {:<20}".format(fw_filename))

    pd = load_pd(args.pd)
    base = pd['mmap']['flash']['address'] if args.base_addr == -1 else args.base_addr
    print("base address: {}".format(hex(base)))
    entrypoints = get_entrypoints(pd=pd, base_addr=base, vtbases=args.vtbases)
    for entry in entrypoints:
        print(hex(entry))

    currentProgram().setImageBase(toAddr(base), True)

    simple_cfg = buildCFG(currentProgram())
    print("simple cfg: {:>5d} blocks {:>5d} edges".format(
        len(simple_cfg['nodes']), len(simple_cfg['edges'])))

    with open(f"{str(cfg_dir)}/{simple_cfg_name}.pkl", 'wb') as pklfile:
        dill.dump(simple_cfg, pklfile)

    connected_cfg = buildConnectedCFG(currentProgram(), entrypoints)
    print("connected cfg: {:>5d} blocks {:>5d} edges".format(
        len(connected_cfg['nodes']), len(connected_cfg['edges'])))

    with open(f"{str(cfg_dir)}/{cnnctd_cfg_name}.pkl", 'wb') as pklfile:
        dill.dump(connected_cfg, pklfile)


    # log_stream.close()
