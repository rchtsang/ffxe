import os
import sys
import argparse
from os.path import (
    basename, splitext, exists, realpath, 
    dirname, relpath, isdir
)
from importlib import import_module
from copy import deepcopy
from glob import glob
from time import perf_counter
from datetime import datetime
from itertools import islice
from pathlib import Path

import yaml
import dill
import angr

from IPython import embed

"""
script to get angr cfgs for all real-world firmware examples
"""

make_timestamp = lambda: datetime.now().strftime('%y%m%d-%H%M%S')

PARENT_DIR = dirname(realpath(__file__))
PROJ_ROOT = dirname(PARENT_DIR)
SAMPLES_DIR = f"{PROJ_ROOT}/examples/real-world"
OUT_DIR = f"{PROJ_ROOT}/tests/cfgs/real-world"


def chunks(n, b):
    """generator utility func for iterating over chunks of a byte string"""
    it = iter(b)
    while True:
        chunk = bytes(islice(it, n))
        if not chunk:
            return
        yield chunk
        
def load_pd(path):
    """utility for loading platform description file"""
    assert exists(path), "file doesn't exist: {}".format(path)
    assert splitext(path)[1] in ['.yml', '.yaml'], \
        "file not YAML: {}".format(path)

    with open(path, 'r') as yf:
        return yaml.load(yf, yaml.Loader)

def get_main_entry(fw_path):
    """utility for getting main entrypoint at fixed address 0x4"""
    with open(fw_path, 'rb') as f:
        f.seek(0x4),
        return int.from_bytes(f.read(4), 'little')

def get_entrypoints(fw_path, pd=None, base_addr=None, vtbases=[0]):
    """utility for getting firmware entrypoints from vector table"""
    base = 0        # assume flash base address is 0
    vtsize = 8      # this gets only the entrypoint at offset 0x4

    if pd:
        base = pd['mmap']['flash']['address'] if base_addr is None else base_addr
        vtsize = pd['vt']['size']

    if 'MCLASS' in pd['cpu']['mode']:
        vector_tables = []
        with open(fw_path, 'rb') as f:
            for vtbase in sorted(vtbases):
                f.seek(vtbase - base_addr)
                vector_tables.append(f.read(vtsize))

        entrypoints = []
        for vector_table_bytes in vector_tables:
            for chunk in chunks(4, vector_table_bytes[4:]):
                word = int.from_bytes(chunk, 'little')
                if word:
                    entrypoints.append(word)
    else: # assume ARM entrypoints
        entrypoints = range(base, base + vtsize + 1, 4)

    return list(set(entrypoints))

## angr helper functions

def load_proj(path : str, 
        arch='cortex-m', base_addr=None, entry=None) -> angr.project.Project:
    options = {
        'backend': 'blob',
        'arch': arch,
    }
    if base_addr:
        options['base_addr'] = base_addr
    if entry:
        options['entry_point'] = entry

    try:
        p = angr.Project(path,
            load_options={
                'auto_load_libs': False,
                'main_opts': options
            })
    except AttributeError as e:
        print(f"couldn't load {path}: {e}", file=sys.stderr)
        exit(1)
    return p

def make_connected_cfg(cfg : angr.analyses.cfg.CFGBase, entrypoints : list[int]):
    """make cfg with nodes only reachable from entrypoints"""

    connected_cfg = {
        'nodes': set(),
        'edges': set()
    }

    # starting at each entrypoint, do bfs to get all reachable nodes
    for entrypoint in entrypoints:
        start = cfg.get_node(entrypoint)

        if not start:
            continue
        
        queue = [start]

        while queue:
            block = queue.pop(0)

            if not block or not block.size:
                print(f"{hex(entrypoint)} not a block!")
                continue

            blocktuple = (
                block.addr & (~1), 
                block.size
            )

            if blocktuple in connected_cfg['nodes']:
                continue

            connected_cfg['nodes'].add(blocktuple)

            for child in block.successors:
                if child.size:
                    connected_cfg['edges'].add((
                        block.instruction_addrs[-1] & (~1),
                        child.addr & (~1)
                    ))
                    queue.append(child)

    return connected_cfg


parser = argparse.ArgumentParser(prog="test-real.py", description=__doc__)
parser.add_argument('--targets', nargs='+', type=str, default=None,
    help="specify folders of target real-world firmware to analyze")
parser.add_argument('--outdir', type=str, default=f"{PARENT_DIR}",
    help="destination directory for results table")

if __name__ == "__main__":
    args = parser.parse_args()

    if not args.targets:
        args.targets = sorted(glob(f"{SAMPLES_DIR}/*/"))
    else:
        args.targets = [realpath(path) for path in args.targets]

    generated_cfgs = {}
    result_table = []

    if not isdir(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    for target in args.targets:
        generated_cfgs[target] = {} 
        print(f"analyzing target: {target}")
        try:
            assert isdir(target), \
                "target is not a directory: {}".format(target)
            
            assert len(binfiles := glob(f"{target}/*.bin")) == 1, \
                "there must be exactly one firmware image binary in {}".format(target)
            assert len(ymlfiles := glob(f"{target}/*.yml")) == 1, \
                "there must be exactly one platform description yaml in {}".format(target)

            assert exists(ghidra_config_path := f"{target}/ghidra.config"), \
                "real-world firmware analysis requires ghidra.config yaml file!"

            fw_path = binfiles[0]
            pd_path = ymlfiles[0]
            fw_name = splitext(basename(fw_path))[0]
            base_addr = 0
            vtbases = ['0x0']

            # check if target has specified base address
            if exists(base_addr_path := f"{target}/base_addr.txt"):
                with open(base_addr_path, 'r') as file:
                    base_addr = int(file.read().strip(), 0)
                print("specified base address: {}".format(hex(base_addr)))

            # check if target has specified vector table offsets
            # should be a file named `vtbases` containing a comma-separated
            # list of offsets in hexadecimal (preferably with leading `0x`)
            if exists(vt_bases_path := f"{target}/vtbases.txt"):
                with open(vt_bases_path, 'r') as file:
                    vtbases = file.read().split(',')
            print("vector table offsets: {}".format(
                ' '.join(vtbases)))
            vtbases = [int(b, 16) for b in vtbases]


        except AssertionError as e:
            print(e)
            continue

        pd = load_pd(pd_path)
        main_entry = get_main_entry(fw_path)

        # load angr project
        # load cortex-m by default for now
        proj = load_proj(fw_path, 
            arch='cortex-m',
            base_addr=base_addr,
            entry=main_entry)

        entrypoints = get_entrypoints(fw_path, 
            pd=pd, base_addr=base_addr, vtbases=vtbases)

        print("starting static recovery...")
        # do static cfg recovery
        t = perf_counter()
        cfg_fast = proj.analyses.CFGFast(
            function_starts=entrypoints,
            force_complete_scan=False,
            normalize=True
        )
        fast_elapsed = perf_counter() - t
        generated_cfgs[target]['fast'] = cfg_fast

        # format and save static cfg result
        fast_graph = {
            'nodes': set([(node.addr & (~1), node.size) for node in cfg_fast.nodes() if node.size]),
            'edges': set([(n1.instruction_addrs[-1] & (~1), n2.addr & (~1)) \
                for (n1, n2) in cfg_fast.graph.edges() if n1.instruction_addrs])
        }
        with open(f"{OUT_DIR}/{fw_name}-angr_fast-cfg.pkl", 'wb') as pklfile:
            dill.dump(fast_graph, pklfile)

        connected_graph = make_connected_cfg(cfg_fast, entrypoints)

        with open(f"{OUT_DIR}/{fw_name}-angr_cnnctd-cfg.pkl", 'wb') as pklfile:
            dill.dump(connected_graph, pklfile)

        # do dynamic cfg recovery
        # assume any exception is fault of emulated analysis and fail it entirely
        print("starting dynamic recovery...")
        try:
            t = perf_counter()
            cfg_emu = proj.analyses.CFGEmulated(
                starts = entrypoints,
                normalize=True
            )
            emu_elapsed = perf_counter() - t
            generated_cfgs[target]['emu'] = cfg_emu

            # format dynamic cfg result
            emu_graph = {
                'nodes': set([((node.addr & (~1)), node.size) for node in cfg_emu.nodes() if node.size]),
                'edges': set([(n1.instruction_addrs[-1] & (~1), n2.addr & (~1)) \
                    for (n1, n2) in cfg_emu.graph.edges() if n1.instruction_addrs])
            }

        except Exception as e:
            emu_elapsed = perf_counter() - t
            print("dynamic recover encountered error:\n", e)
            emu_graph = {
                'nodes': set(),
                'edges': set()
            }

        # save dynamic cfg result
        with open(f"{OUT_DIR}/{fw_name}-angr_emu-cfg.pkl", 'wb') as pklfile:
            dill.dump(emu_graph, pklfile)

        results = (
            "  \"{}\": {{\n".format(basename(fw_path)) +
            "{:<35} \"fast\" : {{ \"blocks\": {:>5d}, \"edges\": {:>5d}, \"elapsed\": \"{} s\" }},\n".format(
                '', 
                len(fast_graph['nodes']), 
                len(fast_graph['edges']), 
                fast_elapsed) + 
            "{:<35} \"cnxd\" : {{ \"blocks\": {:>5d}, \"edges\": {:>5d}, \"elapsed\": \"{} s\" }},\n".format(
                '', 
                len(connected_graph['nodes']), 
                len(connected_graph['edges']), 
                'n/a') + 
            "{:<35} \"emu\"  : {{ \"blocks\": {:>5d}, \"edges\": {:>5d}, \"elapsed\": \"{} s\" }}\n  }}".format(
                '',
                len(emu_graph['nodes']),
                len(emu_graph['edges']),
                emu_elapsed)
        )

        print(results)

        # append results to table
        result_table.append(results)

    print("\n\n")
    print('\n'.join(result_table))
    # with open(f'{PARENT_DIR}/angr-real-world-cfg-results.txt', 'w') as f:
    #     f.write('\n'.join(table))


