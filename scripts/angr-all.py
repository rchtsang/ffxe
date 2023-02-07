import os
import sys
from os.path import realpath, dirname, basename, splitext
from glob import glob
from time import perf_counter

import dill
import angr

"""
script to get angr cfgs for all firmware examples
"""

PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")

def load_proj(path : str) -> angr.project.Project:
    try:
        p = angr.Project(path,
            load_options={
                'auto_load_libs': False,
                'main_opts': {
                    'backend': 'blob',
                    'arch': 'cortex-m',
                },
            })
    except AttributeError as e:
        print(f"couldn't load {path}: {e}", file=sys.stderr)
        exit(1)
    return p

def get_cortexm_entry_points(path : str):
    entry_points = []
    with open(path, 'rb') as f:
        loc = 0x4
        while loc < 0x200:
            f.seek(loc)
            entry_points.append(
                int.from_bytes(f.read(4), 'little'))
            loc += 4
    return entry_points

if __name__ == "__main__":

    fw_examples = glob('examples/*.bin')

    ffxe_cfgs = {}

    table = []
    for fw_path in sorted(fw_examples):
        # get fw name
        (name, ext) = splitext(basename(fw_path))

        # load fw to angr
        proj = load_proj(fw_path)
        entry_points = get_cortexm_entry_points(fw_path)

        # do static cfg recovery
        t = perf_counter()
        cfg_fast = proj.analyses.CFGFast(
            function_starts=entry_points,
            force_complete_scan=False
        )
        fast_elapsed = perf_counter() - t

        # save static cfg result
        fast_graph = {
            'nodes': set([(node.addr & (~1), node.size) for node in cfg_fast.nodes()]),
            'edges': set([(n1.instruction_addrs[-1] & (~1), n2.addr & (~1)) for (n1, n2) in cfg_fast.graph.edges() if n1.instruction_addrs])
        }
        with open(f"{PROJ_DIR}/tests/cfgs/{name}-angr_fast-cfg.pkl", 'wb') as pklfile:
            dill.dump(fast_graph, pklfile)

        # do dynamic cfg recovery
        try:
            t = perf_counter()
            cfg_emu = proj.analyses.CFGEmulated(
                starts=entry_points)
            emu_elapsed = perf_counter() - t

            # save dynamic cfg result
            emu_graph = {
                'nodes': set([((node.addr & (~1)), node.size) for node in cfg_emu.nodes()]),
                'edges': set([(n1.instruction_addrs[-1] & (~1), n2.addr & (~1)) for (n1, n2) in cfg_emu.graph.edges() if n1.instruction_addrs])
            }
        except Exception as e:
            print(e, file=sys.stderr)
            emu_graph = {
                'nodes': set(),
                'edges': set()
            }

        with open(f"{PROJ_DIR}/tests/cfgs/{name}-angr_emu-cfg.pkl", 'wb') as pklfile:
            dill.dump(emu_graph, pklfile)

        table.append(
            "{:<25} fast {:>4d} blocks {:>4d} edges   elapsed: {} s\n".format(
                basename(fw_path), 
                len(fast_graph['nodes']), 
                len(fast_graph['edges']), 
                fast_elapsed) + 
            "{:<25} emu  {:>4d} blocks {:>4d} edges   elapsed: {} s".format(
                '',
                len(emu_graph['nodes']),
                len(emu_graph['edges']),
                emu_elapsed))

    print('\n'.join(table))
    with open(f'{PARENT_DIR}/angr-cfg-results.txt', 'w') as f:
        f.write('\n'.join(table))


