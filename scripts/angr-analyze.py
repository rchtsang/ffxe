import os
import sys
from os.path import realpath, dirname, basename, splitext, isdir
from glob import glob
from time import perf_counter
from pathlib import Path

import dill
import angr

from IPython import embed

"""
script to get angr cfgs for all firmware examples
"""

PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")
OUT_DIR = f"{PROJ_DIR}/tests/cfgs/unit-tests"

def get_main_entry(fw_path):
    """utility for getting main entrypoint at fixed address 0x4"""
    with open(fw_path, 'rb') as f:
        f.seek(0x4),
        return int.from_bytes(f.read(4), 'little')

def load_proj(path : str) -> angr.project.Project:
    try:
        p = angr.Project(path,
            load_options={
                'auto_load_libs': False,
                'main_opts': {
                    'backend': 'blob',
                    'arch': 'cortex-m',
                    'entry_point': get_main_entry(path)
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

if __name__ == "__main__":

    fw_examples = glob('examples/unit-tests/*.bin')

    if not isdir(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    angr_cfgs = {}

    table = []
    for fw_path in sorted(fw_examples):
        # get fw name
        (name, ext) = splitext(basename(fw_path))
        if name not in angr_cfgs:
            angr_cfgs[name] = {}

        print(f"analyzing target: {name}")

        # load fw to angr
        proj = load_proj(fw_path)
        entry_points = get_cortexm_entry_points(fw_path)

        # do static cfg recovery
        t = perf_counter()
        cfg_fast = proj.analyses.CFGFast(
            function_starts=entry_points,
            force_complete_scan=False,
            normalize=True
        )
        fast_elapsed = perf_counter() - t

        angr_cfgs[name]['angr_fast'] = cfg_fast

        # save static cfg result
        fast_graph = {
            'nodes': set([(node.addr & (~1), node.size) for node in cfg_fast.nodes() if node.size]),
            'edges': set([(n1.instruction_addrs[-1] & (~1), n2.addr & (~1)) for (n1, n2) in cfg_fast.graph.edges() if n1.instruction_addrs])
        }
        with open(f"{OUT_DIR}/{name}-angr_fast-cfg.pkl", 'wb') as pklfile:
            dill.dump(fast_graph, pklfile)

        connected_graph = make_connected_cfg(cfg_fast, entry_points)

        with open(f"{OUT_DIR}/{name}-angr_cnnctd-cfg.pkl", 'wb') as pklfile:
            dill.dump(connected_graph, pklfile)

        # do dynamic cfg recovery
        try:
            t = perf_counter()
            cfg_emu = proj.analyses.CFGEmulated(
                starts=entry_points,
                normalize=True)
            emu_elapsed = perf_counter() - t

            angr_cfgs[name]['angr_emu'] = cfg_emu

            # save dynamic cfg result
            emu_graph = {
                'nodes': set([((node.addr & (~1)), node.size) for node in cfg_emu.nodes() if node.size]),
                'edges': set([(n1.instruction_addrs[-1] & (~1), n2.addr & (~1)) for (n1, n2) in cfg_emu.graph.edges() if n1.instruction_addrs])
            }
        except Exception as e:
            print(e)
            emu_graph = {
                'nodes': set(),
                'edges': set()
            }

        with open(f"{OUT_DIR}/{name}-angr_emu-cfg.pkl", 'wb') as pklfile:
            dill.dump(emu_graph, pklfile)

        table.append(
            "{:<25} fast {:>4d} blocks {:>4d} edges   elapsed: {} s\n".format(
                basename(fw_path), 
                len(fast_graph['nodes']), 
                len(fast_graph['edges']), 
                fast_elapsed) + 
            "{:<25} cnxd {:>4d} blocks {:>4d} edges   elapsed: {} s\n".format(
                '', 
                len(connected_graph['nodes']), 
                len(connected_graph['edges']), 
                'n/a') + 
            "{:<25} emu  {:>4d} blocks {:>4d} edges   elapsed: {} s".format(
                '',
                len(emu_graph['nodes']),
                len(emu_graph['edges']),
                emu_elapsed))

    print('\n'.join(table))
    with open(f'{PARENT_DIR}/angr-cfg-results.txt', 'w') as f:
        f.write('\n'.join(table))


