import os
from os.path import basename, splitext, isdir
from copy import deepcopy
from glob import glob
from time import perf_counter
from pathlib import Path

import dill

from ffxe import *

"""
script to run ffxe on all nRF52 unit tests
"""
PARENT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJ_ROOT = os.path.realpath(f"{PARENT_DIR}/..")
OUT_DIR = f"{PROJ_ROOT}/tests/cfgs/unit-tests"

if __name__ == "__main__":

    fw_examples = glob(f'{PROJ_ROOT}/examples/unit-tests/*.bin')

    if not isdir(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    ffxe_cfgs = {}
    table = []

    for fw_path in sorted(fw_examples):

        ffxe = FFXEngine(
            pd="mmaps/nrf52832.yml",
            path=fw_path,
            log_stdout=False,
            log_insn=False,
            log_time=True
        )

        t = perf_counter()
        ffxe.run()
        elapsed = perf_counter() - t

        total_insns = 0
        total_size = 0
        for block in ffxe.cfg.bblocks.values():
            total_size += block.size
            for insn in ffxe.cs.disasm(
                    ffxe.uc.mem_read(block.addr, block.size), block.size):
                total_insns += 1

        result = "{:<25} {:>4d} blocks {:>4d} edges    elapsed (s): {}".format(
            basename(fw_path),
            len(ffxe.cfg.bblocks),
            len(ffxe.cfg.edges),
            elapsed
        )

        print(result)
        table.append(result)

        ffxe_cfgs[basename(fw_path)] = ffxe.cfg

    with open('tests/ffxe-cfg-results.txt', 'w') as f:
        f.write('\n'.join(table))

    for fn, cfg in ffxe_cfgs.items():
        (name, ext) = splitext(fn)
        graph = {
            'nodes': set([(b.addr, b.size) for b in cfg.bblocks.values()]),
            'edges': set([(max(cfg.bblocks[e[0]].insns.keys()), e[1]) for e in cfg.edges]),
                # max() is used to get the last address in the bblock
        }
        with open(f"{OUT_DIR}/{name}-ffxe-cfg.pkl", 'wb') as pklfile:
            dill.dump(graph, pklfile)
