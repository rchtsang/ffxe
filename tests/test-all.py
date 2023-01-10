import os
from os.path import basename, splitext
from copy import deepcopy
from glob import glob
from time import perf_counter

import dill

from ffxe import *

"""
test script that runs tests on all firmware examples

"""

if __name__ == "__main__":

    fw_examples = glob('examples/*.bin')

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
            'edges': cfg.edges,
        }
        with open(f"tests/cfgs/{name}-ffxe-cfg.pkl", 'wb') as pklfile:
            dill.dump(graph, pklfile)
