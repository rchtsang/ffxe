import os
from os.path import basename, splitext
from copy import deepcopy
from glob import glob
from time import perf_counter

import dill

from fxe import *

"""
test script that runs fxe tests on all firmware examples
"""

if __name__ == "__main__":

    fw_examples = glob('examples/unit-tests/*.bin')

    fxe_cfgs = {}
    table = []

    for fw_path in sorted(fw_examples):

        fxe = FXEngine(
            pd="mmaps/nrf52832.yml",
            path=fw_path,
            log_stdout=False,
            log_insn=False,
        )

        t = perf_counter()
        fxe.run()
        elapsed = perf_counter() - t

        total_insns = 0
        total_size = 0
        for block in fxe.cfg.bblocks.values():
            total_size += block.size
            for insn in fxe.cs.disasm(
                    fxe.uc.mem_read(block.addr, block.size), block.size):
                total_insns += 1

        result = "{:<25} : {{ \"blocks\": {:>4d}, \"edges\": {:>4d},  \"elapsed\": \"{:>15.9f} s\" }}".format(
            f'"{basename(fw_path)}"',
            len(fxe.cfg.bblocks),
            len(fxe.cfg.edges),
            elapsed
        )

        print("{:<25} {:>4d} blocks {:>4d} edges    elapsed (s): {:>15.9f}".format(
            basename(fw_path),
            len(fxe.cfg.bblocks),
            len(fxe.cfg.edges),
            elapsed
        ))
        table.append(result)

        fxe_cfgs[basename(fw_path)] = fxe.cfg

    with open('tests/fxe-cfg-results.json', 'w') as f:
        f.write('{\n  ' + ',\n  '.join(table) + '\n}')

    for fn, cfg in fxe_cfgs.items():
        (name, ext) = splitext(fn)
        graph = {
            'nodes': set([(b.addr, b.size) for b in cfg.bblocks.values()]),
            'edges': set([(cfg.bblocks[e[0]].insns[-1].address, e[1]) for e in cfg.edges]),
        }
        with open(f"tests/cfgs/unit-tests/{name}-fxe-cfg.pkl", 'wb') as pklfile:
            dill.dump(graph, pklfile)
