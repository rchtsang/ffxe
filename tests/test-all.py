import os
from os.path import basename
from copy import deepcopy
from glob import glob

from ffxe import *

"""
test script that runs tests on all firmware examples

"""

fw_examples = glob('examples/*.bin')

ffxe_cfgs = {}

for fw_path in sorted(fw_examples):

    ffxe = FFXEngine(
        pd="mmaps/nrf52832.yml",
        path=fw_path,
        log_stdout=False,
        log_insn=False,
        log_time=True
    )

    ffxe.run()

    total_insns = 0
    total_size = 0
    for block in ffxe.cfg.bblocks.values():
        total_size += block.size
        for insn in ffxe.cs.disasm(
                ffxe.uc.mem_read(block.addr, block.size), block.size):
            total_insns += 1

    print("{:<25} {:>4d} blocks {:>4d} edges".format(
        basename(fw_path),
        len(ffxe.cfg.bblocks),
        len(ffxe.cfg.edges),
    ))

    ffxe_cfgs[basename(fw_path)] = ffxe.cfg

