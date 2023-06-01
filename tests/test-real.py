import os
import argparse
from os.path import (
    basename, splitext, exists, realpath, 
    dirname, relpath, isdir
)
from copy import deepcopy
from glob import glob
from time import perf_counter
from datetime import datetime
from pathlib import Path

import dill

from ffxe import *

"""
script to run ffxe on real-world samples
"""

make_timestamp = lambda: datetime.now().strftime('%y%m%d-%H%M%S')

PARENT_DIR = dirname(realpath(__file__))
PROJ_ROOT = dirname(PARENT_DIR)
SAMPLES_DIR = f"{PROJ_ROOT}/examples/real-world"
OUT_DIR = f"{PARENT_DIR}/cfgs/real-world"

def generate_highlighted_disasm_txt(ffxe, graph):
    ffxe.fw.disassemble(graph)

    disasm_txt = deepcopy(ffxe.fw.disasm_txt)
    for block in ffxe.cfg.bblocks.values():
        insn_addr = block.addr
        for insn in ffxe.cs.disasm(
                ffxe.uc.mem_read(block.addr, block.size), block.size):
            try:
                lineno = ffxe.fw.disasm[insn_addr]['line']
                insn_addr += insn.size
                disasm_txt[lineno] = "{}{}{}{:<90}\u001b[0m".format(
                    "\u001b[103m",  # bright yellow background
                    "\u001b[30m",   # black foreground
                    "\u001b[1m",    # bold font
                    disasm_txt[lineno])
            except Exception:
                pass
    return disasm_txt


parser = argparse.ArgumentParser(prog="test-real.py", description=__doc__)
parser.add_argument('--targets', nargs='+', type=str, default=None,
    help="specify folders of target real-world firmware to analyze")
parser.add_argument('--print-cfg', dest='print_cfg', action='store_true',
    help="print cfgs to stdout")
parser.add_argument('--outdir', type=str, default=f"{PARENT_DIR}",
    help="destination directory for results table")
parser.add_argument('--log-insns', dest='log_insn', action='store_true',
    help="turn on instruction logging")
parser.add_argument('--log-stdout', dest='log_stdout', action='store_true',
    help="print log to stdout in real time")

if __name__ == "__main__":
    args = parser.parse_args()

    if not args.targets:
        args.targets = sorted([relpath(path) for path in glob(f"{SAMPLES_DIR}/*/")])

    generated_cfgs = {}
    result_table = []

    for target in args.targets:
        print(f"analyzing target: {target}")
        try:
            assert isdir(target), \
                "target is not a directory: {}".format(target)
            
            assert len(binfiles := glob(f"{target}/*.bin")) == 1, \
                "there must be exactly one firmware image binary in {}".format(target)
            assert len(ymlfiles := glob(f"{target}/*.yml")) == 1, \
                "there must be exactly one platform description yaml in {}".format(target)

            fw_path = binfiles[0]
            pd_path = ymlfiles[0]
            fw_name = splitext(basename(fw_path))[0]
            base_addr = None
            vtbases = [0]

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
                    vtbases = [int(val, 16) for val in file.read().split(',')]
            print("vector table offsets: {}".format(
                ' '.join([hex(base) for base in vtbases])))

        except AssertionError as e:
            print(e)
            continue


        ffxe = FFXEngine(
            pd=pd_path,
            path=fw_path,
            base_addr=base_addr,
            vtbases=vtbases,
            log_dir=f"{PROJ_ROOT}/logs",
            log_name=f"{fw_name}-{make_timestamp()}.log",
            log_stdout=args.log_stdout,
            log_insn=args.log_insn,
            log_time=True,
        )

        t = perf_counter()
        ffxe.run()
        elapsed = perf_counter() - t

        graph = {
            'nodes': set([(b.addr, b.size) for b in ffxe.cfg.bblocks.values() if b.size]),
            'edges': set([(max(ffxe.cfg.bblocks[e[0]].insns.keys()), e[1]) for e in ffxe.cfg.edges if ffxe.cfg.bblocks[e[0]].insns]),
                # max() is used to get the last address in the bblock
        }

        generated_cfgs[basename(fw_path)] = graph


        if not isdir(OUT_DIR):
            Path(OUT_DIR).mkdir(parents=True, exist_ok=True)
        with open(f"{OUT_DIR}/{fw_name}-ffxe-cfg.pkl", 'wb') as pklfile:
            dill.dump(graph, pklfile)


        total_insns = 0
        total_size = 0
        for block in ffxe.cfg.bblocks.values():
            total_size += block.size
            for insn in ffxe.cs.disasm(
                    ffxe.uc.mem_read(block.addr, block.size), block.size):
                total_insns += 1

        result = "{:<35}: {{ \"blocks\": {:>5d}, \"edges\": {:>5d},  \"elapsed\": \"{:>15.9f} s\" }}".format(
            f'"{basename(fw_path)}"',
            len(ffxe.cfg.bblocks),
            len(ffxe.cfg.edges),
            elapsed
        )

        if args.print_cfg:
            disasm_txt = generate_highlighted_disasm_txt(ffxe, graph)
            print('\n'.join(disasm_txt))
            print('\n')

        print(result)
        result_table.append(result)

    print()
    print('\n'.join(result_table))

    with open(f'{args.outdir}/ffxe-real-cfg-results-{make_timestamp()}.json', 'w') as f:
        f.write('{\n  ' + ',\n  '.join(result_table) + '\n}')
