#!/usr/bin/env python3

import os
import re
import argparse
import subprocess
import shlex
import random
from pathlib import Path
from glob import glob
from itertools import product
from os.path import *

import dill

"""
script to conduct random sample for verification of other engines' 
cfg recovery results
flags obviously incorrect edges and blocks, 
but manual inspection may still be required
only tabulate results for unit tests
"""

PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")
CFG_FN_PTRN = re.compile(r"(?P<fw>[\w-]+)-(?P<engine>\w+)-cfg\.pkl")
RE_PTRN_DISASM = re.compile((
    r" +(?P<addr>[0-9a-fA-F]+):\s+"
    r"(?P<raw>[0-9a-fA-F]+(?: [0-9a-fA-F]+)?)\s+"
    r"(?P<mnemonic>.+)"))


def get_disassembly(fw_name, path, isa='armv7e-m'):
    """helper to get gcc disassembly from elf file"""
    assert exists(fw_file := f"{path}/{fw_name}.elf"), "no elf file found"

    disasm_txt = subprocess.run(
        shlex.split(f"arm-none-eabi-objdump -d -m{isa} {fw_file}"),
        stdout=subprocess.PIPE,
    ).stdout.decode('utf-8').split('\n')

    # convert tabs to spaces (maintaining visual spacing)
    for i, line in enumerate(disasm_txt):
        newline = []
        for j, char in enumerate(line):
            if char == '\t':
                newline.append(' '*(4 - (j % 4)))
            else:
                newline.append(char)
        disasm_txt[i] = ''.join(newline)

    disasm = {}
    # construct addr-to-line mapping and disasm dict
    # useful for determining valid line
    for lineno, line in enumerate(disasm_txt):
        match = RE_PTRN_DISASM.search(line)
        if match:
            addr = int(match.group('addr'), base=16)
            disasm[addr] = {
                'line': lineno,
                'raw': int(''.join(match.group('raw').split()), base=16),
                'raw_str': match.group('raw'),
                'mnemonic': match.group('mnemonic'),
            }

    return disasm


parser = argparse.ArgumentParser()
parser.add_argument('-i', default=f"{PROJ_DIR}/tests/cfgs/unit-tests")
parser.add_argument('-d', default=f"{PARENT_DIR}/sampled")
parser.add_argument('--bin-path', dest='binpath', default=f"{PROJ_DIR}/examples/unit-tests")
parser.add_argument('--seed', type=int, dest='seed', default=42)
parser.add_argument('--tabulate', dest='tabulate', action='store_true')

if __name__ == "__main__":
    
    args = parser.parse_args()

    SRC_DIR = args.i
    OUT_DIR = args.d
    BIN_DIR = args.binpath

    pklpaths = glob(f"{SRC_DIR}/*.pkl")

    graphs = {}
    engs = set()
    # load all the generated graphs
    for path in pklpaths:
        # should always match the filename
        match = CFG_FN_PTRN.search(basename(path))
        if not match:
            continue

        fw  = match.group('fw')
        eng = match.group('engine')
        engs.add(eng)

        with open(path, 'rb') as pklfile:
            graph = dill.load(pklfile)

        if fw not in graphs:
            graphs[fw] = {}
        graphs[fw][eng] = graph

    if not exists(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    fw_names = list(sorted(graphs.keys()))
    other_engs = [eng for eng in engs if eng != 'ffxe']

    overlap_data = { fw: { eng: {} for eng in other_engs } for fw in fw_names }
    sampled_sets = {}
    # loop through all firmware and all engines and sample overlap
    # also compare them to the elf disassembly to check validity
    for settype in ['nodes', 'edges']:
        for fw in fw_names:
            for eng in sorted(other_engs):
                print(f"comparing ffxe to {eng} on {fw} {settype}...")
                random.seed(args.seed)
                # load disassembly
                disasm = get_disassembly(fw, BIN_DIR)

                # get data and calculate overlaps
                ffxe_data = graphs[fw]['ffxe'][settype]
                othr_data = graphs[fw][eng][settype]

                overlap = ffxe_data.intersection(othr_data)
                ffxe_only = ffxe_data.difference(overlap)
                othr_only = othr_data.difference(overlap)

                overlap_data[fw][eng][settype] = {
                    'ffxe': ffxe_only,
                    'othr': othr_only,
                    'ovlp': overlap
                }

                print(f"ffxe only: {len(ffxe_only)}")
                print(f"othr only: {len(othr_only)}")

                # randomly sample both
                if len(ffxe_only) > 20:
                    num_samples = round(len(ffxe_only) / 10) if len(ffxe_only) >= 200 else 20
                    ffxe_sampled = random.sample(list(ffxe_only), num_samples)
                else:
                    ffxe_sampled = ffxe_only

                if len(othr_only) > 20:
                    num_samples = round(len(othr_only) / 10) if len(othr_only) >= 200 else 20
                    othr_sampled = random.sample(list(othr_only), num_samples)
                else:
                    othr_sampled = othr_only

                # first-pass check validity
                # for nodes, this will detect blocks that contain data sections,
                # blocks that contain addresses that should not be executed
                #   (this indicated by lack of presence in elf disassembly, which is ground truth)
                # and standalone nop instructions that do not get executed
                ffxe_invalid = set()
                othr_invalid = set()
                if settype == 'nodes':
                    for node in ffxe_sampled:
                        # loop through addresses in node to see 
                        # if actually exists in disassembly
                        addr = node[0]
                        if (addr in disasm 
                                and 'nop' in disasm[addr]['mnemonic']
                                and node[1] == 2):
                            # catch nop hazards as invalid
                            ffxe_invalid.add(node)
                        while (addr < sum(node)):
                            if (addr not in disasm
                                    or any([s in disasm[addr]['mnemonic'] \
                                        for s in ['.word', '.short', '.byte']])):
                                # catch addresses not in disassembly or obviously data sections
                                break
                            addr += len(disasm[addr]['raw_str'].replace(' ', '')) // 2
                        if addr != sum(node):
                            ffxe_invalid.add(node)
                    for node in othr_sampled:
                        # repeat for other engine
                        addr = node[0]
                        if (addr in disasm 
                                and 'nop' in disasm[addr]['mnemonic']
                                and node[1] == 2):
                            # catch nop hazards as invalid
                            othr_invalid.add(node)
                        while (addr < sum(node)):
                            if (addr not in disasm
                                    or any([s in disasm[addr]['mnemonic'] \
                                        for s in ['.word', '.short', '.byte']])):
                                # catch addresses not in disassembly or obviously data sections
                                break
                            addr += len(disasm[addr]['raw_str'].replace(' ', '')) // 2
                        if addr != sum(node):
                            othr_invalid.add(node)
                else:
                    for edge in ffxe_sampled:
                        # loop through edges to see if start and end 
                        # are both actually in disassembly
                        # .word and .short indicate a known data section
                        if (edge[0] not in disasm
                                or '.word' in disasm[edge[0]]['mnemonic']
                                or '.short' in disasm[edge[0]]['mnemonic']):
                            ffxe_invalid.add(edge)
                        elif (edge[1] not in disasm
                                or '.word' in disasm[edge[1]]['mnemonic']
                                or '.short' in disasm[edge[1]]['mnemonic']):
                            ffxe_invalid.add(edge)

                    for edge in othr_sampled:
                        # repeat for other engine
                        if (edge[0] not in disasm
                                or '.word' in disasm[edge[0]]['mnemonic']
                                or '.short' in disasm[edge[0]]['mnemonic']):
                            othr_invalid.add(edge)
                        elif (edge[1] not in disasm
                                or '.word' in disasm[edge[1]]['mnemonic']
                                or '.short' in disasm[edge[1]]['mnemonic']):
                            othr_invalid.add(edge)

                if fw not in sampled_sets:
                    sampled_sets[fw] = {}

                if eng not in sampled_sets[fw]:
                    sampled_sets[fw][eng] = {}
                sampled_sets[fw][eng][settype] = { 
                    'sampled': othr_sampled, 
                    'invalid': othr_invalid,
                }
                
                if 'ffxe' not in sampled_sets[fw]:
                    sampled_sets[fw]['ffxe'] = {}
                sampled_sets[fw]['ffxe'][settype] = { 
                    'sampled': ffxe_sampled, 
                    'invalid': ffxe_invalid,
                }

    data = { eng: { 'nodes': {}, 'edges': {} } for eng in other_engs }
    print('\n\nAutomated Audit Results:')
    # log samples in separate files, organized by set-type, then engine
    for eng in sorted(other_engs):
        for settype in ['nodes', 'edges']:
            filename = f"{eng}-{settype}-sampled.txt"

            eng_sampled = 0
            eng_invalid = 0
            eng_err = 0

            log_lines = []
            csv_lines = []
            csv_lines.append("Name,Total,Sampled,Invalid,Err")

            for fw in sorted(fw_names):
                sampled = sampled_sets[fw][eng][settype]
                print((
                        "{:<15} {:<5} {:>16}: "
                        "total={:<4d} sampled={:<3d} invalid={:<3d} err={}"
                    ).format(
                        eng,
                        settype,
                        fw,
                        total_cnt := len(overlap_data[fw][eng][settype]['othr']),
                        sampled_cnt := len(sampled['sampled']),
                        invalid_cnt := len(sampled['invalid']),
                        "{:>02.02f}%".format(err := round(len(sampled['invalid'])/len(sampled['sampled']) * 100, 2)) \
                            if len(sampled['sampled']) else "n/a"
                ))

                eng_sampled += sampled_cnt
                eng_invalid += invalid_cnt
                eng_err += err

                data[eng][settype][fw] = [
                    total_cnt, 
                    sampled_cnt, 
                    invalid_cnt,
                    err if len(sampled['sampled']) else "~" ]

                log_lines.append(f"{fw}: {sampled_cnt} | {total_cnt}")
                for item in sorted(sampled['sampled']):
                    line = "\t({:>8x}, {:>8d})".format(*item)
                    if item in sampled['invalid']:
                        line += '*'
                    line += '\t'
                    log_lines.append(line)
                log_lines.append('')

                csv_lines.append(
                    "{fw:>15}, {total:>4d}, {sampled:>3d}, {invalid:>4d}, {err}".format(
                        fw=fw, 
                        total=total_cnt, 
                        sampled=sampled_cnt, 
                        invalid=invalid_cnt, 
                        err="{:02.02f}%".format(err) if len(sampled['sampled']) else "n/a"
                ))

            with open(f"{OUT_DIR}/{eng}-{settype}-sampled.txt", 'w') as logfile:
                logfile.write('\n'.join(log_lines))

            with open(f"{OUT_DIR}/{eng}-{settype}-audit.csv", 'w') as tabfile:
                tabfile.write('\n'.join(csv_lines))

            avg_err = round(eng_err / len(fw_names), 2)
            print((
                "{:<15} {:<5} {:>16}: "
                "average error={}%"
            ).format(eng, settype, "cumulative", avg_err))

    if args.tabulate:
        tab_engs = ['angr_cnnctd', 'angr_fast', 'angr_emu', 'ghidra_cnnctd', 'ghidra_simple']

        fw_basenames = set([fw[:-3] for fw in fw_names])

        for settype in ['nodes', 'edges']:
            table = []

            table.append("\\begin{tabular}{@{}ll" + 'c' * len(tab_engs) + "@{}}")
            table.append("\\toprule")

            table.append((
                "\\multicolumn{2}{l}{\\textbf{Firmware}} & "
                + " & ".join([eng.replace('_', '\\_') for eng in tab_engs])
                + " \\\\ \\midrule"
            ))

            for fw in sorted(fw_basenames):
                table.append(f"\\multirow{{4}}{{*}}{{{fw}}}".replace('_', '\\_'))

                for opt in ['-o0', '-o1', '-o2', '-o3']:
                    row = f"    & {opt.upper()}"
                    for eng in tab_engs:
                        row += " & {:>12}".format(
                            "{}/{}/{}".format(*reversed(data[eng][settype][fw + opt][:-1])))
                    row += " \\\\"
                    table.append(row)
                table[-1] = table[-1] + " \\midrule"
            table[-1] = table[-1].replace("\\midrule", "\\bottomrule")

            table.append("\\end{tabular}")

            tabletxt = '\n'.join(table)

            with open(f"{PARENT_DIR}/tbl/audit-unit-{settype}.tex", 'w') as texfile:
                texfile.write(tabletxt)


