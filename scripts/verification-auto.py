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


def compare_coverage(graphs, coverage, eng0, eng1, fw):
    """utility for comparing coverage of cfgs for all firmware
    returns the overlap and exclusive coverage of each engine
    loop through both sorted node sets and compare elements for overlap
    """

    start = lambda n: n[0]
    end = lambda n: n[0] + n[-1]

    def covers(range1, range2):
        """returns true if range1 strictly inside range2 or vice versa"""
        return ((start(range1) <= start(range2) and end(range2) <= end(range1))
            or (start(range2) <= start(range1) and end(range1) <= end(range2)))


    nodes0 = graphs[fw][eng0]['nodes']
    nodes1 = graphs[fw][eng1]['nodes']

    coverage0 = coverage[fw][eng0]
    coverage1 = coverage[fw][eng1]

    eng0_only = set()
    eng1_only = set()
    overlap = set()

    for node in nodes0:
        if any([covers(region, node) for region in coverage1]):
            overlap.add(node)
        else:
            eng0_only.add(node)

    for node in nodes1:
        if any([covers(region, node) for region in coverage0]):
            overlap.add(node)
        else:
            eng1_only.add(node)

    return [ (eng0, eng0_only), ('ovlp', overlap), (eng1, eng1_only) ]


def generate_coverage_set(graphs, fw_name, engine):
    """utility for generating the address space coverage of cfg 
    for a given firmware and engine
    returns a set of tuples representing the covered address range
    tuples of form (start, size)
    """
    ranges = set()
    range_start = 0
    range_size = 0
    for naddr, nsize in sorted(graphs[fw_name][engine]['nodes']):
        if range_start + range_size < naddr:
            # check if gap between current range and next block exists
            if range_size > 0:
                ranges.add((range_start, range_size))
            # start consolidating new range
            range_start = naddr
            range_size = nsize
        else:
            # this includes the case of overlapping blocks
            # in which one blocks only partially cover one another
            # which should never occur
            range_size = naddr + nsize - range_start

    return ranges


def generate_coverage(graphs, engs, fw_names):
    """utility for generating coverage sets 
    of all engines and firmwares provided
    returns a dictionary organized by firmware, then engine
    """
    coverage = {}

    # construct coverage sets
    for fw_name in fw_names:
        coverage[fw_name] = {}
        for eng in engs:
            ranges = generate_coverage_set(graphs, fw_name, eng)
            coverage[fw_name][eng] = ranges

    return coverage


def compare_graphs(graphs, eng0, eng1, settype, fw):
    """utility for comparing blocks or edges of cfgs for a given firmware
    returns the overlap and exclusive blocks or edges of each engine based on settype
    data is in order sorted by firmware name
    """
    
    # pointers to graphs of interest
    eng0_cfg = graphs[fw][eng0]
    eng1_cfg = graphs[fw][eng1]

    # compute intersection and disjoint sets
    ovlp = eng0_cfg[settype].intersection(eng1_cfg[settype])
    eng0_only = eng0_cfg[settype].difference(ovlp)
    eng1_only = eng1_cfg[settype].difference(ovlp)

    return [ (eng0, eng0_only), ('ovlp', ovlp), (eng1, eng1_only) ]


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

    return disasm, disasm_txt

def get_context(addr, disasm, disasm_txt, distance=4):
    context = ['\t\t' + '-'*20]
    if addr not in disasm:
        for i in range(4):
            if addr + i in disasm:
                addr += i
                break
            elif addr - i in disasm:
                addr -= i
                break
        else:
            return context + ["NO CONTEXT"] + context
    lineno = disasm[addr]['line']
    for line in range(lineno-distance, lineno+distance+1):
        if line == lineno:
            prefix = '\t\t->'
        elif 0 <= line < len(disasm_txt):
            prefix = '\t\t  '
        else:
            continue
        context.append(prefix + disasm_txt[line])

    context.append('\t\t' + '-'*20)
    return context


parser = argparse.ArgumentParser()
parser.add_argument('-i', default=f"{PROJ_DIR}/tests/cfgs/unit-tests")
parser.add_argument('-d', default=f"{PARENT_DIR}/sampled")
parser.add_argument('--bin-path', dest='binpath', default=f"{PROJ_DIR}/examples/unit-tests")
parser.add_argument('--seed', type=int, dest='seed', default=42)
parser.add_argument('--tabulate', dest='tabulate', action='store_true')
parser.add_argument('--context', dest='context', action='store_true')
parser.add_argument('--sample-positives', dest='sample_pos', action='store_true')

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

    # generate coverage data
    coverage = generate_coverage(graphs, engs, graphs.keys())

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
                # load disassembly
                disasm, disasm_txt = get_disassembly(fw, BIN_DIR)

                # get data and calculate overlaps
                if settype == 'nodes':
                    data = dict(compare_coverage(
                        graphs, coverage, 'ffxe', eng, fw))
                    overlap_data[fw][eng][settype] = data
                else:
                    data = dict(compare_graphs(
                        graphs, 'ffxe', eng, settype, fw))
                    overlap_data[fw][eng][settype] = data

                print(f"ffxe only: {len(data['ffxe'])}")
                print(f"othr only: {len(data[eng])}")

                # # randomly sample both
                # if len(data['ffxe']) > 20:
                #     num_samples = round(len(data['ffxe']) / 10) if len(data['ffxe']) >= 200 else 20
                #     ffxe_sampled = random.sample(list(data['ffxe']), num_samples)
                # else:
                #     ffxe_sampled = data['ffxe']

                # if len(data[eng]) > 20:
                #     num_samples = round(len(data[eng]) / 10) if len(data[eng]) >= 200 else 20
                #     othr_sampled = random.sample(list(data[eng]), num_samples)
                # else:
                #     othr_sampled = data[eng]

                ffxe_sampled = data['ffxe']
                othr_sampled = data[eng]

                if args.context:
                    # collect context
                    ffxe_sampled_context = { t: get_context(t[0], disasm, disasm_txt) for t in ffxe_sampled }
                    othr_sampled_context = { t: get_context(t[0], disasm, disasm_txt) for t in othr_sampled }
                else:
                    ffxe_sampled_context = {}
                    othr_sampled_context = {}

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
                    'context': othr_sampled_context
                }
                
                if 'ffxe' not in sampled_sets[fw]:
                    sampled_sets[fw]['ffxe'] = {}
                sampled_sets[fw]['ffxe'][settype] = { 
                    'sampled': ffxe_sampled, 
                    'invalid': ffxe_invalid,
                    'context': ffxe_sampled_context
                }

    data = { eng: { 'nodes': {}, 'edges': {} } for eng in other_engs }
    avg_errs = { eng: {} for eng in other_engs }
    print('\n\nAutomated Audit Results:')
    # log samples in separate files, organized by set-type, then engine
    for eng in sorted(other_engs):
        for settype in ['nodes', 'edges']:
            random.seed(args.seed)

            filename = f"{eng}-{settype}-sampled.txt"

            eng_sampled = 0
            eng_invalid = 0
            eng_err = []

            auto_log_lines = []
            manu_log_lines = []
            # csv_lines = []
            # csv_lines.append("Name,Total,Sampled,Invalid,Err")

            for fw in sorted(fw_names):
                sampled = sampled_sets[fw][eng][settype]
                print((
                        "{:<15} {:<5} {:>16}: "
                        "total={:<4d} invalid={:<3d} err={}"
                    ).format(
                        eng,
                        settype,
                        fw,
                        # total_cnt := len(overlap_data[fw][eng][settype][eng]),
                        sampled_cnt := len(sampled['sampled']),
                        invalid_cnt := len(sampled['invalid']),
                        "{:>02.02f}%".format(err := round(len(sampled['invalid'])/len(sampled['sampled']) * 100, 2)) \
                            if sampled['sampled'] else "n/a"
                ))

                if sampled['sampled']:
                    eng_err.append(err)

                data[eng][settype][fw] = [
                    "{:>6.02f}".format(err) if sampled['sampled'] else '-'*6,
                    # total_cnt, 
                    sampled_cnt, 
                    invalid_cnt
                ]

                auto_log_lines.append(f"{fw}: {sampled_cnt}")
                for item in sorted(sampled['sampled']):
                    line = "\t({:>8x}, {:>8d})" if settype == 'nodes' else "\t({:>8x}, {:>8x})"
                    line = line.format(*item)
                    if item in sampled['invalid']:
                        line += '*'
                    line += '\t'
                    auto_log_lines.append(line)
                    # if args.context:
                    #     auto_log_lines.extend(sampled['context'][item])
                auto_log_lines.append('')

                if args.sample_pos:
                    # randomly sample positives (blocks/edges not marked invalid)
                    positives = sampled['sampled'].difference(sampled['invalid'])
                    if len(positives) > 20:
                        num_samples = int(round(len(positives) / 10)) if len(positives) >= 200 else 20
                        man_sampled = random.sample(list(positives), num_samples)
                    else:
                        man_sampled = list(positives)

                    manu_log_lines.append(f"{fw}: {len(man_sampled)} | {len(positives)}")
                    for item in sorted(man_sampled):
                        line = "\t({:>8x}, {:>8d})\t" if settype == 'nodes' else "\t({:>8x}, {:>8x})\t"
                        line = line.format(*item)
                        manu_log_lines.append(line)
                        if args.context:
                            manu_log_lines.extend(sampled['context'][item])
                    manu_log_lines.append('')

                # csv_lines.append(
                #     "{fw:>15}, {total:>4d}, {sampled:>3d}, {invalid:>4d}, {err}".format(
                #         fw=fw, 
                #         total=total_cnt, 
                #         sampled=sampled_cnt, 
                #         invalid=invalid_cnt, 
                #         err="{:02.02f}%".format(err) if len(sampled['sampled']) else "n/a"
                # ))

            with open(f"{OUT_DIR}/{eng}-{settype}-auto-sampled.txt", 'w') as logfile:
                logfile.write('\n'.join(auto_log_lines))

            if args.sample_pos:
                with open(f"{OUT_DIR}/{eng}-{settype}-man-sampled.txt", 'w') as logfile:
                    logfile.write('\n'.join(manu_log_lines))

            # with open(f"{OUT_DIR}/{eng}-{settype}-auto-audit.csv", 'w') as csvfile:
            #     csvfile.write('\n'.join(csv_lines))

            avg_err = round(sum(eng_err) / len(eng_err), 2)
            print((
                "{:<15} {:<5} {:>16}: "
                "average error={}%"
            ).format(eng, settype, "cumulative", avg_err))
            avg_errs[eng][settype] = avg_err

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
                        row += " & {:>18}".format(
                            "{}/{}|{}".format(*reversed(data[eng][settype][fw + opt][:]), ))
                    row += " \\\\"
                    table.append(row)
                table[-1] = table[-1] + " \\midrule"
            # table[-1] = table[-1].replace("\\midrule", "\\bottomrule")

            table.append((
                "\\multicolumn{2}{l}{\\textbf{Average of Error}}\n    & "
                + " & ".join(["\\textbf{{{:2.02f}\\%}}".format(avg_errs[eng][settype]) for eng in tab_engs])
                + " \\\\ \\bottomrule"
            ))

            table.append("\\end{tabular}")

            tabletxt = '\n'.join(table)

            with open(f"{PARENT_DIR}/tbl/auto-verif-unit-{settype}.tex", 'w') as texfile:
                texfile.write(tabletxt)


