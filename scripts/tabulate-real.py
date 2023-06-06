import os
import sys
import re
import argparse
from os.path import *
from pathlib import Path
from glob import glob

import dill


PARENT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJ_DIR = os.path.realpath(f"{PARENT_DIR}/..")
RE_RESULTFILE_PTRN = re.compile(r"(?P<eng>.+)-cfg-results\.json")
FW_PTRN = re.compile(
    r"(?P<fw>(?P<name>\w+)\.bin)?"
)
CFG_FN_PTRN = re.compile(r"(?P<fw_name>[\w-]+)-(?P<engine>\w+)-cfg\.pkl")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', default=f"{PROJ_DIR}/tests/cfgs/real-world",
        help="path to input directory")
    parser.add_argument('-d', default=f"{PARENT_DIR}/tbl",
        help="path to output directory")
    
    args = parser.parse_args()

    is_unit_tests = (args.i == f"{PROJ_DIR}/tests/cfgs/unit-tests")

    SRC_DIR = args.i
    OUT_DIR = args.d

    pklpaths = glob(f"{SRC_DIR}/*.pkl")
    pklpaths.sort()

    graphs = {}
    engs = set()
    # load all the generated graphs
    for path in pklpaths:
        # should always match the filename
        match = CFG_FN_PTRN.search(basename(path))

        fw  = match.group('fw_name')
        eng = match.group('engine')
        engs.add(eng)

        if fw in ['ble_app_template_pca10056_s140']:
            continue

        with open(path, 'rb') as pklfile:
            graph = dill.load(pklfile)

        if fw not in graphs:
            graphs[fw] = {}
        graphs[fw][eng] = graph

    if not exists(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    engs = list(sorted(engs))


    table = []
    table.append("\\begin{tabular}{@{}llllllllll@{}}")
    table.append("\\toprule")
    # write table header
    table.append((
        "\\multicolumn{2}{l}{\\textbf{Firmware}} & " +  
        ' & '.join([eng.replace('_', '\\_') for eng in engs]) +
        "\\\\ \\midrule"
    ))

    # write table rows
    data = []
    for fw in sorted(graphs.keys()):
        table.append(f"\\multirow{{2}}{{*}}{{{fw}}}".replace('_', '\\_'))
        for mode in ['nodes', 'edges']:
            table.append(
                "    & {:>6} &".format('blocks' if mode == 'nodes' else mode) + 
                " & ".join(["{:>6d}".format(len(g[mode])) for eng, g in sorted(graphs[fw].items())]) +
                "  \\\\"
            )
        # table[-1] = table[-1] + " \\midrule"

    # table.append("\\textbf{Average}")
    # avgs = []
    # for col in [4, 5, 6, 7]:
    #     relevant_data = [d[col] for d in data if (not math.isnan(d[col]) and d[col] != 0)]
    #     avgs.append(
    #         round(sum(relevant_data) / len(relevant_data) if len(relevant_data) else nan, 2))

    # table.append(
    #     "    &     &      &      &      &      & " +
    #     "{:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\% \\\\ \\bottomrule".format(*avgs))
    table.append("\\end{tabular}")

    with open(f"{OUT_DIR}/real-world-results.tex", 'w') as outfile:
        outfile.write('\n'.join(table))