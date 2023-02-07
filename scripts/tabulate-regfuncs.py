import os
import sys
import re
import json
from argparse import ArgumentParser
from os.path import basename
from glob import glob

import dill

PARENT_DIR = os.path.dirname(os.path.realpath(__file__))
CFG_FN_PTRN = re.compile(r"(?P<fw>\w+)-(?P<opt>o[0123])-(?P<engine>\w+)-cfg\.pkl")


if __name__ == "__main__":
    parser = ArgumentParser('cmp-results.py')
    parser.add_argument('-d', default=f'{PARENT_DIR}/../tests/cfgs',
        help="path to pickled cfg folder")
    parser.add_argument('-o', default=f"{PARENT_DIR}/tbl",
        help="output folder for tables")
    parser.add_argument('--json-path', dest='jsonpath', default=f"{PARENT_DIR}/../tests/registered-functions.json")

    args = parser.parse_args()
    outdir = args.o

    pklpaths = glob(f"{args.d.rstrip('/')}/*.pkl")

    graphs = {}
    engs = set()

    # load all the generated graphs
    for path in pklpaths:
        # should always match the filename
        match = CFG_FN_PTRN.search(basename(path))

        fw  = match.group('fw')
        opt = match.group('opt')
        eng = match.group('engine')
        engs.add(eng)

        with open(path, 'rb') as pklfile:
            graph = dill.load(pklfile)

        if fw not in graphs:
            graphs[fw] = {}
        if eng not in graphs[fw]:
            graphs[fw][eng] = {}
        graphs[fw][eng][opt] = graph

    if not os.path.exists(outdir):
        os.mkdir(outdir)

    engs = list(engs)


    with open(args.jsonpath, 'r') as jsonfile:
        registered_functions = json.load(jsonfile)

    table = []
    table.append("\\begin{tabular}{@{}ll" + 'c' * len(engs) + "@{}}")
    table.append("\\toprule")

    table.append((
        "\\multicolumn{2}{l}{\\textbf{Firmware}} & "
        + " & ".join([eng.replace('_', '\\_') for eng in sorted(engs)])
        + " \\\\ \\midrule"
    ))

    opts = ['o0', 'o1', 'o2', 'o3']

    for fw in sorted(graphs.keys()):
        if any([opt not in registered_functions[fw] for opt in opts]):
            continue
        table.append(f"\\multirow{{4}}{{*}}{{{fw}}}".replace('_', '\\_'))
        for opt in opts:
            row = f"    & -{opt.upper()}"
            for eng in sorted(engs):
                found_rf_edges = set()
                found_rf_blocks = set()
                total_rf = 0
                for func, loc in registered_functions[fw][opt].items():
                    total_rf += 1
                    loc = int(loc, base=16)
                    # check if block found
                    for block in graphs[fw][eng][opt]['nodes']:
                        if block[0] == loc:
                            found_rf_blocks.add(block)
                            break
                    # find edges
                    for edge in graphs[fw][eng][opt]['edges']:
                        if edge[1] == loc:
                            found_rf_edges.add(edge)
                row += " & {:>8}".format(f"{len(found_rf_edges)}/{len(found_rf_blocks)}/{total_rf}")
            row += " \\\\"
            table.append(row)
        table[-1] = table[-1] + " \\midrule"
    table[-1] = table[-1].replace("\\midrule", "\\bottomrule")

    table.append("\\end{tabular}")

    tabletxt = '\n'.join(table)

    with open(f"{outdir}/found-registered.tex", 'w') as texfile:
        texfile.write(tabletxt)

    print(tabletxt)
    print()











