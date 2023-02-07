import os
import sys
import re
import json
from argparse import ArgumentParser
from os.path import basename

PARENT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJ_DIR = os.path.realpath(f"{PARENT_DIR}/..")
RE_RESULTFILE_PTRN = re.compile(r"(?P<eng>.+)-cfg-results\.txt")
RE_LOG_PTRN = re.compile(
    r"(?P<fw>(?P<name>\w+)(?P<opt>-o[0-3])\.bin)?\s+(?P<eng>[a-zA-Z]+)?(:?\s+)?"
    r"(?P<nblocks>\d+) blocks\s+"
    r"(?P<nedges>\d+) edges\s+"
    r"elapsed(?::| \(s\):) (?P<runtime>[\d\.]+)(:? s)?"
)

if __name__ == "__main__":
    parser = ArgumentParser('tabulate-runtimes.py')
    parser.add_argument('--inputs', nargs='+', default=[
            f"{PROJ_DIR}/tests/ffxe-cfg-results.txt",
            f"{PROJ_DIR}/tests/fxe-cfg-results.txt",
            f"{PROJ_DIR}/scripts/angr-cfg-results.txt"],
        help="path to pickled cfg folder")
    parser.add_argument('-o', default=f"{PARENT_DIR}/tbl",
        help="output folder for tables")
    parser.add_argument('--json-path', dest='jsonpath', default=f"{PARENT_DIR}/../tests/registered-functions.json")

    args = parser.parse_args()
    outdir = args.o

    # get runtimes for each file
    runtimes = {}
    engs = set()
    fws = set()
    for filename in args.inputs:
        # only process files that match the expected format
        match = RE_RESULTFILE_PTRN.search(basename(filename))
        if match:
            base_eng = match.group('eng')

            with open(filename, 'r') as resultfile:
                table_text = resultfile.read()

            # process file
            prev_fw_name = ('', '')
            for match in RE_LOG_PTRN.finditer(table_text):
                groups = match.groupdict()
                eng = base_eng
                if groups['fw']:
                    prev_fw_name = (groups['name'], groups['opt'])
                    fws.add(groups['name'])
                if groups['eng']:
                    if groups['eng'] == 'fast':
                        continue
                    eng = f"{eng}_{groups['eng']}"
                if eng not in runtimes:
                    runtimes[eng] = {}
                    engs.add(eng)
                if prev_fw_name[0] not in runtimes[eng]:
                    runtimes[eng][prev_fw_name[0]] = {}
                runtimes[eng][prev_fw_name[0]][prev_fw_name[1]] = float(groups['runtime'])

    engs = list(sorted(engs))
    fws = list(sorted(fws))

    # tabulate runtimes
    table = []
    table.append("\\begin{tabular}{@{}ll" + 'r' * len(engs) + "@{}}")
    table.append("\\toprule")

    table.append((
        "\\multicolumn{2}{l}{\\textbf{Firmware}} & "
        + " & ".join([eng.replace('_', '\\_') for eng in engs])
        + " \\\\ \\midrule"
    ))

    opts = ['-o0', '-o1', '-o2', '-o3']

    for fw in fws:
        table.append(f"\\multirow{{4}}{{*}}{{{fw}}}".replace('_', '\\_'))
        for opt in opts:
            row = "    & {} & {} \\\\".format(
                opt.upper(),
                " & ".join(
                    ["{:>8.04f}".format(round(runtimes[eng][fw][opt], 4)) \
                        for eng in engs])
            )
            table.append(row)
        table[-1] = table[-1] + " \\midrule"
    table[-1] = table[-1].replace("\\midrule", "\\bottomrule")
    table.append("\\end{tabular}")

    tabletxt = '\n'.join(table)

    with open(f"{outdir}/runtimes.tex", 'w') as texfile:
        texfile.write(tabletxt)

    print(tabletxt)
    print()

    