import os
import sys
import re
import json
from argparse import ArgumentParser
from os.path import basename

PARENT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJ_DIR = os.path.realpath(f"{PARENT_DIR}/..")
RE_RESULTFILE_PTRN = re.compile(r"(?P<eng>.+)-cfg-results\.json")
FW_PTRN = re.compile(
    r"(?P<fw>(?P<name>\w+)(?P<opt>-o[0-3])\.bin)?"
)

if __name__ == "__main__":
    parser = ArgumentParser('tabulate-runtimes.py')
    parser.add_argument('--inputs', nargs='+', default=[
            f"{PROJ_DIR}/tests/ffxe-cfg-results.json",
            f"{PROJ_DIR}/tests/fxe-cfg-results.json",
            f"{PROJ_DIR}/scripts/angr-cfg-results.json"],
        help="path to pickled cfg folder")
    parser.add_argument('-o', default=f"{PARENT_DIR}/tbl",
        help="output folder for tables")
    parser.add_argument('--horizontal', action='store_true',
        help="tabulate horizontally")
    parser.add_argument('--json-path', dest='jsonpath', default=f"{PARENT_DIR}/../tests/registered-functions.json")

    args = parser.parse_args()
    outdir = args.o

    # get runtimes for each file
    runtimes = {}
    engs = set()
    fws = set()

    def populate_runtimes(eng, fw, opt, data):
        if eng not in runtimes:
            runtimes[eng] = {}
            engs.add(eng)
        if fw not in runtimes[eng]:
            runtimes[eng][fw] = {}
            fws.add(fw)
        runtimes[eng][fw][opt] = float(data['elapsed'].strip(' s'))

    for filename in args.inputs:
        # only process files that match the expected format
        match = RE_RESULTFILE_PTRN.search(basename(filename))
        if match:
            base_eng = match.group('eng')

            with open(filename, 'r') as jsonfile:
                results = json.load(jsonfile)
            
            for fwname, data in results.items():
                match = FW_PTRN.search(fwname)
                if not match:
                    continue
                fw = match.group('name')
                opt = match.group('opt')
                if base_eng == 'angr':
                    for eng_type, d in data.items():
                        if eng_type == 'cnxd':
                            continue
                        eng = f"{base_eng}_{eng_type}"
                        populate_runtimes(eng, fw, opt, d)
                else:
                    populate_runtimes(base_eng, fw, opt, data)

    engs = list(sorted(engs))
    fws = list(sorted(fws))

    if args.horizontal:
        table = []
        table.append("\\begin{tabular}{@{}l|l" + 'c' * (len(fws)) + "@{}}")
        table.append("\\toprule")

        # top rows
        table.append(
            "{:<20} & {:<2} & ".format("\\textbf{Engine}", "\\textbf{Firmware}")
            # + " & ".join([f"\\multicolumn{{4}}{{c}}{{{fw}}}" for fw in fws])
            + " & ".join([fw.replace('_', '\\_') for fw in fws])
            + " \\\\"
        )
        # table.append(
        #     "{:<25} & ".format('')
        #     + " & ".join(["-O0 & -O1 & -O2 & -O3" for fw in fws])
        #     + " \\\\ \\midrule"
        # )

        opts = ['-o0', '-o1', '-o2', '-o3']

        for eng in engs:
            table.append(f"\\multirow{{4}}{{*}}{{{eng}}}".replace('_', '\\_'))
            for opt in opts:
                engine = eng.replace('_', '\\_')
                table.append(
                    "    & {} & {} \\\\".format(
                        opt.upper(),
                        " & ".join([
                                "\\textbf{{{:>8.04f}}}".format(round(runtimes[eng][fw][opt], 4)) \
                                    if eng == "ffxe" else "{:>8.04f}".format(round(runtimes[eng][fw][opt], 4)) \
                                    for fw in fws])
                    )
                )
            table[-1] = table[-1] + " \\midrule"
        table[-1] = table[-1] + " \\bottomrule"
        table.append("\\end{tabular}")

        tabletxt = '\n'.join(table)

    else:
        # tabulate runtimes
        table = []
        table.append("\\begin{tabular}{@{}ll" + 'r' * len(engs) + "@{}}")
        table.append("\\toprule")

        table.append((
            "\\multicolumn{2}{l}{\\textbf{Firmware}} & "
            + " & ".join([eng.replace('_', '\\_') if eng != "ffxe" else "\\textbf{ffxe}" \
                for eng in engs])
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
                            if eng != "ffxe" else "\\textbf{{{:>8.04f}}}".format(round(runtimes[eng][fw][opt], 4)) \
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

    