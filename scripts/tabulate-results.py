import os
import sys
import re
import math
from argparse import ArgumentParser
from os.path import basename
from glob import glob
from math import nan

import dill

PARENT_DIR = os.path.dirname(os.path.realpath(__file__))
CFG_FN_PTRN = re.compile(r"(?P<fw>\w+)-(?P<opt>o[0123])-(?P<engine>\w+)-cfg\.pkl")

def compare(cfg1 : dict, cfg2 : dict, prepend=''):
    """helper to compare cfgs"""
    assert 'nodes' in cfg1 and 'nodes' in cfg2, \
        "cfg missing 'nodes' keyword"
    assert isinstance(cfg1['nodes'], set) and isinstance(cfg2['nodes'], set), \
        "graph nodes must be a set of tuples"
    assert 'edges' in cfg1 and 'edges' in cfg2, \
        "cfg missing 'edges' keyword"
    assert isinstance(cfg1['edges'], set) and isinstance(cfg2['edges'], set), \
        "graph edges must be a set of tuples"

    # compute the block and edge overlap
    node_overlap = len(cfg1['nodes'].intersection(cfg2['nodes']))
    edge_overlap = len(cfg1['edges'].intersection(cfg2['edges']))

    comparison = (
        (f"{prepend} & " if prepend else '') +
        # 1-blks  2-blks   1-edges  2-edges  1-%blkolp  2-%blkolp  1-%edgolp  2-%edgolp
        "{:>4d} & {:>4d} & {:>4d} & {:>4d} & {:>4d} & {:>4d}".format(
            len(cfg1['nodes']),
            node_overlap, 
            len(cfg2['nodes']), 
            len(cfg1['edges']),
            edge_overlap, 
            len(cfg2['edges']))
    )
    return comparison

def compare_percent_overlap(cfg1 : dict, cfg2 : dict, pre='', post=''):
    """helper to compare cfgs with percentages"""
    assert 'nodes' in cfg1 and 'nodes' in cfg2, \
        "cfg missing 'nodes' keyword"
    assert isinstance(cfg1['nodes'], set) and isinstance(cfg2['nodes'], set), \
        "graph nodes must be a set of tuples"
    assert 'edges' in cfg1 and 'edges' in cfg2, \
        "cfg missing 'edges' keyword"
    assert isinstance(cfg1['edges'], set) and isinstance(cfg2['edges'], set), \
        "graph edges must be a set of tuples"

    # compute the block and edge overlap
    node_overlap = len(cfg1['nodes'].intersection(cfg2['nodes']))
    edge_overlap = len(cfg1['edges'].intersection(cfg2['edges']))

    compare_data = [
        len(cfg1['nodes']),
        len(cfg2['nodes']),
        len(cfg1['edges']),
        len(cfg2['edges']),
        round(node_overlap / len(cfg1['nodes']) * 100 if cfg1['nodes'] else nan, 2),
        round(node_overlap / len(cfg2['nodes']) * 100 if cfg2['nodes'] else nan, 2),
        round(edge_overlap / len(cfg1['edges']) * 100 if cfg1['edges'] else nan, 2),
        round(edge_overlap / len(cfg2['edges']) * 100 if cfg2['edges'] else nan, 2),
    ]

    compare_str = (
        (f"{pre} & " if pre else '') +
        # 1-blks  2-blks   1-edges  2-edges  1-%blkolp  2-%blkolp  1-%edgolp  2-%edgolp
        ("{:>4d} & {:>4d} & {:>4d} & {:>4d} & "
                "{:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\%").format(*compare_data) +
        (f" {post}" if post else '')
    )
    return compare_data, compare_str

def gen_overlap_table(graphs : dict, eng1 : str, eng2 : str='ffxe'):
    """takes all graphs and both engines to compare 
    and spits out the full latex comparison table
    """
    table = []
    table.append("\\begin{tabular}{@{}llllllllll@{}}")
    table.append("\\toprule")
    # write table header
    e2 = eng2.replace('_', '\\_')
    e1 = eng1.replace('_', '\\_')
    table.append((
        "\\multicolumn{2}{l}{\\textbf{Firmware}} & "
        f"$|V_{{{e1}}}|$ & $|V_{{{e2}}}|$ & "
        f"$|E_{{{e1}}}|$ & $|E_{{{e2}}}|$ & "
        f"$\\frac{{|V_{{{e1}}} \\cap V_{{{e2}}}|}}{{|V_{{{e1}}}|}}$ & "
        f"$\\frac{{|V_{{{e1}}} \\cap V_{{{e2}}}|}}{{|V_{{{e2}}}|}}$ & "
        f"$\\frac{{|E_{{{e1}}} \\cap E_{{{e2}}}|}}{{|E_{{{e1}}}|}}$ & "
        f"$\\frac{{|E_{{{e1}}} \\cap E_{{{e2}}}|}}{{|E_{{{e2}}}|}}$ "
        "\\\\ \\midrule"
    ))

    # write table rows
    data = []
    for fw in sorted(graphs.keys()):
        table.append(f"\\multirow{{4}}{{*}}{{{fw}}}".replace('_', '\\_'))
        for opt in ['o0', 'o1', 'o2', 'o3']:
            compare_data, compare_str = compare_percent_overlap(
                graphs[fw][eng1][opt], graphs[fw][eng2][opt],
                pre=f"    & -{opt.upper()}",
                post="\\\\")
            table.append(compare_str)
            data.append(compare_data)
        table[-1] = table[-1] + " \\midrule"

    table.append("\\textbf{Average}")
    avgs = []
    for col in [4, 5, 6, 7]:
        relevant_data = [d[col] for d in data if (not math.isnan(d[col]) and d[col] != 0)]
        avgs.append(
            round(sum(relevant_data) / len(relevant_data) if len(relevant_data) else nan, 2))

    table.append(
        "    &     &      &      &      &      & " +
        "{:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\% \\\\ \\bottomrule".format(*avgs))
    table.append("\\end{tabular}")

    return '\n'.join(table)


if __name__ == "__main__":

    parser = ArgumentParser('cmp-results.py')
    parser.add_argument('-d', default=f'{PARENT_DIR}/../tests/cfgs',
        help="path to pickled cfg folder")
    parser.add_argument('-o', default=f"{PARENT_DIR}/tbl",
        help="output folder for tables")

    args = parser.parse_args()
    outdir = args.o

    pklpaths = glob(f"{args.d.rstrip('/')}/*.pkl")

    graphs = {}
    engs = []

    # load all the generated graphs
    for path in pklpaths:
        # should always match the filename
        match = CFG_FN_PTRN.search(basename(path))

        fw  = match.group('fw')
        opt = match.group('opt')
        eng = match.group('engine')
        engs.append(eng)

        with open(path, 'rb') as pklfile:
            graph = dill.load(pklfile)

        if fw not in graphs:
            graphs[fw] = {}
        if eng not in graphs[fw]:
            graphs[fw][eng] = {}
        graphs[fw][eng][opt] = graph

    # # do comparison of ffxe with all other engines and print resulting tables
    # for fw, engs in sorted(graphs.items()):
    #     for eng, opts in sorted(engs.items()):
    #         if eng == 'ffxe':
    #             continue

    #         comp_table = []
    #         for opt, cfg in sorted(opts.items()):
    #             comparison = compare(
    #                 graphs[fw]['ffxe'][opt], cfg, prepend=f"& -{opt.upper()}")
    #             comp_table.append(comparison)
    #         print(fw, f"ffxe vs {eng}")
    #         print('\n'.join(comp_table))
    #         print()

    if not os.path.exists(outdir):
        os.mkdir(outdir)

    engs = list(set(engs))

    for eng in engs:
        cmp_table = gen_overlap_table(graphs, eng)
        with open(f"{outdir}/ffxe-vs-{eng}.tex", 'w') as f:
            f.write(cmp_table)
        print(cmp_table)
        print()
