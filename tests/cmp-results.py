import os
import sys
import re
from argparse import ArgumentParser
from os.path import basename
from glob import glob
from math import nan

import dill

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

        # "{:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\% & {:>6.02f}\\%".format(
        #     round(node_overlap / len(cfg1['nodes']) * 100 if cfg1['nodes'] else nan, 2),
        #     round(node_overlap / len(cfg2['nodes']) * 100 if cfg2['nodes'] else nan, 2),
        #     round(edge_overlap / len(cfg1['edges']) * 100 if cfg1['edges'] else nan, 2),
        #     round(edge_overlap / len(cfg2['edges']) * 100 if cfg2['edges'] else nan, 2))
    )
    return comparison

if __name__ == "__main__":

    parser = ArgumentParser('cmp-results.py')
    parser.add_argument('-d', default='tests/cfgs')

    args = parser.parse_args()

    pklpaths = glob(f"{args.d.rstrip('/')}/*.pkl")

    graphs = {}

    # load all the generated graphs
    for path in pklpaths:
        # should always match the filename
        match = CFG_FN_PTRN.search(basename(path))

        fw  = match.group('fw')
        opt = match.group('opt')
        eng = match.group('engine')

        with open(path, 'rb') as pklfile:
            graph = dill.load(pklfile)

        if fw not in graphs:
            graphs[fw] = {}
        if eng not in graphs[fw]:
            graphs[fw][eng] = {}
        graphs[fw][eng][opt] = graph

    # do comparison of ffxe with all other engines and print resulting tables
    for fw, engs in sorted(graphs.items()):
        for eng, opts in sorted(engs.items()):
            if eng == 'ffxe':
                continue

            comp_table = []
            for opt, cfg in sorted(opts.items()):
                comparison = compare(
                    graphs[fw]['ffxe'][opt], cfg, prepend=f"& -{opt.upper()}")
                comp_table.append(comparison)
            print(fw, f"ffxe vs {eng}")
            print('\n'.join(comp_table))
            print()
