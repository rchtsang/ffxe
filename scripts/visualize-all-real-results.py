import os
import sys
import re
import argparse
from os.path import *
from pathlib import Path
from glob import glob

import dill
import numpy as np
import pandas as pd

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib import rcParams
import seaborn as sns

from IPython import embed

"""
A script to create horizontal bar charts of cfg overlap
blocks always considered overlapping if any block 
"""

DEBUG = False

PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")
CFG_FN_PTRN = re.compile(r"(?P<fw>\w+)-(?P<engine>\w+)-cfg\.pkl")

tableau10raw = {
    "blue"   :(80, 122, 166), 
    "orange" :(240, 142, 57), 
    "red"    :(223, 88, 92),  
    "cyan"   :(120, 183, 178),
    "green"  :(91, 160, 83),  
    "yellow" :(236, 200, 84), 
    "purple" :(175, 123, 161),
    "pink"   :(253, 158, 169),
    "brown"  :(156, 117, 97), 
    "grey"   :(186, 176, 172) 
}

tableau10 = {k:'#%02x%02x%02x' % (v[0], v[1], v[2]) for k, v in tableau10raw.items()}

sns.set_theme(style='white',
              palette=tableau10.values())

rcParams.update({
    'font.family': 'Arial Rounded MT Bold',
    'axes.unicode_minus': False
})


def overlapping(start1, end1, start2, end2):
    """util to compute if 2 ranges overlap (edge exclusive)"""
    return end1 > start2 and end2 > start1


def compare_coverage(graphs, coverage, eng0, eng1):
    """utility for comparing coverage of cfgs for all firmware
    returns the overlap and exclusive coverage of each engine
    loop through both sorted node sets and compare elements for overlap
    """
    fw_names = list(sorted(graphs.keys()))

    start = lambda n: n[0]
    end = lambda n: n[0] + n[-1]

    def covers(range1, range2):
        """returns true if range1 strictly inside range2 or vice versa"""
        return ((start(range1) <= start(range2) and end(range2) <= end(range1))
            or (start(range2) <= start(range1) and end(range1) <= end(range2)))

    only0 = []
    ovrlp = []
    only1 = []

    for fw_name in fw_names:
        nodes0 = graphs[fw_name][eng0]['nodes']
        nodes1 = graphs[fw_name][eng1]['nodes']

        coverage0 = coverage[fw_name][eng0]
        coverage1 = coverage[fw_name][eng1]

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

        only0.append(len(eng0_only))
        only1.append(len(eng1_only))
        ovrlp.append(len(overlap))

    only0 = np.array(only0)
    only1 = np.array(only1)
    ovrlp = np.array(ovrlp)

    return [ (eng0, only0), ('ovlp', ovrlp), (eng1, only1) ]


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


def compare_graphs(graphs, eng0, eng1, settype):
    """utility for comparing blocks or edges of cfgs for a given firmware
    returns the overlap and exclusive blocks or edges of each engine based on settype
    data is in order sorted by firmware name
    """
    fw_names = list(sorted(graphs.keys()))
    only0 = []
    ovrlp = []
    only1 = []
    for fw in fw_names:
        # pointers to graphs of interest
        eng0_cfg = graphs[fw][eng0]
        eng1_cfg = graphs[fw][eng1]

        # compute intersection and disjoint sets
        ovlp = eng0_cfg[settype].intersection(eng1_cfg[settype])
        eng0_only = eng0_cfg[settype].difference(ovlp)
        eng1_only = eng1_cfg[settype].difference(ovlp)

        only0.append(len(eng0_only))
        only1.append(len(eng1_only))
        ovrlp.append(len(ovlp))

    only0 = np.array(only0)
    only1 = np.array(only1)
    ovrlp = np.array(ovrlp)

    return [ (eng0, only0), ('ovlp', ovrlp), (eng1, only1) ]


def draw_subplot(ax, data, config, row_name=None):
    """helper function to plot horizontal bar venn diagram subplots
    expects data to be a list of tuples where the first element is the 
    engine name and the second is a dictionary containing
    ndarray containing counts in sorted order by fw_name
    """

    # set up symmetrix x axis
    ax.xaxis.set_major_locator(ticker.MaxNLocator(symmetric=True))

    # setup data
    ffxe_data = data[0][1]
    ovlp_data = data[1][1]
    othr_data = data[2][1]

    down_shift    = 0.75             # add space between bars and grid lines
    annotate_size = 9               # font size of annotation in bars
    left_shift    = -ovlp_data / 2  # left shift to center bars

    ### plot bars first

    # ffxe bars
    ffxe_rects = ax.barh(
        config['fw_label_locs'] - down_shift, # + config['bar_width'],
        ffxe_data,
        height=config['bar_width'],
        color=tableau10['blue'],
        left=(left_shift - ffxe_data),
        align='edge'
    )

    # overlap bars
    ovlp_rects = ax.barh(
        config['fw_label_locs'] - down_shift, # + config['bar_width'],
        ovlp_data,
        height=config['bar_width'],
        color=tableau10['purple'],
        left=(left_shift),
        align='edge'
    )

    # other bars
    othr_rects = ax.barh(
        config['fw_label_locs'] - down_shift, # + config['bar_width'],
        othr_data,
        height=config['bar_width'],
        color=tableau10['red'],
        left=(left_shift + ovlp_data),
        align='edge'
    )

    ### add edge space
    edge_spacing = config['edge_spacing']
    max_width = max(ffxe_data + ovlp_data + othr_data)
    if edge_spacing < (max_width / 20):
        # increase spacing based on empirically established threshold
        edge_spacing = (max_width // 100 + 1) * 10

    (llim, rlim) = ax.get_xlim()
    ax.set_xlim(
        left=(llim - edge_spacing),
        right=(rlim + edge_spacing)
    )

    ### add annotations

    # add annotations to left
    for bar in ffxe_rects:
        text = ax.text(
            bar.get_x(),
            bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
            round(bar.get_width()),
            va='center',
            ha='right',
            size=annotate_size
        )
        text_bb = text.get_window_extent()
        text_width = text_bb.width
        bar_bb = bar.get_window_extent()
        bar_width = bar_bb.width
        if text_width < bar_width:
            # place text inside bar
            x, y = text.get_position()
            text.set(
                position=(x + edge_spacing / 10, y),
                horizontalalignment='left', 
                color='w',
            )

    # add annotations to center
    for bar in ovlp_rects:
        text = ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_y() + bar.get_height() * 3 / 2 - 0.05, # place text above bar
            round(bar.get_width()),
            va='center',
            ha='center',
            # color='w',
            size=annotate_size
        )

    # add annotation to right
    for bar in othr_rects:
        text = ax.text(
            bar.get_x() + bar.get_width(),
            bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
            round(bar.get_width()),
            va='center',
            ha='left',
            size=annotate_size
        )
        text_bb = text.get_window_extent()
        text_width = text_bb.width
        bar_bb = bar.get_window_extent()
        bar_width = bar_bb.width
        if text_width < bar_width:
            # place text inside bar
            x, y = text.get_position()
            text.set(
                position=(x - edge_spacing / 10, y),
                horizontalalignment='right', 
                color='w'
            )

    # hide plot borders
    ax.spines['top'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax.yaxis.grid(True) # turn on horizontal grid lines
    ax.xaxis.set_visible(False) # hide x axis labels

    # add labels if first engine
    if row_name:
        # set y axis name
        ax.set_ylabel(row_name, 
            fontsize=config['subtitle_fontsize'])

        # set major y labels (firmware names)
        ax.set_yticks(fw_label_locs, fw_labels,
            # verticalalignment='center',
            rotation=45,
            fontsize=config['tick_fontsize'])

        # add spacing between y axis line and edge of labels
        ax.tick_params(axis='y', which='major', pad=25, left=False)

    return


parser = argparse.ArgumentParser()
parser.add_argument('-i', default=f"{PROJ_DIR}/tests/cfgs/real-world")
parser.add_argument('-d', default=f"{PARENT_DIR}/img")

if __name__ == "__main__":
    args = parser.parse_args()

    SRC_DIR = args.i
    OUT_DIR = args.d

    # load the graphs
    print("loading pickled graphs...")
    pklpaths = glob(f"{SRC_DIR}/*.pkl")

    graphs = {} # keyed first by engines, then by fw names
    engs = set()

    # exclude some firmware images
    exclude_fws = [
        "ble_app_template_pca10056_s140",
    ]

    for path in pklpaths:
        # should always match the filename
        match = CFG_FN_PTRN.search(basename(path))

        fw  = match.group('fw')
        eng = match.group('engine')
        engs.add(eng)

        if fw in exclude_fws:
            continue

        with open(path, 'rb') as pklfile:
            graph = dill.load(pklfile)

        if fw not in graphs:
            graphs[fw] = {}
        graphs[fw][eng] = graph

    engs = list(sorted(engs))

    Path(OUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(f"{PARENT_DIR}/.cache").mkdir(parents=True, exist_ok=True)

    # construct block coverage sets
    print("generating block coverage sets...")
    coverage = generate_coverage(graphs, engs, graphs.keys())

    ##################################################
    # figure configuration

    fw_labels = list(sorted(graphs.keys(), reverse=False))
    fw_label_locs = np.arange(len(fw_labels)) - 0.5

    config = {
        'fw_labels'           : fw_labels,
        'fw_label_locs'       : fw_label_locs,
        'bar_width'           : 0.4,   # plt uses 0.8 by default
        'subtitle_fontsize'   : 32,
        'tick_fontsize'       : 20,
        'minor_tick_fontsize' : 12,
        'text_fontsize'       : 10,
        'edge_spacing'        : 350,   # add buffer between y axis and bars
        # 'e_edge_spacing'      : 450,   # add buffer between y axis and bars for edges
    }

    ##################################################
    # construct figure

    print("calculating overlap and constructing figure...")

    exclude_engs = ['angr_fast', 'ghidra_simple']
    othr_engs = [eng for eng in engs \
        if eng != 'ffxe' and eng not in exclude_engs]

    fig, (nodes_axs, edges_axs) = plt.subplots(
        nrows=2,
        ncols=len(othr_engs),
        sharey=True,
        figsize=(24,12),
        gridspec_kw={
            'wspace': 0.025,
            'hspace': 0.025
        }
    )

    fig.gca().use_sticky_edges = False
    
    # construct axes for nodes first (top row of graphs)
    row_name = 'block coverage'
    for eng, ax in zip(othr_engs, nodes_axs):

        if exists(cached := f"{PARENT_DIR}/.cache/{eng}-blocks-cmp.pkl"):
            with open(cached, 'rb') as pklfile:
                data = dill.load(pklfile)
        else:
            print(f"calculating coverage overlap for {eng}...")
            data = compare_coverage(graphs, coverage, 'ffxe', eng)
            with open(cached, 'wb') as pklfile:
                dill.dump(data, pklfile)

        print(f"plotting {eng} coverage overlap...")
        draw_subplot(ax, data, config, row_name=row_name)

        # add engine names as column titles (block coverage on top)
        ax.set_title(eng, fontsize=config['subtitle_fontsize'])
        row_name = None

    # construct axes for edges
    row_name = 'edges'
    for eng, ax in zip(othr_engs, edges_axs):

        if exists(cached := f"{PARENT_DIR}/.cache/{eng}-edges-cmp.pkl"):
            with open(cached, 'rb') as pklfile:
                data = dill.load(pklfile)
        else:
            print(f"calculating edge overlap for {eng}")
            data = compare_graphs(graphs, 'ffxe', eng, 'edges')
            with open(cached, 'wb') as pklfile:
                dill.dump(data, pklfile)

        print(f"plotting {eng} edge overlap...")
        draw_subplot(ax, data, config, row_name=row_name)
        row_name = None

    # save figure
    fig.savefig(f"{OUT_DIR}/ffxe-vs-all-real.svg",
        transparent=True, bbox_inches='tight', format='svg')


    

