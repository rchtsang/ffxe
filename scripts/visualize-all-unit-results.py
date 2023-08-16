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

"""
A script to create horizontal bar charts of cfg overlap
"""


PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")
CFG_FN_PTRN = re.compile(r"(?P<fw>\w+)-(?P<opt>o[0123])-(?P<engine>\w+)-cfg\.pkl")

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

    opts = ['o0', 'o1', 'o2', 'o3']
    only0 = { opt:[] for opt in opts }
    ovrlp = { opt:[] for opt in opts }
    only1 = { opt:[] for opt in opts }

    for fw_name in sorted(fw_names, reverse=True):
        for opt in opts:
            nodes0 = graphs[fw_name][eng0][opt]['nodes']
            nodes1 = graphs[fw_name][eng1][opt]['nodes']

            coverage0 = coverage[fw_name][eng0][opt]
            coverage1 = coverage[fw_name][eng1][opt]

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

            only0[opt].append(len(eng0_only))
            only1[opt].append(len(eng1_only))
            ovrlp[opt].append(len(overlap))

    for opt in opts:
        only0[opt] = np.array(only0[opt])
        only1[opt] = np.array(only1[opt])
        ovrlp[opt] = np.array(ovrlp[opt])

    return [ (eng0, only0), ('ovlp', ovrlp), (eng1, only1) ]


def generate_coverage_set(graphs, fw_name, engine, opt):
    """utility for generating the address space coverage of cfg 
    for a given firmware and engine
    returns a set of tuples representing the covered address range
    tuples of form (start, size)
    """
    ranges = set()
    range_start = 0
    range_size = 0
    for naddr, nsize in sorted(graphs[fw_name][engine][opt]['nodes']):
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
            coverage[fw_name][eng] = {}
            for opt in ['o0', 'o1', 'o2', 'o3']:
                ranges = generate_coverage_set(graphs, fw_name, eng, opt)
                coverage[fw_name][eng][opt] = ranges

    return coverage


def get_ovlp_data(graphs, engine, settype):
    """a helper function to get intersection data"""
    opts = [f"o{i}" for i in range(4)]
    ffxe_opts = { o:[] for o in opts }
    ovlp_opts = { o:[] for o in opts }
    othr_opts = { o:[] for o in opts }
    for fw in sorted(graphs.keys(), reverse=True):
        for opt in opts:
            # get graphs to compare
            ffxe_cfg = graphs[fw]['ffxe'][opt]
            othr_cfg = graphs[fw][engine][opt]
            
            # compute overlaps
            ovlp = ffxe_cfg[settype].intersection(othr_cfg[settype])
            ffxe_only = ffxe_cfg[settype].difference(ovlp)
            othr_only = othr_cfg[settype].difference(ovlp)
            
            ffxe_opts[opt].append(len(ffxe_only))
            othr_opts[opt].append(len(othr_only))
            ovlp_opts[opt].append(len(ovlp))
    
    for opt in opts:
        ffxe_opts[opt] = np.array(ffxe_opts[opt])
        ovlp_opts[opt] = np.array(ovlp_opts[opt])
        othr_opts[opt] = np.array(othr_opts[opt])
    
    ovlp_data = [ ('ffxe', ffxe_opts), ('ovlp', ovlp_opts), (engine, othr_opts) ]
    return ovlp_data

def make_ovlp_subplot(ax, ovlp_data, getsublabels=False):
    """helper function to plot horizontal bar chart subplots"""
    
    # set up symmetrix x axis
    ax.xaxis.set_major_locator(ticker.MaxNLocator(symmetric=True))
    
    # setup data
    opts = [f"o{i}" for i in range(4)]
    engine = ovlp_data[-1][0]
    ovlp_data = dict(ovlp_data)
    ffxe_opts = ovlp_data['ffxe']
    ovlp_opts = ovlp_data['ovlp']
    othr_opts = ovlp_data[engine]

    sublabels = []
    ffxe_rects = {}
    ovlp_rects = {}
    othr_rects = {}
    # offsets = [3, 1, -1, -3] # fw name in center of opts
    offsets = [0, -2, -4, -6] # o0 aligned with fw name
    # offsets = [-6, -4, -2, 0] # 03 aligned with fw name
    down_shift = 0.1 # adding space between bars and grid lines
    annotate_size = 9 # fontsize of annotation
    for opt, offset in zip(opts, offsets):
        # left shift to center bars
        left_shift = -ovlp_opts[opt] / 2
        
        ffxe_rects[opt] = ax.barh(
            fw_label_locs + (bar_width * offset / 2) - down_shift, 
            ffxe_opts[opt],
            height=-bar_width,
            color=tableau10['blue'],
            left=(left_shift - ffxe_opts[opt]),
            align='edge'
        )
        # add annotations to left
        for bar in ffxe_rects[opt]:
            ax.text(
                bar.get_x(),
                bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
                round(bar.get_width()),
                va='center',
                ha='right',
                size=annotate_size
            )
        ovlp_rects[opt] = ax.barh(
            fw_label_locs + (bar_width * offset / 2) - down_shift, 
            ovlp_opts[opt], 
            height=-bar_width,
            color=tableau10['purple'],
            left=(left_shift),
            align='edge'
        )
        # add annotations centered
        for bar in ovlp_rects[opt]:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
                round(bar.get_width()),
                va='center',
                ha='center',
                # color=tableau10['yellow'],
                color='w',
                size=annotate_size
            )
        othr_rects[opt] = ax.barh(
            fw_label_locs + (bar_width * offset / 2) - down_shift, 
            othr_opts[opt], 
            height=-bar_width,
            color=tableau10['red'],
            left=(left_shift + ovlp_opts[opt]),
            align='edge'
        )
        # add annotations to right
        for bar in othr_rects[opt]:
            ax.text(
                bar.get_x() + bar.get_width(),
                bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
                round(bar.get_width()),
                va='center',
                ha='left',
                size=annotate_size
            )
        
        if getsublabels:
            for bar in ffxe_rects[opt]:
                bar_center = (bar.get_y() + bar.get_height() / 2)
                sublabels.append((opt, bar_center))
                
    return np.array(sublabels).T



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', default=f"{PROJ_DIR}/tests/cfgs/unit-tests")
    parser.add_argument('-d', default=f"{PARENT_DIR}/img")
    
    args = parser.parse_args()

    SRC_DIR = args.i
    OUT_DIR = args.d

    pklpaths = glob(f"{SRC_DIR}/*.pkl")

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

    if not exists(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    # generate coverage data
    coverage = generate_coverage(graphs, engs, graphs.keys())

    engs = ['fxe', 'angr_emu', 'angr_fast', 'angr_cnnctd', 'ghidra_simple', 'ghidra_cnnctd']

    fw_labels = list(sorted(graphs.keys(), reverse=True))
    fw_label_locs = np.arange(len(fw_labels))
    bar_width = 0.2

    fig, (nodes_ax, edges_ax) = plt.subplots(
        nrows=2, 
        ncols=len(engs), 
        sharey=True,
        figsize=(24,16),
        gridspec_kw={
            'wspace': 0.025, 
            'hspace': 0.025
        }
    )

    # don't align bars with y axis
    fig.gca().use_sticky_edges = False

    for settype, axs in zip(['nodes', 'edges'], (nodes_ax, edges_ax)):
        for eng, ax in zip(engs, axs):
            if settype == 'nodes':
                if exists(cached := f"{PARENT_DIR}/.cache/{eng}-blocks-unit-cmp.pkl"):
                    with open(cached, 'rb') as pklfile:
                        ovlp_data = dill.load(pklfile)
                else:
                    print(f"calculating coverage overlap for {eng}...")
                    ovlp_data = compare_coverage(graphs, coverage, 'ffxe', eng)
                    with open(cached, 'wb') as pklfile:
                        dill.dump(ovlp_data, pklfile)
            else:
                ovlp_data = get_ovlp_data(graphs, eng, settype)
            
            sublabels = make_ovlp_subplot(ax, ovlp_data, getsublabels=(eng == 'fxe'))
            
            if settype == 'nodes':
                ax.set_title(eng,
                    fontsize=28)
            
            # hide plot borders
            ax.spines['top'].set_visible(False)
            ax.spines['bottom'].set_visible(False)
            ax.spines['right'].set_visible(False)

            ax.yaxis.grid(True) # turn on horizontal grid lines
            ax.xaxis.set_visible(False) # hide x axis labels
            
            # add edge space
            space = 250
            if settype == 'edges':
                space = 350
            (llim, rlim) = ax.get_xlim()
            ax.set_xlim(left=(llim - space), right=(rlim + space))
            
            if sublabels.size:
                # nodes/edges y axis
                ax.set_ylabel(settype,
                    fontsize=32)

                # set major y labels
                ax.set_yticks(fw_label_locs, fw_labels,
                    # verticalalignment='center',
                    rotation=45,
                    fontsize=20)
                # add optimization labels
                locs = list(sublabels[1].astype(float))
                text = list(sublabels[0])
                text = ['-' + t for t in text]
                ax.set_yticks(locs, text, minor=True)

                ax.tick_params(axis='y', which='major', pad=25) # spacing between y axis and major labels 
                ax.tick_params(axis='y', which='major', left=False)

    # fig.canvas.draw()
    fig.savefig(f"{OUT_DIR}/ffxe-vs-all.svg", 
        transparent=True, bbox_inches='tight', format='svg')
            