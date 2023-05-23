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


def plot_comparison(graphs, other, 
        title=None, outdir='.', draw=False, suptitle=False):
    """a function to draw a side-by-side horizontal
    bar chart that shows cfg overlap
    """
    rcParams.update({
        'font.family': 'Arial Rounded MT Bold',
        'axes.unicode_minus': False
    })
    
    if not title:
        title = f"ffxe-vs-{other}"

    fw_labels = list(sorted(graphs.keys(), reverse=True))
    fw_label_locs = np.arange(len(fw_labels))
    bar_width = 0.2

    # ax0 for graph node comparison
    opts = [f"o{i}" for i in range(4)]
    ffxe_opts = { k: { o:[] for o in opts } for k in ['nodes', 'edges'] }
    othr_opts = { k: { o:[] for o in opts } for k in ['nodes', 'edges'] }
    ovlp_opts = { k: { o:[] for o in opts } for k in ['nodes', 'edges'] }
    for fw in fw_labels:
        for opt in opts:
            # get graphs to compare
            ffxe_cfg = graphs[fw]['ffxe'][opt]
            othr_cfg = graphs[fw][other][opt]

            # comput node overlaps
            for k in ['nodes', 'edges']:
                ovlp = ffxe_cfg[k].intersection(othr_cfg[k])
                ffxe_only = ffxe_cfg[k].difference(ovlp)
                othr_only = othr_cfg[k].difference(ovlp)

                ffxe_opts[k][opt].append(len(ffxe_only))
                othr_opts[k][opt].append(len(othr_only))
                ovlp_opts[k][opt].append(len(ovlp))

    for k in ['nodes', 'edges']:
        for opt in opts:
            ffxe_opts[k][opt] = np.array(ffxe_opts[k][opt])
            ovlp_opts[k][opt] = np.array(ovlp_opts[k][opt])
            othr_opts[k][opt] = np.array(othr_opts[k][opt])

    fig, (ax0, ax1) = plt.subplots(
        nrows=1, 
        ncols=2, 
        sharey=True,
        figsize=(12,8))

    fig.gca().use_sticky_edges = False

    sublabel_positions = []
    subtitle_fontsize = 32
    tick_fontsize = 20
    minor_tick_fontsize = 12
    label_fontsize = 10

    for k, ax in zip(('nodes', 'edges'), (ax0, ax1)):
        ax.xaxis.set_major_locator(
            ticker.MaxNLocator(symmetric=True))

        ffxe_rects = {}
        ovlp_rects = {}
        othr_rects = {}
        # offsets = [3, 1, -1, -3]
        offsets = [0, -2, -4, -6]
        # offsets = [-6, -4, -2, 0]
        max_width = 0
        down_shift = 0.1
        for opt, offset in zip(opts, offsets):
            total_widths = ffxe_opts[k][opt] + ovlp_opts[k][opt] + othr_opts[k][opt]
            max_width = max(max_width, max(total_widths))
            left_shift = -ovlp_opts[k][opt] / 2
            ffxe_rects[opt] = ax.barh(
                fw_label_locs + (bar_width * offset / 2) - down_shift, 
                ffxe_opts[k][opt],
                height=-bar_width,
                color=tableau10['blue'],
                left=(left_shift - ffxe_opts[k][opt]),
                align='edge'
            )
            # add annotations
            for bar in ffxe_rects[opt]:
                ax.text(
                    bar.get_x(),
                    bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
                    round(bar.get_width()),
                    va='center',
                    ha='right',
                    size=label_fontsize
                )
            ovlp_rects[opt] = ax.barh(
                fw_label_locs + (bar_width * offset / 2) - down_shift, 
                ovlp_opts[k][opt], 
                height=-bar_width,
                color=tableau10['purple'],
                left=(left_shift),
                align='edge'
            )
            for bar in ovlp_rects[opt]:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
                    round(bar.get_width()),
                    va='center',
                    ha='center',
                    color='w',
                    size=label_fontsize
                )
            othr_rects[opt] = ax.barh(
                fw_label_locs + (bar_width * offset / 2) - down_shift, 
                othr_opts[k][opt], 
                height=-bar_width,
                color=tableau10['red'],
                left=(left_shift + ovlp_opts[k][opt]),
                align='edge'
            )
            for bar in othr_rects[opt]:
                ax.text(
                    bar.get_x() + bar.get_width(),
                    bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
                    round(bar.get_width()),
                    va='center',
                    ha='left',
                    size=label_fontsize
                )

            # add edge space
            space = 250
            if k == 'edges':
                space = 300
            (llim, rlim) = ax.get_xlim()
            ax.set_xlim(left=(llim - space), right=(rlim + space))

            if k == 'nodes':
                for bar in ffxe_rects[opt]:
                    bar_center = (bar.get_y() + bar.get_height() / 2)
                    sublabel_positions.append(bar_center)


        ax.set_title(k,
            fontsize=subtitle_fontsize)

        # hide plot borders
        ax.spines['top'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['right'].set_visible(False)

        ax.yaxis.grid(True) # turn on horizontal grid lines
        ax.xaxis.set_visible(False) # hide x axis labels

        if k == 'nodes':
            ax.set_ylabel('Samples',
                fontsize=subtitle_fontsize)

            # set major y labels
            ax.set_yticks(fw_label_locs, fw_labels,
                # verticalalignment='center',
                rotation=45,
                fontsize=tick_fontsize)
            # add optimization labels
            sublabels = ['-' + opt for opt in opts for fw in fw_labels]
            ax.set_yticks(sublabel_positions, sublabels, 
                fontsize=minor_tick_fontsize,
                minor=True)

            ax.tick_params(axis='y', which='major', pad=25) # spacing between y axis and major labels 
            # ax.tick_params(axis='y', which='major', left=False)

    if suptitle: fig.suptitle(title, x=0.55)
    fig.tight_layout()
    if draw:
        fig.canvas.draw()
    fig.savefig(f"{outdir}/{title}.svg", transparent=True, format='svg')

    return fig


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', default=f"{PROJ_DIR}/tests/cfgs/unit-tests")
    parser.add_argument('-d', default=f"{PARENT_DIR}/img")
    
    args = parser.parse_args()

    SRC_DIR = args.i
    OUT_DIR = args.d

    pklpaths = glob(f"{SRC_DIR}/*.pkl")

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

    if not exists(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    for eng in [
                # 'fxe', 
                'angr_emu',
                'angr_cnnctd', 
                'angr_fast', 
                'ghidra_simple',
                'ghidra_cnnctd',
            ]:
        plot_comparison(graphs, other=eng, outdir=OUT_DIR)
        