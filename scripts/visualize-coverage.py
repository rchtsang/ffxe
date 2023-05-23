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
"""


PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")
CFG_FN_PTRN = re.compile(r"(?P<fw_name>[\w-]+)-(?P<engine>\w+)-cfg\.pkl")
OPT_FN_PTRN = re.compile(r"(?P<fw>\w+)-(?P<opt>o[0123])")

DIV_FACTOR = 0x400

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


def compare_coverage(graphs, coverage, eng0, eng1, fw_name):
    """utility for comparing coverage of cfgs for a given firmware
    returns the overlap and exclusive coverage of each engine
    loop through both sorted node sets and compare elements for overlap
    """
    start = lambda n: n[0]
    end = lambda n: n[0] + n[-1]

    def covers(range1, range2):
        """returns true if range1 strictly inside range2 or vice versa"""
        return ((start(range1) <= start(range2) and end(range2) <= end(range1))
            or (start(range2) <= start(range1) and end(range1) <= end(range2)))

    nodes0 = graphs[fw_name][eng0]['nodes']
    nodes1 = graphs[fw_name][eng1]['nodes']

    coverage0 = coverage[fw_name][eng0]
    coverage1 = coverage[fw_name][eng1]

    only0 = set()
    only1 = set()
    overlap = set()

    for node in nodes0:
        if any([covers(region, node) for region in coverage1]):
            overlap.add(node)
        else:
            only0.add(node)

    for node in nodes1:
        if any([covers(region, node) for region in coverage0]):
            overlap.add(node)
        else:
            only1.add(node)

    return only0, overlap, only1


def plot_venn_diagrams_unit(graphs, coverage, other, 
        title=None, outdir='.', draw=False, suptitle=False):
    """a function to draw a side-by-side horizontal
    bar chart that shows cfg overlap
    for unit tests only
    """
    rcParams.update({
        'font.family': 'Arial Rounded MT Bold',
        'axes.unicode_minus': False
    })
    
    if not title:
        title = f"ffxe-vs-{other}"

    names_no_opts = []
    for fw_name in sorted(graphs.keys()):
        match = OPT_FN_PTRN.search(fw_name)
        if match and match.group('fw') not in names_no_opts:
            names_no_opts.append(match.group('fw'))

    fw_labels = list(sorted(names_no_opts, reverse=True))
    fw_label_locs = np.arange(len(fw_labels))
    bar_width = 0.2

    # ax0 for graph node comparison
    opts = [f"o{i}" for i in range(4)]
    ffxe_opts = { o:[] for o in opts }
    othr_opts = { o:[] for o in opts }
    ovlp_opts = { o:[] for o in opts }
    for fw in fw_labels:
        for opt in opts:
            # comput node overlaps

            ffxe_only, ovlp, othr_only = compare_coverage(graphs, coverage, 'ffxe', other, f"{fw}-{opt}")

            ffxe_opts[opt].append(len(ffxe_only))
            othr_opts[opt].append(len(othr_only))
            ovlp_opts[opt].append(len(ovlp))

    for opt in opts:
        ffxe_opts[opt] = np.array(ffxe_opts[opt])
        ovlp_opts[opt] = np.array(ovlp_opts[opt])
        othr_opts[opt] = np.array(othr_opts[opt])

    fig, ax = plt.subplots( 
        figsize=(10,8))

    fig.gca().use_sticky_edges = False

    sublabel_positions = []
    subtitle_fontsize = 32
    tick_fontsize = 20
    minor_tick_fontsize = 12
    label_fontsize = 10

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
        total_widths = ffxe_opts[opt] + ovlp_opts[opt] + othr_opts[opt]
        max_width = max(max_width, max(total_widths))
        left_shift = -ovlp_opts[opt] / 2
        ffxe_rects[opt] = ax.barh(
            fw_label_locs + (bar_width * offset / 2) - down_shift, 
            ffxe_opts[opt],
            height=-bar_width,
            color=tableau10['blue'],
            left=(left_shift - ffxe_opts[opt]),
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
            ovlp_opts[opt], 
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
            othr_opts[opt], 
            height=-bar_width,
            color=tableau10['red'],
            left=(left_shift + ovlp_opts[opt]),
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

        for bar in ffxe_rects[opt]:
            bar_center = (bar.get_y() + bar.get_height() / 2)
            sublabel_positions.append(bar_center)

    # add edge space
    space = 250
    (llim, rlim) = ax.get_xlim()
    ax.set_xlim(left=(llim - space), right=(rlim + space))

    # hide plot borders
    ax.spines['top'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax.yaxis.grid(True) # turn on horizontal grid lines
    ax.xaxis.set_visible(False) # hide x axis labels

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
    fig.savefig(f"{outdir}/{title}-coverage.svg", transparent=True, format='svg')

    return fig


def plot_venn_diagrams(graphs, coverage, fw_name, engines,
        draw : bool = False,
        suptitle : str = None,
        outdir : str = '.',
        figsize : tuple = (10, 6)):
    """utility for plotting cfg coverage overlap between engines"""
    fig, ax = plt.subplots(figsize=figsize)

    title = f"{fw_name}"

    if 'ffxe' in engines: engines.remove('ffxe')

    rcParams.update({
        'font.family': 'Arial Rounded MT Bold',
        'axes.unicode_minus': False
    })

    eng_labels = sorted(engines, reverse=True)

    bar_width           = 0.4   # plt uses 0.8 by default
    subtitle_fontsize   = 32
    tick_fontsize       = 20
    minor_tick_fontsize = 12
    text_fontsize       = 10
    edge_spacing        = 250   # add buffer between y axis and bars

    ffxe_cnts = []
    ovlp_cnts = []
    othr_cnts = []
    for eng in eng_labels:
        ffxe_only, overlap, othr_only = compare_coverage(
            graphs, coverage, 'ffxe', eng, fw_name)

        ffxe_cnts.append(len(ffxe_only))
        ovlp_cnts.append(len(overlap))
        othr_cnts.append(len(othr_only))

    ffxe_cnts = np.array(ffxe_cnts)
    ovlp_cnts = np.array(ovlp_cnts)
    othr_cnts = np.array(othr_cnts)

    total_widths = ffxe_cnts + ovlp_cnts + othr_cnts
    max_width = max(total_widths)
    left_shift = -ovlp_cnts / 2

    # plot ffxe only bars
    ffxe_rects = ax.barh(
        eng_labels, 
        ffxe_cnts,
        height=-bar_width,
        color=tableau10['blue'],
        left=(left_shift - ffxe_cnts),
        align='edge'
    )
    # add annotations
    for bar in ffxe_rects:
        ax.text(
            bar.get_x(),
            bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
            round(bar.get_width()),
            va='center',
            ha='right',
            size=text_fontsize
        )

    # plot overlap bars
    ovlp_rects = ax.barh(
        eng_labels,
        ovlp_cnts, 
        height=-bar_width,
        color=tableau10['purple'],
        left=(left_shift),
        align='edge'
    )

    for bar in ovlp_rects:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
            round(bar.get_width()),
            va='center',
            ha='center',
            color='w',
            size=text_fontsize
        )

    # plot other only bars
    othr_rects = ax.barh(
        eng_labels,
        othr_cnts, 
        height=-bar_width,
        color=tableau10['red'],
        left=(left_shift + ovlp_cnts),
        align='edge'
    )

    for bar in othr_rects:
        ax.text(
            bar.get_x() + bar.get_width(),
            bar.get_y() + bar.get_height() / 2 - 0.02, # center text in bar
            round(bar.get_width()),
            va='center',
            ha='left',
            size=text_fontsize
        )

    # add edge space
    if edge_spacing < (max_width / 20):
        edge_spacing = (max_width // 100 + 1) * 10
    (llim, rlim) = ax.get_xlim()
    ax.set_xlim(
        left=(llim - edge_spacing), 
        right=(rlim + edge_spacing))

    # hide plot borders
    ax.spines['top'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax.yaxis.grid(True) # turn on horizontal grid lines
    ax.xaxis.set_visible(False) # hide x axis labels

    ax.set_ylabel('Samples',
        fontsize=subtitle_fontsize)

    # set major y labels
    ax.set_yticks(ax.get_yticks(), eng_labels,
        # verticalalignment='center',
        rotation=45,
        fontsize=tick_fontsize)

    ax.tick_params(axis='y', which='major', pad=25) # spacing between y axis and major labels 
    # ax.tick_params(axis='y', which='major', left=False)

    if suptitle: fig.suptitle(title, x=0.55)
    fig.tight_layout()
    if draw:
        fig.canvas.draw()
    fig.savefig(f"{outdir}/{title}-coverage-ovlp.svg", transparent=True, format='svg')

    return fig


def calculate_xaxis_multiple(xmin, xmax):
    """utility to calculate multiple for ticker.MultipleLocator"""
    base = (xmin // DIV_FACTOR) * DIV_FACTOR
    xmax = ((xmax) // DIV_FACTOR + 1) * DIV_FACTOR
    range_size = xmax - base

    binsize = int(range_size // 8)
    div = 0x400
    while binsize // div >= 2:
        div *= 2
    return div


def plot_coverage_comparison(
        coverage : dict, 
        imgs : dict, 
        fw_name : str, 
        engines : list, 
        eng_cmap : dict,
        figsize : tuple = (14, 6)):
    """utility for plotting coverage comparison for single firmware"""
    fig, ax = plt.subplots(figsize=figsize)

    bars = {}
    ylabels = []
    fw_len = imgs[fw_name]['size']
    base_addr = imgs[fw_name]['base']

    for i, (eng, eng_cov) in enumerate(sorted(coverage[fw_name].items())):
        ylabels.append(eng)
        ypos = np.array([eng] * len(eng_cov))
        widths = np.array([r[1] for r in sorted(eng_cov)])
        offsets = np.array([r[0] for r in sorted(eng_cov)])
        colors = [eng_cmap[eng]] * len(eng_cov)
        bars[eng] = ax.barh(
            y=ypos,
            width=widths,
            left=offsets,
            color=colors,
            linewidth=0,
        )

    # format x axis
    xmin = base_addr
    xmax = base_addr + (((fw_len) // DIV_FACTOR + 1) * DIV_FACTOR)
    div = calculate_xaxis_multiple(xmin, xmax)
    xmax = base_addr + (((fw_len - 1) // div + 1) * div)
    ax.set_xlim(left=xmin, right=xmax)
    # div = DIV_FACTOR
    ax.xaxis.set_major_locator(
        ticker.MultipleLocator(div))
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: hex(int(x))))
    ax.xaxis.grid(True) # turn on horizontal grid lines
    for tick in ax.get_xticklabels():
        tick.set_rotation(-90)

    # highlight firmware range
    (ymin, ymax) = ax.get_ylim()
    ax.axhspan(
        ymin=ymin,
        ymax=ymax,
        xmin=(xmin - base_addr) / (xmax - xmin),
        xmax=fw_len / (xmax - xmin),
        linewidth=0,
        color=tableau10['grey'] + '40',
        zorder=0)

    # hide plot borders
    ax.spines['top'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['right'].set_visible(False)

    fig.suptitle(f"{fw_name} coverage")

    fig.tight_layout()

    return fig, ax


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', default=f"{PROJ_DIR}/tests/cfgs/unit-tests",
        help="path to input directory")
    parser.add_argument('-d', default=f"{PARENT_DIR}/img",
        help="path to output directory")
    
    args = parser.parse_args()

    is_unit_tests = (args.i == f"{PROJ_DIR}/tests/cfgs/unit-tests")

    SRC_DIR = args.i
    OUT_DIR = args.d

    pklpaths = glob(f"{SRC_DIR}/*.pkl")
    pklpaths.sort()

    graphs = {}
    imgs = {}
    engs = set()
    # load all the generated graphs
    for path in pklpaths:
        # should always match the filename
        match = CFG_FN_PTRN.search(basename(path))

        fw  = match.group('fw_name')
        eng = match.group('engine')
        engs.add(eng)

        with open(path, 'rb') as pklfile:
            graph = dill.load(pklfile)

        if fw not in graphs:
            graphs[fw] = {}
        # if eng not in graphs[fw]:
        #     graphs[fw][eng] = {}
        # graphs[fw][eng][opt] = graph
        graphs[fw][eng] = graph

        # load known firmware images
        if fw not in imgs:
            assert len(img_paths := glob(f"{PROJ_DIR}/examples/**/{fw}.bin", recursive=True)) == 1, \
                "couldn't locate exactly 1 corresponding firmware bin for {}".format(fw)
            fw_path = img_paths[0]
            fw_dir = dirname(fw_path)
            base_addr = 0x0
            if exists(base_addr_path := f"{fw_dir}/base_addr.txt"):
                with open(base_addr_path, 'r') as f:
                    base_addr = int(f.read().strip(), 0)

            with open(fw_path, 'rb') as binfile:
                data = binfile.read()
                imgs[fw] = {
                    'bytes': data,
                    'size': len(data),
                    'base': base_addr,
                }

    if not exists(OUT_DIR):
        Path(OUT_DIR).mkdir(parents=True, exist_ok=True)

    engs = list(sorted(engs))
    eng_cmap = dict(zip(engs, tableau10.values()))

    coverage = {}

    # construct coverage sets
    for fw_name in imgs.keys():
        coverage[fw_name] = {}
        for engine in engs:
            ranges = set()
            range_start = 0
            range_size = 0
            for naddr, nsize in sorted(graphs[fw_name][engine]['nodes']):
                if range_start + range_size < naddr:
                    # check if gap between current range and next block
                    if range_size > 0:
                        ranges.add((range_start, range_size))
                    # start consolidating new range
                    range_start = naddr
                    range_size = nsize
                else:
                    # this includes the case of overlapping blocks,
                    # which should never occur.
                    range_size = naddr + nsize - range_start

            coverage[fw_name][engine] = ranges

    if is_unit_tests:
        for eng in sorted([eng for eng in engs if eng != 'ffxe']):
            print(eng)
            plot_venn_diagrams_unit(graphs, coverage, other=eng, outdir=OUT_DIR)

    for fw_name in sorted(imgs.keys()):
        print(fw_name)
        if not is_unit_tests:
            plot_venn_diagrams(graphs, coverage, fw_name, engs, outdir=OUT_DIR)
        fig, ax = plot_coverage_comparison(coverage, imgs, fw_name, engs, eng_cmap)
        fig.savefig(f"{OUT_DIR}/{fw_name}-coverage-cmp.svg", transparent=True, format='svg')
        plt.close()



    