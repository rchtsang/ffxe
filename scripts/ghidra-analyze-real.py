import os
import argparse
from os.path import (
    basename, splitext, exists, realpath, 
    dirname, relpath, isdir
)
from importlib import import_module
from copy import deepcopy
from glob import glob
from time import perf_counter
from datetime import datetime

import yaml
import dill

# import ghidra-analyze (b/c hyphenated name)
ghidra_analyze = import_module('ghidra-analyze')
# import analyzeHeadless
analyzeHeadless = ghidra_analyze.analyzeHeadless

"""
script to run ghidra on real-world samples
"""

make_timestamp = lambda: datetime.now().strftime('%y%m%d-%H%M%S')

PARENT_DIR = dirname(realpath(__file__))
PROJ_ROOT = dirname(PARENT_DIR)
SAMPLES_DIR = f"{PROJ_ROOT}/examples/real-world"


parser = argparse.ArgumentParser(prog="test-real.py", description=__doc__)
parser.add_argument('--targets', nargs='+', type=str, default=None,
    help="specify folders of target real-world firmware to analyze")
parser.add_argument('--outdir', type=str, default=f"{PARENT_DIR}",
    help="destination directory for results table")

if __name__ == "__main__":
    args = parser.parse_args()

    if not args.targets:
        args.targets = glob(f"{SAMPLES_DIR}/*/")
    else:
        args.targets = [realpath(path) for path in args.targets]

    generated_cfgs = {}
    result_table = []

    for target in args.targets:
        print(f"analyzing target: {target}")
        try:
            assert isdir(target), \
                "target is not a directory: {}".format(target)
            
            assert len(binfiles := glob(f"{target}/*.bin")) == 1, \
                "there must be exactly one firmware image binary in {}".format(target)
            assert len(ymlfiles := glob(f"{target}/*.yml")) == 1, \
                "there must be exactly one platform description yaml in {}".format(target)

            assert exists(ghidra_config_path := f"{target}/ghidra.config"), \
                "real-world firmware analysis requires ghidra.config yaml file!"

            fw_path = binfiles[0]
            pd_path = ymlfiles[0]
            fw_name = splitext(basename(fw_path))[0]
            base_addr = -1
            vtbases = [0]

            # check if target has specified base address
            if exists(base_addr_path := f"{target}/base_addr.txt"):
                with open(base_addr_path, 'r') as file:
                    base_addr = int(file.read().strip(), 0)
                print("specified base address: {}".format(hex(base_addr)))

            # check if target has specified vector table offsets
            # should be a file named `vtbases` containing a comma-separated
            # list of offsets in hexadecimal (preferably with leading `0x`)
            if exists(vt_bases_path := f"{target}/vtbases.txt"):
                with open(vt_bases_path, 'r') as file:
                    vtbases = file.read().split(',')
            print("vector table offsets: {}".format(
                ' '.join(vtbases)))


        except AssertionError as e:
            print(e)
            continue

        # load ghidra_config
        with open(ghidra_config_path, 'r') as ymlfile:
            ghidra_config = yaml.load(ymlfile, yaml.Loader)

        analyzeHeadless(
            target=fw_path,
            processor=ghidra_config['processor'],
            prescript=f"{PARENT_DIR}/ghidra-disassemble-entrypoints.py",
            preargs=[pd_path, base_addr] + vtbases,
            postscript=f"{PARENT_DIR}/ghidra-simple-cfg.py",
            postargs=[pd_path, base_addr] + vtbases,
            rm_project=True
        )