import os
import argparse
import json
import re
from glob import glob
from pathlib import Path

import dill
import yaml

import models
from utils import *

FW_NAME_PTRN = re.compile(r"(?P<fwname>[\w-]+)-(?P<engine>\w+)-cfg\.pkl")

PARENT_DIR = os.path.dirname(os.path.realpath(__file__))

def load_cfg(path : str):
    assert os.path.exists(path)
    with open(path, 'rb') as pf:
        return dill.load(pf)

def load_pd(path : str):
    assert os.path.exists(path)
    with open(path, 'rb') as pd_file:
        return yaml.load(pd_file, yaml.Loader)

parser = argparse.ArgumentParser(prog="visualize-cfg.py",
    description="generate a text-based visualization of a cfg")
parser.add_argument('--path', type=str, default=f"{PARENT_DIR}/../tests/cfgs/unit-tests",
    help="path to pickled cfg or directory containing pickled cfgs")
parser.add_argument('--pd', type=str, default=f"{PARENT_DIR}/../mmaps/nrf52832.yml",
    help="path to platform description yaml file")
parser.add_argument('--fw', type=str, default=f"{PARENT_DIR}/../examples/unit-tests",
    help="path to corresponding firmware image of directory containing image")
parser.add_argument('--batch', type=str, default=None,
    help="path to batch job json file")
parser.add_argument('--out', type=str, default=f"{PARENT_DIR}/cfgs/unit-tests",
    help="path to output directory")

if __name__ == "__main__":
    args = parser.parse_args()

    batch = {}
    if args.batch:
        assert os.path.exists(args.batch), "json file doesn't exist: {}".format(args.batch)

        with open(args.batch, 'r') as jf:
            batch = json.load(jf)

    elif (os.path.isdir(args.path) and os.path.isdir(args.fw)):
        for path in sorted(glob(f"{args.path}/*.pkl")):
            name_ptrn_match = FW_NAME_PTRN.search(os.path.basename(path))
            assert name_ptrn_match, "file name not formatted: {}".format(path)
            fw_name = name_ptrn_match.group('fwname')

            # find firmware image path
            if os.path.exists(elf_fw_path := f"{args.fw}/{fw_name}.elf"):
                fw_path = elf_fw_path
            elif os.path.exists(bin_fw_path := f"{args.fw}/{fw_name}.bin"):
                fw_path = bin_fw_path
            else:
                # raise AssertionError("fw path not found: {}".format(path))
                continue

            batch[path] = {
                'pd': args.pd,
                'fw': fw_path,
            }
    else:
        assert not (os.path.isdir(args.path) or os.path.isdir(args.fw)), \
            "path and fw must be both dir or both files"

        batch[args.path] = {
            'pd': args.pd,
            'fw': args.fw
        }

    for cfg_path, params in batch.items():
        pd_path = params['pd']
        fw_path = params['fw']
        fw_filename = os.path.basename(cfg_path)
        (name, ext) = os.path.splitext(fw_filename)
        print(f"drawing {name}...")

        name_ptrn_match = FW_NAME_PTRN.search(fw_filename)

        try:
            assert os.path.exists(cfg_path), \
                "cfg file doesn't exist: {}".format(cfg_path)
            assert os.path.exists(pd_path), \
                "pd file doesn't exist:  {}".format(pd_path)

            assert os.path.splitext(cfg_path)[-1] in ['.pkl', '.pickle'], \
                "cfg file not a pickle: {}".format(cfg_path)
            assert name_ptrn_match, (
                "cfg file name not formatted: {}\n"
                "expected <fwname>-<engine>-cfg.pkl"
            ).format(cfg_path)
        except AssertionError as e:
            print(e)
            continue

        pd = load_pd(pd_path)
        cfg = load_cfg(cfg_path)
        vtbases = [0]
        if 'vtbases' in params:
            vtbases = params['vtbases']

        fw_name = name_ptrn_match.group('fwname')
        fw = models.FirmwareImage(
            fw_path,
            base_addr=pd['mmap']['flash']['address'],
            pd=pd,
            vtbases=vtbases,
        )

        annotated_disasm = fw.annotated_disasm(cfg)
        Path(args.out).mkdir(parents=True, exist_ok=True)
        with open(f"{args.out}/{name}.txt", 'w') as f:
            f.write("{:d} blocks {:d} edges\n".format(len(cfg['nodes']), len(cfg['edges'])))
            f.write('\n'.join(annotated_disasm))

