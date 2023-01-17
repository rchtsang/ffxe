import os
from glob import glob

import dill

import models
from utils import *

PARENT_DIR = os.path.dirname(os.path.realpath(__file__))

def load_cfg(path : str):
    assert os.path.exists(path)
    with open(path, 'rb') as pf:
        return dill.load(pf)

def print_cfg(path : str, engine : str = 'ffxe'):
    assert os.path.exists(path)

    fw = models.FirmwareImage(path)

    (name, ext) = os.path.splitext(os.path.basename(path))

    cfg_path = f"{PARENT_DIR}/../tests/cfgs/{name}-{engine}-cfg.pkl"

    cfg = load_cfg(cfg_path)

    return fw.print_cfg(cfg)

if __name__ == "__main__":
    cfg_paths = glob(f"{PARENT_DIR}/../tests/cfgs/*.pkl")
    cfgs = {
        os.path.basename(path) : load_cfg(path) for path in cfg_paths
    }
    for path in cfg_paths:
        cfg = load_cfg(path)
        (name, ext) = os.path.splitext(os.path.basename(path))
        print(f"drawing {name}")
        fw_name = '-'.join(name.split('-')[:2])
        fw = models.FirmwareImage(f"{PARENT_DIR}/../examples/{fw_name}.elf")
        annotated_disasm = fw.annotated_disasm(cfg)
        with open(f"{PARENT_DIR}/cfgs/{name}.txt", 'w') as f:
            f.write("{:d} blocks {:d} edges\n".format(len(cfg['nodes']), len(cfg['edges'])))
            f.write('\n'.join(annotated_disasm))

    # from IPython import embed
    # embed()