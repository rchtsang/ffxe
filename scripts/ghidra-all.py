import os
import sys
import subprocess
import typing
import shutil
from typing import Union
from os.path import (
    realpath, dirname, splitext, split, exists)
from pathlib import Path
from glob import glob

"""
a script to run ghidra analyzeHeadless
expects ghidraRun to be on path
"""

PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")
GHIDRA_ROOT = dirname(realpath(shutil.which('ghidraRun')))

def analyzeHeadless(target : str, processor : str, postscript : str,
        postargs : list = [],
        prescript : str = None,
        preargs : list = [],
        project_loc : str = f"{PARENT_DIR}/tmp-ghidra",
        project_name : str = "tmp",
        loader : str = "BinaryLoader",
        rm_project : bool = True):
    """
    a helper function to invoke ghidra's analyzeHeadless
    targets         a single target executable path or path to directory of targets
    postscript      script path to execute on targets after ghidra's analysis
    postargs        list of arguments to postscript
    prescript       script path to execute on targets before ghidra's analysis
    preargs         list of arguments to prescript
    project_loc     path to ghidra project directory (created if not exists)
    project_name    ghidra project name (created if not exists)
    """
    assert exists(f"{GHIDRA_ROOT}/support/analyzeHeadless"), \
        "analyzeHeadless not found!"
    assert exists(target), \
        "target does not exist"
    assert exists(postscript), \
        "postscript does not exist: {}".format(postscript)

    # create project directory
    Path(project_loc).mkdir(parents=True, exist_ok=True)

    (scriptdir, scriptname) = split(postscript)

    # run analyze command
    analyze_cmd = [
        f"{GHIDRA_ROOT}/support/analyzeHeadless",
        realpath(project_loc),
        project_name,
        '-import', target,
        '-postScript', scriptname,
        '-scriptPath', realpath(scriptdir),
        '-processor', processor,
        '-loader', loader,
    ]
    result = subprocess.run(analyze_cmd)

    # clean up directories
    if rm_project:
        shutil.rmtree(project_loc)

    return result

if __name__ == "__main__":

    from tempfile import TemporaryDirectory
    
    # copy all files to be analyzed into a new temporary directory
    targets = glob(f"{PROJ_DIR}/examples/*.bin")
    with TemporaryDirectory() as td:
        for target in targets:
            shutil.copy(target, td)

        analyzeHeadless(
            target=td,
            processor="ARM:LE:32:Cortex",
            postscript=f"{PARENT_DIR}/simple-ghidra-cfg.py")
