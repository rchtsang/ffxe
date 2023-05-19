import os
import sys
import subprocess
import typing
import shutil
import threading
import shlex
from typing import Union
from os.path import (
    realpath, dirname, splitext, split, exists)
from pathlib import Path
from glob import glob
from tempfile import TemporaryDirectory

"""
a script to run ghidra analyzeHeadless
expects ghidraRun to be on path
also expects Ghidrathon to be installed
"""
# for analyzeHeadless options, see
# https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html

PARENT_DIR = dirname(realpath(__file__))
PROJ_DIR = realpath(f"{PARENT_DIR}/..")
GHIDRA_ROOT = dirname(realpath(shutil.which('ghidraRun')))

def analyzeHeadless(target : str, processor : str, 
        postscript : str = None,
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
    assert prescript or postscript, \
        "missing prescript or postscript"
    assert exists(target), \
        "target does not exist"

    if prescript:
        assert exists(prescript), \
            "postscript does not exist: {}".format(pretscript)
        (prescriptdir, prescriptname) = split(prescript)

    if postscript:
        assert exists(postscript), \
            "prescript does not exist: {}".format(postscript)
        (postscriptdir, postscriptname) = split(postscript)


    # create project directory
    Path(project_loc).mkdir(parents=True, exist_ok=True)

    # constructing cli command
    analyze_cmd = [
        f"{GHIDRA_ROOT}/support/analyzeHeadless",
        realpath(project_loc),
        project_name,
        '-import', target,
    ]

    scriptpaths = []

    if prescript:
        analyze_cmd.extend(['-preScript', prescriptname])
        if preargs:
            analyze_cmd.extend(preargs)
        scriptpaths.append(prescriptdir)

    if postscript:
        analyze_cmd.extend(['-postScript', postscriptname])
        if postargs:
            analyze_cmd.extend(postargs)
        scriptpaths.append(postscriptdir)

    analyze_cmd.extend(['-scriptPath', f"\"{';'.join(scriptpaths)}\""])
    analyze_cmd.extend(['-processor', processor])
    analyze_cmd.extend(['-loader', loader])

    print(shlex.join(analyze_cmd))

    # run analyze command
    result = subprocess.run(analyze_cmd)

    # clean up directories
    if rm_project:
        # input("press enter to delete tmp-ghidra...")
        shutil.rmtree(project_loc)

    return result


def task(targets, pdfilepath, base):
    # copy all files to be analyzed into a new temporary directory
    with TemporaryDirectory() as td:
        for target in targets:
            shutil.copy(target, td)

        analyzeHeadless(
            target=td,
            processor="ARM:LE:32:Cortex",
            prescript=f"{PARENT_DIR}/ghidra-disassemble-entrypoints.py",
            preargs=[pdfilepath, base],
            postscript=f"{PARENT_DIR}/ghidra-simple-cfg.py",
            postargs=[pdfilepath, base],
            rm_project=True)

if __name__ == "__main__":
    # default behavior when run is to run all unit tests

    # set up io stream-based logging
    import io

    targets = glob(f"{PROJ_DIR}/examples/unit-tests/*.bin")
    pdfilepath = realpath(f"{PARENT_DIR}/../mmaps/nrf52832.yml")

    # open("/tmp/ghidra-analyze.log", 'w').close()

    # log_stream = io.open("/tmp/ghidra-analyze.log")

    # thread = threading.Thread(target=task, args=[targets, pdfilepath])
    # thread.start()
    # while (thread.is_alive()):
    #     line = log_stream.readline()
    #     if line:
    #         print(line)

    # log_stream.close()
    # os.remove("/tmp/ghidra-analyze.log")

    task(targets, pdfilepath, -1)