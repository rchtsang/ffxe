# FFXE

## Dynamic Control Flow Graph Recovery for Embedded Firmware Binaries

This repository contains the artifacts for the paper **FFXE: Dynamic Control Flow Graph Recovery for Embedded Firmware Binaries**, which presents a novel technique for resolving indirect branches dependent on asynchronous writes (callback functions) that is based on dynamic forced execution.

Our implementation of the Forced Firmware Execution Engine can be found in the file `ffxe.py`, and a reimplementation of the original Forced Execution Engine by Xu et al. can be found in `fxe.py`. 

## Setup

### Native

The dependencies can be installed in a conda environment using the provided `environment.yml` file.

_After activating the environment, the engine must be installed via pip in developer mode with `pip install -e .` from the project root directory_.

Note that the Ghidra and `angr` scripts will not run correctly as they require additional installation steps. The Ghidra scripts depend on Ghidrathon and `angr` needs to be installed in a separate conda environment, as it uses an incompatible version of Unicorn.

Other conda environments can be installed from the corresponding `docker/envs/<env>.yml` file. See below for usage details.

### Docker

Alternatively, we provide a complete Docker environment capable of running all relevant scripts. The Docker image can be built with the provided Makefile on Mac and Linux by running `make build`, then logged in with `make ssh`, both from this directory.

The correct conda environment must be activated for each script:
	- `angr`	environment for angr-related scripts
	- `ghidra`	environment for ghidra-related scripts
	- `ffxe`	environment for ffxe install and ffxe-related scripts
	- `plot`	environment for plotting and visualization scripts

**NOTE: You must still manually install ffxe on the `ffxe` environment with `pip install -e .`**

_Note: `visualize-cfg.py` requires `ffxe` environment, not `plot` environment_

## Duplicating FFXE Experiments

FFXE can be invoked on all samples in our unit test set by invoking the following commands from the project directory:

```console
$ [ $(basename $CONDA_PREFIX) = "ffxe" ] || conda activate ffxe # conda env must be active
$ [ pip show ffxe &> /dev/null ] || pip install -e . # ffxe must be installed in conda env via pip
$ python tests/test-unit.py
$ # conda deactivate
```
This will generate basic CFGs in python pickled format for all firmware images with a `.bin` extension in the `examples/unit-tests` folder.

The results can be visualized using another script `visual_cfg.py`, which is meant for correctness checking and therefore maps the generated cfgs onto the unstripped elf firmware binary.

```console
# conda activate ffxe
$ python scripts/visual_cfg.py
$ # conda deactivate
```
This will write rough CFGs in the form of annotated disassembly to the folder `scripts/cfgs`. 

### Testing Real World Samples

FFXE can be invoked on our real-world test set by invoking the command

```console
# conda activate ffxe
$ python tests/test-real.py
$ # conda deactivate
```
This will generate basic CFGs in python pickled format for each real-world sample directory in the `examples/real-world` folder.

The resulting CFG cannot be visualized directly using the `visual_cfg.py` script due to lack of ELF files for baseline disassembly accuracy; however, we have included scripts that allow for high-level visualization of coverage and coverage comparison in the `scripts` directory.

### Testing Other Recovery Methods

Our version of FXE can be invoked with the command
```console
# conda activate ffxe
$ python tests/fxe-all.py
$ # conda deactivate
```
This has the same behavior as `test-unit.py` except that it invokes FXE instead.

_Scripts for other recovery methods can be found in the `scripts` directory_.

Running the other recovery methods is somewhat more involved as additional dependencies must be installed for our provided scripts to work. Moreover, other dependencies must be installed in different environments to avoid package conflicts. (There is a known conflict between the version of Unicorn we use, and the version that angr uses)

The script `scripts/angr-analyze.py` will run angr's static and emulated recovery methods on all `.bin` images in the `examples/unit-tests` folder, but must be run from an environment that has angr installed.

The scripts `scripts/ghidra-analyze.py` requires a working installation of [Ghidrathon](https://github.com/mandiant/Ghidrathon) to work. Please visit their GitHub for install instructions.

Scripts `scripts/angr-analyze-real.py` and `scripts/ghidra-analyze-real.py` can be used for analyzing the real-world set but have the same requirements as already stipulated.

If you are in the docker container, you should be able to invoke these analysis scripts with the following commands:

```sh
conda activate ghidra
# 1. Run ghidra basic tests in docker
python scripts/ghidra-analyze.py
# 2. Run ghidra real-world tests in docker
python scripts/ghidra-analyze-real.py
conda deactivate

conda activate angr
# 3. Run angr basic tests in docker
python scripts/angr-analyze.py
# 4. Run angr real-world tests in docker
python scripts/angr-analyze-real.py
conda deactivate
```

## Other Scripts

Other scripts are used to tabulate results and generate images for our paper. The `tabulate-` scripts can be invoked in the same environment as FFXE. However, the `visualize-` scripts require matplotlib, which is not installed in the FFXE environment by default.
