import angr
import sys

def load_project(path: str) -> angr.project.Project:
    try:
        p = angr.Project(path, load_options={'auto_load_libs': False, 'main_opts':{'backend':'blob', 'arch' : 'cortex-m'}})

    except AttributeError:
        sys.stderr.write(f'could not load {path} in angry: attribute error\n')
        exit(1)

    return p 

def generate_cfg_fast(p: angr.project.Project) -> angr.analyses.cfg.cfg_fast.CFGFast:
    main_addr = 0x248
    cfg_fast = p.analyses.CFGFast(function_starts=[main_addr], force_complete_scan=False)
    return cfg_fast

def generate_cfg_emulated(p: angr.project.Project) -> angr.analyses.cfg.cfg_fast.CFGFast:
    main_addr = 0x248
    # start_state = p.factory.blank_state(addr=main_addr)
    cfg_emulated = p.analyses.CFGEmulated(fail_fast=True, starts=[main_addr])
    # cfg_emulated = p.analyses.CFGEmulated(keep_state=True)
    return cfg_emulated

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Requires input elf binary path")
        exit(1)
    binary_path = sys.argv[1]
    pr = load_project(binary_path)
    generated_cfg_fast = generate_cfg_fast(pr)
    generated_cfg_emulated = generate_cfg_emulated(pr)
    print(f"blocks: {len(list(generated_cfg_fast.graph.nodes()))}\tedges: {len(list(generated_cfg_fast.graph.edges()))}")
    print(f"blocks: {len(list(generated_cfg_emulated.graph.nodes()))}\tedges: {len(list(generated_cfg_emulated.graph.edges()))}")


    print("Done!!")
