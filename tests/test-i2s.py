import os
from copy import deepcopy

from ffxe import *

ffxe = FFXEngine(
    pd="mmaps/nrf52832.yml",
    path="examples/i2s-o0.elf",
    log_stdout=True,
    log_insn=True,
    log_time=True
)

# 2d19 is spi handler, need to get this one.
# 18d8 is spim_evt_handler, which invokes the registered handler
bpts = [
]

# from IPython import embed ; embed()

for addr in bpts:
    ffxe.add_breakpoint(addr)

ffxe.run()


disasm_txt = deepcopy(ffxe.fw.disasm_txt)
for block in ffxe.cfg.bblocks.values():
    insn_addr = block.addr
    for insn in ffxe.cs.disasm(
            ffxe.uc.mem_read(block.addr, block.size), block.size):
        try:
            lineno = ffxe.fw.disasm[insn_addr]['line']
            insn_addr += insn.size
            disasm_txt[lineno] = "{}{}{}{:<90}\u001b[0m".format(
                "\u001b[103m",  # bright yellow background
                "\u001b[30m",   # black foreground
                "\u001b[1m",    # bold font
                disasm_txt[lineno])
        except Exception:
            pass
print('\n'.join(disasm_txt))
print('\n')

total_insns = 0
total_size = 0
for block in ffxe.cfg.bblocks.values():
    total_size += block.size
    for insn in ffxe.cs.disasm(
            ffxe.uc.mem_read(block.addr, block.size), block.size):
        total_insns += 1
print(f"Found {len(ffxe.cfg.bblocks)} blocks, "
      f"{len(ffxe.cfg.edges)} edges, "
      f"{total_insns} insns, "
      f"{hex(total_size)} bytes, "
      "\n")