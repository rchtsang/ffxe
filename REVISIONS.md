# Revisions

First, we refactored both the ffxe engine and model classes to support multiple vector tables (which were added to support FitBit firmware images, which have 2), refactored the platform description format to support more detailed information that can generalize better across platforms.

refactor to use slots and named tuples as space-saving optimizations, as well as the firmware disassembly function 

refactor to support restore-on-write to peripheral interrupt enable registers (updates to platform description file and ffxe engine)
	^ expand on this?

added conditions on branch queueing to ameliorate potential infinite loops
	^ expand on this?

adding real world samples (focus first on fitbit)

update test scripts to generalize to different real-world samples

make ghidra analysis fair: pre-script to reset base address, disassemble all vector table entries, and extract the cfg. also compare raw ghidra cfg to reachable cfg. 
	^ expand on this


---

TI over the air download firmware is compressed based on a boundary file and reverse engineering a loader would be quite time consuming. 

nordic over-the-air is also compressed apparently, and base address needs to be determined. can use firmxrays for this, or needs to be manually determind. 

firmxrays can be used, at least for the nordic images. the ti images still suffer from unpacking issues, since the format doesn't seem to be well documented enough to unpack...




