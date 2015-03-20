pedal
=====

PEDAL - Python Exploit Development Assistance for GDB Lite

## Lite?:

* Working in progress for improving peda
  * Remove unused features
  * Fix minor bugs
* Features plan
  * Support syscall arguments trace
  * Limitation for `examine_mem_reference`
  * History for registers (go back to the past)
  * ncurses?

PEDAL has forked from https://github.com/zachriggle/peda

## New Features:

* phexdump
* socat

## Screenshot
![start](http://i.imgur.com/f22ZRro.png)

## Enhancements:

 This version has been extended by Zach Riggle to add some features and give dual-compatibility with Python2 and Python3.

* Python2 and Python3 compatibility
* Line width wrapping on banners
* Colorize stack and heap differently than regular data
* Show registers alongside stack output (and 'telescope' command)
* Basic support for ARM and PPC registers
* Support for passing GDB variables to PEDA routines (e.g. `hexdump $pc`)

## Key Features:

These are the standard features of PEDA:

* Enhance the display of gdb: colorize and display disassembly codes, registers, memory information during debugging.
* Add commands to support debugging and exploit development (for a full list of commands use `peda help`):
  * `aslr` -- Show/set ASLR setting of GDB
  * `checksec` -- Check for various security options of binary
  * `dumpargs` -- Display arguments passed to a function when stopped at a call instruction
  * `dumprop` -- Dump all ROP gadgets in specific memory range
  * `elfheader` -- Get headers information from debugged ELF file
  * `elfsymbol` -- Get non-debugging symbol information from an ELF file
  * `lookup` -- Search for all addresses/references to addresses which belong to a memory range
  * `patch` -- Patch memory start at an address with string/hexstring/int
  * `procinfo` -- Display various info from /proc/pid/
  * `pshow` -- Show various PEDA options and other settings
  * `pset` -- Set various PEDA options and other settings
  * `readelf` -- Get headers information from an ELF file
  * `ropgadget` -- Get common ROP gadgets of binary or library
  * `ropsearch` -- Search for ROP gadgets in memory
  * `searchmem|find` -- Search for a pattern in memory; support regex search
  * `vmmap` -- Get virtual mapping address ranges of section(s) in debugged process
  * `xormem` -- XOR a memory region with a key

## Installation

    git clone https://github.com/akiym/pedal.git ~/pedal
    echo "source ~/pedal/peda.py" >> ~/.gdbinit
    echo "DONE! debug your program with gdb and enjoy"
