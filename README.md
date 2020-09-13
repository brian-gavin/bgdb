# BGDB
### (Brian Gavin DeBugger)

## What is this?

This is a toy debugger I'm writing for fun.

This was started from reading Eli Bendersky's [How Debuggers Work](https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1/) series, from which the first test program was taken.

## Goals

Non-exhaustive list of some goals of this project, to have some sort of direction:
* Support features that I think would be fun to implement and possibly useful
  * DWARF stuff like line breaks and function breaks, expression execution, a nice command line UX, with some helpful suggestions when errors occur.
* Write some bare metal x86 programs to use as test programs
* Support both 64 and 32 bit x86
