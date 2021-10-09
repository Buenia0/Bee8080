# Bee8080
Intel 8080 emulation engine, kinda

A complete emulation of the Intel 8080 processor written in C++11.


# Features

Extremely accurate - passes all the test ROMs at my disposal

Platform-independent and architecture-independent code

Compact - consists of only a single header and source file

Extremely tiny - only 57 KB for the core library's source files

Easily customizable interface

Dynamic disassembly (from any memory address) and simple debug output

And more to come!

# Building Instructions

The Bee8080 library (and the testing framework, if desired) does not have any dependencies and can be compiled with MinGW on Windows, and (presumably) both GCC and Clang on Linux, as well as (presumably) AppleClang on OSX.

In order to build the testing framework, simply pass `-DBUILD_8080_TESTS="ON"` to CMake.

## Linux:

Step 1: Install dependencies:

Core dependencies:

Compiler: GCC or Clang. You only need one of those two:

GCC 10.2.0+ (earlier versions not tested):

Debian (not tested): `sudo apt-get install build-essential`
Arch (not tested): `sudo pacman -S base-devel`
Fedora (not tested): `sudo dnf install gcc-c++`
OpenSUSE (not tested): `sudo zypper in gcc-c++`

Clang (not tested):

Debian: `sudo apt-get install clang clang-format libc++-dev` (in some distros, clang-5.0)
Arch: `pacman -S clang`, `libc++` is in the AUR. Use pacaur or yaourt to install it.
Fedora: `dnf install clang libcxx-devel`
OpenSUSE: `zypper in clang`

Other core dependencies:

Git (if not installed already) and CMake 3.1+:

Debian (not tested): `sudo apt-get install git cmake`
Arch (not tested): `sudo pacman -S git`
Fedora (not tested): `sudo dnf install git cmake`
OpenSUSE (not tested): `sudo zypper in git cmake extra-cmake-modules`

Step 2: Clone the repository:

`git clone --recursive https://github.com/BueniaDev/Bee8080.git`

`cd Bee8080`

Step 3: Compile:

`mkdir build && cd build`

`cmake .. -G "Unix Makefiles" -DBUILD_8080_TESTS="<ON/OFF>" -DCMAKE_BUILD_TYPE="<Debug/Release>"`

`make -j$(nproc --all)`


## Mac OS (not tested):

You will need [homebrew](https://brew.sh), a recent version of Xcode and the Xcode command-line tools to build Bee8080.
Please note that due to personal financial constraints, Bee8080 has not been tested on Mac OS as of yet.

Step 1: Install dependencies:

`brew install git cmake pkg-config`

Step 2: Clone the repository:

`git clone --recursive https://github.com/BueniaDev/Bee8080.git`

`cd Bee8080`

Step 3: Compile:

`mkdir build && cd build`

`cmake .. -G "Unix Makefiles" -DBUILD_8080_TESTS="<ON/OFF>" -DCMAKE_BUILD_TYPE="<Debug/Release>"`

`make -j$(sysctl -n hw.ncpu)`

## Windows:

You will need [MSYS2](https://msys2.github.io) in order to install Bee8080.
Make sure to run `pacman -Syu` as needed.

Step 1: Install dependencies:

`pacman -S base-devel mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake git`

Step 2: Clone the repository:

`git clone --recursive https://github.com/BueniaDev/Bee8080.git`

`cd Bee8080`

Step 3: Compile:

`mkdir build && cd build`

`cmake .. -G "MSYS Makefiles" -DBUILD_8080_TESTS="<ON/OFF>" -DCMAKE_BUILD_TYPE="<Debug/Release>"`

`(mingw32-)make -j$(nproc --all)`

If you chose to build the (optional) testing framework:

`../msys-dist.sh`

# Minimal usage

Step 1. Include the header file:

```
#include "bee8080.h"
using namespace bee8080;
```

Step 2: Implement the interface:

```
class Interface : public Bee8080Interface
{
    public:
	uint8_t ram[0x10000]; // 64KB memory (minimum)
	uint8_t io[0x100]; // 256 bytes of I/O ports

	Interface()
	{
	    memset(&ram, 0, sizeof(RAM));
	    memset(&io, 0, sizeof(IO));
	}

	// Memory read request per 1 byte from CPU
	uint8_t readByte(uint16_t addr)
	{
	    return ram[addr];
	}

	// Memory write request per 1 byte from CPU
	void writeByte(uint16_t addr, uint8_t val)
	{
	    ram[addr] = value;
	}

	// IN operand request from CPU
	uint8_t portIn(uint8_t port)
	{
	    return io[port];
	}

	// OUT operand request from CPU
	void portOut(uint8_t port, uint8_t val)
	{
	    io[port] = val;
	}
};
```

Step 3: Create an instance of the emulated Intel 8080:

```
Interface interface;

// Create instance of Intel 8080
Bee8080 core;

// Set hardware abstraction interface
core.setinterface(&interface);
```

Step 4: Initialize the processor:

```
core.init(); // Initializes the program counter to 0...

// but you can set the program counter to an abritary 16-bit value too
// core.init(0x100);
```

Step 5: Begin executing instructions:

```
// Run one Intel 8080 instruction
int instr_cycles = core.runinstruction();
```

# Optional features

If you want to generate an interrupt:

```
// This function accepts a valid Intel 8080 opcode as its sole argument
core.setinterrupt(0xC7); // 0xC7 = RST 0
```

If you want to reset the CPU:

```
core.reset(); // Resets the CPU with the program counter set to 0...

// but you can set the program counter to an abritary 16-bit value too
// core.reset(0x100);
```

If you want to disassemble an instruction at a specific address:

```
// "addr" is the address of the instruction you want to disassemble
// The resulting string can be printed to the console,
// or even utilized in some sort of graphical debugger
string instr_disassembly = core.disassembleinstr(addr);
```

If you want to output a more complete debug log of the emulated CPU state to the console:

```
// Call this function before executing an instruction
core.debugoutput();
// Run a single instruction
core.runinstruction();
```

# Plans

## Near-term

Expand debugging support

## Medium-term

Intel 8085 support

## Long-term

Graphical debugger (possibly via Qt5?)

# License

<img src="https://www.gnu.org/graphics/gplv3-127x51.png" alt="drawing" width="150"/>

Bee8080 is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# Copyright

(C) 2021 BueniaDev. This project is not affiliated in any way with Intel or its associates. Intel 8080 is a registered trademark of Intel Corporation.

For information regarding Bee8080's stance on copyright infringement, as well as proof of Bee8080's legality, see the LEGAL.md file in this repository.