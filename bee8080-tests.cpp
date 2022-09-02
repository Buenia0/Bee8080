/*
    This file is part of the Bee8080 engine.
    Copyright (C) 2022 BueniaDev.

    Bee8080 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Bee8080 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Bee8080.  If not, see <https://www.gnu.org/licenses/>.
*/

// bee8080-tests.cpp - automated test suite for Bee8080 engine

#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <cstdint>
#include <bee8080.h>
using namespace bee8080;
using namespace std;

vector<uint8_t> memory;

// Intel 8080 machine code to inject at 0x0000 (simulates necessary CP/M BDOS calls)
vector<uint8_t> patch_code = {
    0x3E, 0x01, // mvi a, 1
    0xD3, 0x00, // out 0, a ; Value of 0x01 written to port 0 stops test execution
    0x00, // nop
    0xF5, // push psw
    0x79, // mov a, c
    0xD3, 0x01, // out 1, a ; Send command value to control port
    0xDB, 0x01, // in 1 ; Receive status byte from control port
    0x47, // mov b, a
    0xE6, 0x01, // ani 1 ; Return from function if bit 0 is clear
    0xCA, 0x28, 0x00, // jz end_func
    0x78, // mov a, b
    0xE6, 0x02, // ani 2 ; Check if bit 1 is set
    0xCC, 0x1D, 0x00, // cz c_write ; If bit 1 is clear, call c_write function
    0xC4, 0x21, 0x00, // cnz c_write_str ; Otherwise, call c_write_str function
    0xC3, 0x28, 0x00, // jmp end_func ; Return from function
          // c_write:
    0x7B, //       mov a, e
    0xD3, 0x02, // out 2, a ; Send character (in E register) to data port
    0xC9, //       ret ; Return from function
          // c_write_str:
    0x7A, //       mov a, d
    0xD3, 0x02, // out 2, a ; Send MSB of string's address to data port
    0x7B, //       mov a, e
    0xD3, 0x02, // out 2, a ; Send LSB of string's address to data port
    0xC9, //       ret ; Return from function
	  // end_func:
    0xF1, //       pop psw
    0xC9  //       ret
};

// Inject patch code (above) at 0x0000
void patchisr()
{
    for (size_t i = 0; i < patch_code.size(); i++)
    {
	memory[i] = patch_code[i];
    }
}

// Loads test file into memory
bool loadfile(string filename)
{
    ifstream file(filename.c_str(), ios::in | ios::binary | ios::ate);

    if (!file.is_open())
    {
	cout << "Error" << endl;
	return false;
    }

    memory.resize(0x10000, 0);
    streampos size = file.tellg();
    file.seekg(0, ios::beg);
    file.read((char*)&memory[0x100], size);
    file.close();
    patchisr();
    cout << "Success" << endl;
    return true;
}

class TestInterface : public Bee8080Interface
{
    public:
	TestInterface(bool& test_bool) : is_test_done(test_bool)
	{

	}

	~TestInterface()
	{

	}

	uint8_t readByte(uint16_t addr)
	{
	    return memory[addr];
	}

	void writeByte(uint16_t addr, uint8_t val)
	{
	    memory[addr] = val;
	}

	uint8_t portIn(uint8_t port)
	{
	    uint8_t temp = 0x00;

	    // Port 0x01 - Receive status byte from control port
	    // Bit 0 - Data readiness bit (0=Not ready, 1=Ready)
	    // Bit 1 - Single character bit (0=Print single character, 1=Print string)
	    if (port == 0x01)
	    {
		temp = ((!is_single_char << 1) | is_active);
	    }

	    return temp;
	}

	void portOut(uint8_t port, uint8_t val)
	{
	    // Port 0 - End of test port
	    if (port == 0x00)
	    {
		// Value of 0x01 written to this port halts the machine and ends the current test
		if (val == 0x01)
		{
		    is_test_done = true;
		}
	    }
	    // Port 1 - Control port
	    // Write 0x02 to this port to print a single character
	    // Write 0x09 to this port to print an entire string
	    else if (port == 0x01)
	    {
		switch (val)
		{
		    case 0x02:
		    {
		        is_active = true;
		        is_single_char = true;
		    }
		    break;
		    case 0x09:
		    {
		        is_active = true;
		        is_single_char = false;
		    }
		    break;
		    default: cout << "Invalid command of " << hex << (int)(val) << endl; break;
		}
	    }
	    // Port 2 - Data port
	    // If writing a single character, write character to be printed to this port
	    // If printing a single string, write the address in memory that the string is located (upper byte first)
	    else if (port == 0x02)
	    {
		// Error out if control port is not ready for data
		if (!is_active)
		{
		    cout << "Error: Please send a valid command to port 1." << endl;
		    return;
		}

		// If single character bit is set, print ASCII character written to this port
		if (is_single_char)
		{
		    cout.put(val);
		}
		// Otherwise, construct the specific address in memory that the string is located
		else
		{
		    // Upper byte first...
		    if (!is_msb_sent)
		    {
			str_address = (val << 8);
			is_msb_sent = true;
		    }
		    // Then lower byte
		    else
		    {
			str_address |= val;
		
			// Strings are terminated with '$' character
			for (uint16_t addr = str_address; readByte(addr) != '$'; addr++)
			{
			    cout.put(readByte(addr));
			}

			cout << flush;

			is_msb_sent = false;
		    }
		}
	    }
	}

    private:
	bool is_active = false;
	bool is_single_char = false;
	uint16_t str_address = 0;
	bool is_msb_sent = false;

	bool& is_test_done;
};

void run_test(Bee8080 &core, string filename, uint64_t cycles_expected)
{
    if (!loadfile(filename))
    {
	return;
    }

    bool is_test_done = false;
    TestInterface inter(is_test_done);
    core.setinterface(&inter);
    core.setBreakpointCallback([&](Bee8080Breakpoint &breakpoint, uint16_t value) -> void
    {
	switch (breakpoint.break_type)
	{
	    case Bee8080Breakpoint::Type::Opcode:
	    {
		cout << "PC [" << hex << int(breakpoint.address) << "] opcode" << endl;
	    }
	    break;
	    default:
	    {
		cout << "Unknown breakpoint" << endl;
	    }
	    break;
	}
    });

    // core.addbreakpoint(0);

    core.init(0x100);

    cout << "*** TEST: " << filename << endl;

    uint64_t cycles = 0;
    uint64_t num_instrs = 0;

    while (!is_test_done)
    {
	num_instrs += 1;
	// WARNING: Uncommenting the following line will output multiple GB of data
	// core.debugoutput();
	cycles += core.runinstruction();
    }

    int64_t diff = (cycles_expected - cycles);
    cout << endl;
    // Print number of instructions executed and difference between cycles executed and expected cycles
    cout << "*** " << dec << (uint64_t)(num_instrs) << " instructions executed on " << dec << (uint64_t)(cycles) << " cycles";
    cout << " (expected=" << dec << (uint64_t)(cycles_expected) << ", diff=" << dec << (int64_t)(diff) << ")" << endl;
    cout << endl;
    core.shutdown();
    fflush(stdout); // TODO: Is this line necessary for cout to work properly?
    memory.clear();
}

int main(int argc, char *argv[])
{
    Bee8080 core;
    run_test(core, "tests/TEST.COM", 302LU); // Barebones demo program to test system functionality
    run_test(core, "tests/TST8080.COM", 5230LU); // Microcosm 8080/8085 CPU Diagnostic v1.0
    run_test(core, "tests/CPUTEST.COM", 255689268LU); // Supersoft CPU Test
    run_test(core, "tests/8080PRE.COM", 7972LU); // Intel 8080 Exerciser (preliminary tests)
    run_test(core, "tests/8080EXM.COM", 23835703061LU); // Intel 8080 Exercsier (actual tests)
    run_test(core, "tests/8080EX1.COM", 23835598629LU); // Intel 8080 Exercsier (actual tests, KR580VM80A (Soviet 8080 clone) version)
    return 0;
}