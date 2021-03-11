#include "bee8080.h"
using namespace bee8080;
using namespace std;

// Constructor/deconstructor definitions for Bee8080Interface
Bee8080Interface::Bee8080Interface()
{

}

Bee8080Interface::~Bee8080Interface()
{

}

// Function declarations for Bee8080Register
Bee8080Register::Bee8080Register()
{

}

Bee8080Register::~Bee8080Register()
{

}

// Functions for the 16-bit "register pair"
// The high register makes up the upper 8 bits of the register pair,
// while the low register makes up the lower 8 bits

uint16_t Bee8080Register::getreg()
{
    return ((hi << 8) | lo);
}

void Bee8080Register::setreg(uint16_t val)
{
    hi = (val >> 8);
    lo = (val & 0xFF);
}

// Functions for the 8-bit registers themselves

// High register
uint8_t Bee8080Register::gethi()
{
    return hi;
}

void Bee8080Register::sethi(uint8_t val)
{
    hi = val;
}

// Low register
uint8_t Bee8080Register::getlo()
{
    return lo;
}

void Bee8080Register::setlo(uint8_t val)
{
    lo = val;
}

// Class definitions for the Bee8080 class
Bee8080::Bee8080()
{

}

Bee8080::~Bee8080()
{

}

void Bee8080::init(uint16_t init_pc)
{
   // Initialize the registers (AF, BC, DE, HL) and the stack pointer to 0
   af.setreg(0x0000);
   bc.setreg(0x0000);
   de.setreg(0x0000);
   hl.setreg(0x0000);
   sp = 0x0000;

   // Initialize the PC to the value of init_pc
   pc = init_pc;

   // Notify the user that the emulated 8080 has been initialized
   cout << "Bee8080::Initialized" << endl;
}

void Bee8080::shutdown()
{
    // Set the interface class pointer to NULL if it hasn't been already
    if (inter != NULL)
    {
	inter = NULL;
    }

    // Notify the user that the emulated 8080 has been shut down
    cout << "Bee8080::Shutting down..." << endl;
}

void Bee8080::setinterface(Bee8080Interface *cb)
{
    // Sanity check to prevent a possible buffer overflow
    // from a erroneous null pointer
    if (cb == NULL)
    {
	cout << "Error: new interface is NULL" << endl;
	return;
    }

    inter = cb;
}

// Executes a single instruction and returns its cycle count
int Bee8080::runinstruction()
{
    return executenextopcode(getimmByte());
}

uint8_t Bee8080::readByte(uint16_t addr)
{
    // Check if interface is valid (i.e. not a null pointer)
    // before accessing it (this helps prevent a buffer overflow caused
    // by an erroneous null pointer)

    if (inter != NULL)
    {
	return inter->readByte(addr);
    }
    else
    {
	// Return 0 if interface is invalid
	return 0x00;
    }
}

void Bee8080::writeByte(uint16_t addr, uint8_t val)
{
    // Check if interface is valid (i.e. not a null pointer)
    // before accessing it (this helps prevent a buffer overflow caused
    // by an erroneous null pointer)

    if (inter != NULL)
    {
	inter->writeByte(addr, val);
    }
}

uint16_t Bee8080::readWord(uint16_t addr)
{
    // Check if interface is valid (i.e. not a null pointer)
    // before accessing it (this helps prevent a buffer overflow caused
    // by an erroneous null pointer)

    if (inter != NULL)
    {
	// The Intel 8080 is a little-endian system,
	// so the 16-bit value is constructed as follows:
	// val_16 = (mem[addr + 1] << 8) | mem[addr])
	uint8_t lo_byte = inter->readByte(addr);
	uint8_t hi_byte = inter->readByte((addr + 1));
	return ((hi_byte << 8) | lo_byte);
    }
    else
    {
	// Return 0 if interface is invalid
	return 0x0000;
    }
}

void Bee8080::writeWord(uint16_t addr, uint16_t val)
{
    // Check if interface is valid (i.e. not a null pointer)
    // before accessing it (this helps prevent a buffer overflow caused
    // by an erroneous null pointer)

    if (inter != NULL)
    {
	// The Intel 8080 is a little-endian system,
	// so the 16-bit value is written as follows:
	// mem[addr] = low_byte(val)
	// mem[addr + 1] = high_byte(val)

	inter->writeByte(addr, (val & 0xFF));
	inter->writeByte((addr + 1), (val >> 8));
    }
}

uint8_t Bee8080::portIn(uint8_t port)
{
    // Check if interface is valid (i.e. not a null pointer)
    // before accessing it (this helps prevent a buffer overflow caused
    // by an erroneous null pointer)

    if (inter != NULL)
    {
	return inter->portIn(port);
    }
    else
    {
	// Return 0 if interface is invalid
	return 0x00;
    }
}

void Bee8080::portOut(uint8_t port, uint8_t val)
{
    // Check if interface is valid (i.e. not a null pointer)
    // before accessing it (this helps prevent a buffer overflow caused
    // by an erroneous null pointer)

    if (inter != NULL)
    {
	inter->portOut(port, val);
    }
}

uint8_t Bee8080::getimmByte()
{
    // Fetch the byte located at the address of the program counter...
    uint8_t value = readByte(pc);

    // ...increment the program counter...
    pc += 1;

    // ...and then return the fetched value
    return value;
}

uint16_t Bee8080::getimmWord()
{
    // Fetch the 16-bit word located at the address of the program counter...
    uint16_t value = readWord(pc);

    // ...increment the program counter by 2 (once for each fetched byte)...
    pc += 2;

    // ...and then return the fetched value
    return value;
}

// Bit manipulation functions start here

// Returns value of bit X as bool
bool Bee8080::testbit(uint8_t reg, int bit)
{
    return (reg & (1 << bit)) ? true : false;
}

// Sets bit X to 1
uint8_t Bee8080::setbit(uint8_t reg, int bit)
{
    return (reg | (1 << bit));   
}

// Resets bit X to 0
uint8_t Bee8080::resetbit(uint8_t reg, int bit)
{
    return (reg & ~(1 << bit));
}

// Change bit based on whether boolean of val is true
uint8_t Bee8080::changebit(uint8_t reg, int bit, bool val)
{
    if (val)
    {
	return setbit(reg, bit);
    }
    else
    {
	return resetbit(reg, bit);
    }
}

// Function definitions for fetching and setting individual flags start here

// Fetches the value of the carry flag
bool Bee8080::iscarry()
{
    // The carry flag is bit 0 of the flags register
    return testbit(af.getlo(), 0);
}

// Sets the carry flag to the value of val
void Bee8080::setcarry(bool val)
{
    // The carry flag is bit 0 of the flags register
    af.setlo(changebit(af.getlo(), 0, val));
}

// Fetches the value of the auxillary-carry (aka. half-carry) flag
bool Bee8080::ishalf()
{
    // The half-carry flag is bit 4 of the flags register
    return testbit(af.getlo(), 4);
}

// Sets the auxillary-carry (aka. half-carry) flag to the value of val
void Bee8080::sethalf(bool val)
{
    // The half-carry flag is bit 4 of the flags register
    af.setlo(changebit(af.getlo(), 4, val));
}

// Fetches the value of the zero flag
bool Bee8080::iszero()
{
    // The zero flag is bit 6 of the flags register
    return testbit(af.getlo(), 6);
}

// Sets the zero flag to the value of val
void Bee8080::setzero(bool val)
{
    // The zero flag is bit 6 of the flags register
    af.setlo(changebit(af.getlo(), 6, val));
}

// Fetches the value of the sign flag
bool Bee8080::issign()
{
    // The sign flag is bit 7 of the flags register
    return testbit(af.getlo(), 7);
}

// Sets the sign flag to the value of val
void Bee8080::setsign(bool val)
{
    // The sign flag is bit 7 of the flags register
    af.setlo(changebit(af.getlo(), 7, val));
}

// Fetches the value of the parity flag
bool Bee8080::isparity()
{
    // The parity flag is bit 2 of the flags register
    return testbit(af.getlo(), 2);
}

// Sets the parity flag to the value of val
void Bee8080::setparity(bool val)
{
    // The parity flag is bit 2 of the flags register
    af.setlo(changebit(af.getlo(), 2, val));
}

// This code is responsible for calculating the parity of a byte
// Returns false if the number of 1 bits in 'val' are odd,
// otherwise it returns true
bool Bee8080::parity(uint8_t val)
{
    uint8_t num_one_bits = 0;

    for (int i = 0; i < 8; i++)
    {
	num_one_bits += testbit(val, i);
    }

    return !testbit(num_one_bits, 0);
}

// Instruction definitions start here

// Jump instruction code (takes up 10 cycles)
int Bee8080::jump(uint16_t val, bool cond)
{
    if (cond)
    {
	// Set the program counter to the given address
	// if cond is true
	pc = val;
    }

    return 10;
}

// Call instruction code (takes up 17 cycles if cond is true, or 11 cycles if cond is false)
int Bee8080::call(bool cond)
{
    // Fetch next word in memory...
    uint16_t val = getimmWord();

    // ...and call to that value if cond is true
    if (cond)
    {
	// Push the current PC onto the stack,
	// and jump to the provided address
	push_stack(pc);
	jump(val);
	// A call instruction takes up 17 cycles if cond is true
	return 17;
    }

    // A call instruction takes up 11 cycles if cond is false
    return 11;
}

// Return instruction code (takes up 10 cycles)
int Bee8080::ret()
{
    pc = pop_stack();
    return 10;
}

// Conditonal return instruction code (takes up 11 cycles if cond is true, or 5 cycles if cond is false)
int Bee8080::ret_cond(bool cond)
{
    // Call ret function if cond is true
    if (cond)
    {
	ret();
	return 11;
    }   

    return 5;
}

// This code is responsible for pushing a 16-bit value onto the stack
int Bee8080::push_stack(uint16_t val)
{
    // Decrement the stack pointer by 2...
    sp -= 2;
    // ...and then write the given value to the address
    // of the decremented stack pointer
    writeWord(sp, val);

    // A push instruction takes up 11 cycles
    return 11;
}

// This code is responsible for pushing the accumulator and flags onto the stack
int Bee8080::push_psw()
{
    // Fetch accumulator and flags
    uint16_t reg = af.getreg();
    // Bits 3 and 5 are always 0
    // Mask of 0xFFD5 = Bits 1, 3, and 5 of flags register cleared
    reg = (reg & 0xFFD5);
    // Bit 1 is always 1
    reg |= 0x02;
    return push_stack(reg);
}

// This code is responsible for popping a 16-bit value off of the stack
uint16_t Bee8080::pop_stack()
{
    // Fetch the value at the address of the stack pointer...
    uint16_t val = readWord(sp);
    // ...increment the stack pointer by 2...
    sp += 2;
    // ...and return the fetched value
    return val;
}

// This code is responsible for popping the accumulator and flags off of the stack
void Bee8080::pop_psw()
{
    uint16_t reg = pop_stack();
    // Mask of 0xFFD5 = Bits 1, 3, and 5 of flags register cleared
    reg &= 0xFFD5;
    // Set the accumulator and flags
    af.setreg(reg);
}

// This code is responsible for ANDing the accumulator with an 8-bit value
void Bee8080::ana(uint8_t val)
{
    uint8_t res = (af.gethi() & val);
    setcarry(false);
    sethalf(testbit((af.gethi() | val), 3));
    setzero((res == 0));
    setsign(testbit(res, 7));
    setparity(parity(res));
    af.sethi(res);
}

// This code is responsible for ORing the accumulator with an 8-bit value
void Bee8080::ora(uint8_t val)
{
    uint8_t res = (af.gethi() | val);
    setcarry(false);
    sethalf(false);
    setzero((res == 0));
    setsign(testbit(res, 7));
    setparity(parity(res));
    af.sethi(res);
}

// This code is responsible for XORing the accumulator with an 8-bit value
void Bee8080::xra(uint8_t val)
{
    uint8_t res = (af.gethi() ^ val);
    setcarry(false);
    sethalf(false);
    setzero((res == 0));
    setsign(testbit(res, 7));
    setparity(parity(res));
    af.sethi(res);
}

// This code is responsible for the XCHG instruction,
// which swaps the values of the DE and HL registers
int Bee8080::xchg()
{
    // Store current value of DE in a temporary variable
    uint16_t de_old = de.getreg();
    // Set the DE register to the value of HL...
    de.setreg(hl.getreg());
    // ...and set HL to the old value of DE
    hl.setreg(de_old);
    return 5;
}

// This function is responsible for emulating the individual Intel 8080 instructions
int Bee8080::executenextopcode(uint8_t opcode)
{
    int cycle_count = 0;
    switch (opcode)
    {
	case 0x06: bc.sethi(getimmByte()); cycle_count = 7; break; // MVI B, d8
	case 0x0E: bc.setlo(getimmByte()); cycle_count = 7; break; // MVI C, d8
	case 0x16: de.sethi(getimmByte()); cycle_count = 7; break; // MVI D, d8
	case 0x1E: de.setlo(getimmByte()); cycle_count = 7; break; // MVI E, d8
	case 0x21: hl.setreg(getimmWord()); cycle_count = 10; break; // LXI H, d16
	case 0x26: hl.sethi(getimmByte()); cycle_count = 7; break; // MVI H, d8
	case 0x2E: hl.setlo(getimmByte()); cycle_count = 7; break; // MVI L, d8
	case 0x31: sp = getimmWord(); cycle_count = 10; break; // LXI SP, d16
	case 0x36: writeByte(hl.getreg(), getimmByte()); cycle_count = 10; break; // MVI M, d8
	case 0x3E: af.sethi(getimmByte()); cycle_count = 7; break; // MVI A, d8
	case 0x40: bc.sethi(bc.gethi()); cycle_count = 5; break; // MOV B, B
	case 0x41: bc.sethi(bc.getlo()); cycle_count = 5; break; // MOV B, C
	case 0x42: bc.sethi(de.gethi()); cycle_count = 5; break; // MOV B, D
	case 0x43: bc.sethi(de.getlo()); cycle_count = 5; break; // MOV B, E
	case 0x44: bc.sethi(hl.gethi()); cycle_count = 5; break; // MOV B, H
	case 0x45: bc.sethi(hl.getlo()); cycle_count = 5; break; // MOV B, L
	case 0x46: bc.sethi(readByte(hl.getreg())); cycle_count = 7; break; // MOV B, M
	case 0x47: bc.sethi(af.gethi()); cycle_count = 5; break; // MOV B, A
	case 0x48: bc.setlo(bc.gethi()); cycle_count = 5; break; // MOV C, B
	case 0x49: bc.setlo(bc.getlo()); cycle_count = 5; break; // MOV C, C
	case 0x4A: bc.setlo(de.gethi()); cycle_count = 5; break; // MOV C, D
	case 0x4B: bc.setlo(de.getlo()); cycle_count = 5; break; // MOV C, E
	case 0x4C: bc.setlo(hl.gethi()); cycle_count = 5; break; // MOV C, H
	case 0x4D: bc.setlo(hl.getlo()); cycle_count = 5; break; // MOV C, L
	case 0x4E: bc.setlo(readByte(hl.getreg())); cycle_count = 7; break; // MOV C, M
	case 0x4F: bc.setlo(af.gethi()); cycle_count = 5; break; // MOV C, A
	case 0x50: de.sethi(bc.gethi()); cycle_count = 5; break; // MOV D, B
	case 0x51: de.sethi(bc.getlo()); cycle_count = 5; break; // MOV D, C
	case 0x52: de.sethi(de.gethi()); cycle_count = 5; break; // MOV D, D
	case 0x53: de.sethi(de.getlo()); cycle_count = 5; break; // MOV D, E
	case 0x54: de.sethi(hl.gethi()); cycle_count = 5; break; // MOV D, H
	case 0x55: de.sethi(hl.getlo()); cycle_count = 5; break; // MOV D, L
	case 0x56: de.sethi(readByte(hl.getreg())); cycle_count = 7; break; // MOV D, M
	case 0x57: de.sethi(af.gethi()); cycle_count = 5; break; // MOV D, A
	case 0x58: de.setlo(bc.gethi()); cycle_count = 5; break; // MOV E, B
	case 0x59: de.setlo(bc.getlo()); cycle_count = 5; break; // MOV E, C
	case 0x5A: de.setlo(de.gethi()); cycle_count = 5; break; // MOV E, D
	case 0x5B: de.setlo(de.getlo()); cycle_count = 5; break; // MOV E, E
	case 0x5C: de.setlo(hl.gethi()); cycle_count = 5; break; // MOV E, H
	case 0x5D: de.setlo(hl.getlo()); cycle_count = 5; break; // MOV E, L
	case 0x5E: de.setlo(readByte(hl.getreg())); cycle_count = 7; break; // MOV E, M
	case 0x5F: de.setlo(af.gethi()); cycle_count = 5; break; // MOV E, A
	case 0x60: hl.sethi(bc.gethi()); cycle_count = 5; break; // MOV H, B
	case 0x61: hl.sethi(bc.getlo()); cycle_count = 5; break; // MOV H, C
	case 0x62: hl.sethi(de.gethi()); cycle_count = 5; break; // MOV H, D
	case 0x63: hl.sethi(de.getlo()); cycle_count = 5; break; // MOV H, E
	case 0x64: hl.sethi(hl.gethi()); cycle_count = 5; break; // MOV H, H
	case 0x65: hl.sethi(hl.getlo()); cycle_count = 5; break; // MOV H, L
	case 0x66: hl.sethi(readByte(hl.getreg())); cycle_count = 7; break; // MOV H, M
	case 0x67: hl.sethi(af.gethi()); cycle_count = 5; break; // MOV H, A
	case 0x68: hl.setlo(bc.gethi()); cycle_count = 5; break; // MOV L, B
	case 0x69: hl.setlo(bc.getlo()); cycle_count = 5; break; // MOV L, C
	case 0x6A: hl.setlo(de.gethi()); cycle_count = 5; break; // MOV L, D
	case 0x6B: hl.setlo(de.getlo()); cycle_count = 5; break; // MOV L, E
	case 0x6C: hl.setlo(hl.gethi()); cycle_count = 5; break; // MOV L, H
	case 0x6D: hl.setlo(hl.getlo()); cycle_count = 5; break; // MOV L, L
	case 0x6E: hl.setlo(readByte(hl.getreg())); cycle_count = 7; break; // MOV L, M
	case 0x6F: hl.setlo(af.gethi()); cycle_count = 5; break; // MOV L, A
	case 0x70: writeByte(hl.getreg(), bc.gethi()); cycle_count = 7; break; // MOV M, B
	case 0x71: writeByte(hl.getreg(), bc.getlo()); cycle_count = 7; break; // MOV M, C
	case 0x72: writeByte(hl.getreg(), de.gethi()); cycle_count = 7; break; // MOV M, D
	case 0x73: writeByte(hl.getreg(), de.getlo()); cycle_count = 7; break; // MOV M, E
	case 0x74: writeByte(hl.getreg(), hl.gethi()); cycle_count = 7; break; // MOV M, H
	case 0x75: writeByte(hl.getreg(), hl.getlo()); cycle_count = 7; break; // MOV M, L
	case 0x77: writeByte(hl.getreg(), af.gethi()); cycle_count = 7; break; // MOV M, A
	case 0x78: af.sethi(bc.gethi()); cycle_count = 5; break; // MOV A, B
	case 0x79: af.sethi(bc.getlo()); cycle_count = 5; break; // MOV A, C
	case 0x7A: af.sethi(de.gethi()); cycle_count = 5; break; // MOV A, D
	case 0x7B: af.sethi(de.getlo()); cycle_count = 5; break; // MOV A, E
	case 0x7C: af.sethi(hl.gethi()); cycle_count = 5; break; // MOV A, H
	case 0x7D: af.sethi(hl.getlo()); cycle_count = 5; break; // MOV A, L
	case 0x7E: af.sethi(readByte(hl.getreg())); cycle_count = 7; break; // MOV A, M
	case 0x7F: af.sethi(af.gethi()); cycle_count = 5; break; // MOV A, A
	case 0xA0: ana(bc.gethi()); cycle_count = 4; break; // ANA B
	case 0xA1: ana(bc.getlo()); cycle_count = 4; break; // ANA C
	case 0xA2: ana(de.gethi()); cycle_count = 4; break; // ANA D
	case 0xA3: ana(de.getlo()); cycle_count = 4; break; // ANA E
	case 0xA4: ana(hl.gethi()); cycle_count = 4; break; // ANA H
	case 0xA5: ana(hl.getlo()); cycle_count = 4; break; // ANA L
	case 0xA6: ana(readByte(hl.getreg())); cycle_count = 7; break; // ANA M
	case 0xA7: ana(af.gethi()); cycle_count = 4; break; // ANA A
	case 0xA8: xra(bc.gethi()); cycle_count = 4; break; // XRA B
	case 0xA9: xra(bc.getlo()); cycle_count = 4; break; // XRA C
	case 0xAA: xra(de.gethi()); cycle_count = 4; break; // XRA D
	case 0xAB: xra(de.getlo()); cycle_count = 4; break; // XRA E
	case 0xAC: xra(hl.gethi()); cycle_count = 4; break; // XRA H
	case 0xAD: xra(hl.getlo()); cycle_count = 4; break; // XRA L
	case 0xAE: xra(readByte(hl.getreg())); cycle_count = 7; break; // XRA M
	case 0xAF: xra(af.gethi()); cycle_count = 4; break; // XRA A
	case 0xB0: ora(bc.gethi()); cycle_count = 4; break; // ORA B
	case 0xB1: ora(bc.getlo()); cycle_count = 4; break; // ORA C
	case 0xB2: ora(de.gethi()); cycle_count = 4; break; // ORA D
	case 0xB3: ora(de.getlo()); cycle_count = 4; break; // ORA E
	case 0xB4: ora(hl.gethi()); cycle_count = 4; break; // ORA H
	case 0xB5: ora(hl.getlo()); cycle_count = 4; break; // ORA L
	case 0xB6: ora(readByte(hl.getreg())); cycle_count = 7; break; // ORA M
	case 0xB7: ora(af.gethi()); cycle_count = 4; break; // ORA A
	case 0xC0: cycle_count = ret_cond(!iszero()); break; // RNZ
	case 0xC1: bc.setreg(pop_stack()); cycle_count = 10; break; // POP B
	case 0xC2: cycle_count = jump(getimmWord(), !iszero()); break; // JNZ a16
	case 0xC3: cycle_count = jump(getimmWord()); break; // JMP a16
	case 0xC4: cycle_count = call(!iszero()); break; // CNZ
	case 0xC5: cycle_count = push_stack(bc.getreg()); break; // PUSH B
	case 0xC8: cycle_count = ret_cond(iszero()); break; // RZ
	case 0xC9: cycle_count = ret(); break; // RET
	case 0xCA: cycle_count = jump(getimmWord(), iszero()); break; // JZ a16
	case 0xCC: cycle_count = call(iszero()); break; // CZ
	case 0xCD: cycle_count = call(); break; // CALL a16
	case 0xD0: cycle_count = ret_cond(!iscarry()); break; // RNC
	case 0xD1: de.setreg(pop_stack()); cycle_count = 10; break; // POP D
	case 0xD2: cycle_count = jump(getimmWord(), !iscarry()); break; // JNC a16
	case 0xD3: portOut(getimmByte(), af.gethi()); cycle_count = 10; break; // OUT d8
	case 0xD4: cycle_count = call(!iscarry()); break; // CNC
	case 0xD5: cycle_count = push_stack(de.getreg()); break; // PUSH D
	case 0xD8: cycle_count = ret_cond(iscarry()); break; // RC
	case 0xDA: cycle_count = jump(getimmWord(), iscarry()); break; // JC a16
	case 0xDB: af.sethi(portIn(getimmByte())); cycle_count = 10; break; // IN d8
	case 0xDC: cycle_count = call(iscarry()); break; // CC
	case 0xE0: cycle_count = ret_cond(!isparity()); break; // RPO
	case 0xE1: hl.setreg(pop_stack()); cycle_count = 10; break; // POP H
	case 0xE2: cycle_count = jump(getimmWord(), !isparity()); break; // JPO a16
	case 0xE4: cycle_count = call(!isparity()); break; // CPO
	case 0xE5: cycle_count = push_stack(hl.getreg()); break; // PUSH H
	case 0xE6: ana(getimmByte()); cycle_count = 7; break; // ANI d8
	case 0xE8: cycle_count = ret_cond(isparity()); break; // RPE
	case 0xEA: cycle_count = jump(getimmWord(), isparity()); break; // JPE a16
	case 0xEB: cycle_count = xchg(); break;  // XCHG
	case 0xEC: cycle_count = call(isparity()); break; // CPE
	case 0xEE: xra(getimmByte()); cycle_count = 7; break; // XRI d8
	case 0xF0: cycle_count = ret_cond(!issign()); break; // RP
	case 0xF1: pop_psw(); cycle_count = 10; break; // POP PSW
	case 0xF2: cycle_count = jump(getimmWord(), !issign()); break; // JP a16
	case 0xF4: cycle_count = call(!issign()); break; // CP
	case 0xF5: cycle_count = push_psw(); break;  // PUSH PSW
	case 0xF6: ora(getimmByte()); cycle_count = 7; break; // ORI d8
	case 0xF8: cycle_count = ret_cond(issign()); break; // RM
	case 0xFA: cycle_count = jump(getimmWord(), issign()); break; // JM a16
	case 0xFC: cycle_count = call(issign()); break; // CM
	default: unrecognizedopcode(opcode); cycle_count = 0; break;
    }

    return cycle_count;
}

// This function is called when the emulated Intel 8080 encounters
// a CPU instruction it doesn't recgonize
void Bee8080::unrecognizedopcode(uint8_t opcode)
{
    cout << "Fatal: Unrecognized opcode of " << hex << (int)(opcode) << endl;
    exit(1);
}