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

// Initialize the emulated 8080
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

// Shutdown the emulated 8080
void Bee8080::shutdown()
{
    // Set the interface pointer to NULL if we haven't done so already
    if (inter != NULL)
    {
	inter = NULL;
    }

    // Notify the user that the emulated 8080 has been shut down
    cout << "Bee8080::Shutting down..." << endl;
}

// Reset the emulated 8080
void Bee8080::reset(uint16_t init_pc)
{
    cout << "Bee8080::Resetting..." << endl;
    init(init_pc);
}

// Set callback interface
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
    // Handle interrupts
    if (interrupt_pending && interrupt_enable)
    {
	interrupt_pending = false;
	interrupt_enable = false;
	is_halted = false;
	return executenextopcode(interrupt_opcode);
    }
    else if (!is_halted)
    {
	// Execute next instruction
	return executenextopcode(getimmByte());
    }

    return 0;
}

// Asks the emulated 8080 to service an interrupt
// with an instruction of "opcode"
void Bee8080::setinterrupt(uint8_t opcode)
{
    interrupt_pending = true;
    interrupt_opcode = opcode;
}

// Reads an 8-bit value from memory at address of "addr"
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

// Writes an 8-bit value "val" to memory at address of "addr"
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

// Reads a 16-bit value from memory at address of "addr"
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

// Writes a 16-bit value "val" to memory at address of "addr"
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

// Reads an 8-bit value from an I/O device at port of "port"
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

// Writes an 8-bit value "val" to an I/O device at port of "port"
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

// Fetches subsequent byte from memory
uint8_t Bee8080::getimmByte()
{
    // Fetch the byte located at the address of the program counter...
    uint8_t value = readByte(pc);

    // ...increment the program counter...
    pc += 1;

    // ...and then return the fetched value
    return value;
}

// Fetches subsequent word from memory
uint16_t Bee8080::getimmWord()
{
    // Fetch the 16-bit word located at the address of the program counter...
    uint16_t value = readWord(pc);

    // ...increment the program counter by 2 (once for each fetched byte)...
    pc += 2;

    // ...and then return the fetched value
    return value;
}

// Prints debug output to the console (handy for debugging)
void Bee8080::debugoutput(bool printdisassembly)
{
    uint16_t af_reg = af.getreg();
    // Bits 3 and 5 are always 0
    af_reg = resetbit(af_reg, 3);
    af_reg = resetbit(af_reg, 5);
    // Bit 1 is always 1
    af_reg = setbit(af_reg, 1);

    cout << "AF: " << hex << (int)(af_reg) << endl;
    cout << "BC: " << hex << (int)(bc.getreg()) << endl;
    cout << "DE: " << hex << (int)(de.getreg()) << endl;
    cout << "HL: " << hex << (int)(hl.getreg()) << endl;
    cout << "PC: " << hex << (int)(pc) << endl;
    cout << "SP: " << hex << (int)(sp) << endl;

    if (printdisassembly)
    {
	cout << "Current instruction: " << disassembleinstr(pc) << endl;
    }

    cout << endl;
}

// Disassembles an instruction at address of "addr"
string Bee8080::disassembleinstr(uint16_t addr)
{
    stringstream instr;

    uint8_t opcode = readByte(addr);

    uint16_t pc_val = (addr + 1);
    uint8_t imm_byte = readByte(pc_val);
    uint16_t imm_word = readWord(pc_val);

    switch (opcode)
    {
	case 0x00: instr << "NOP"; break;
	case 0x01: instr << "LXI B, " << hex << (int)(imm_word); break;
	case 0x02: instr << "STAX B"; break;
	case 0x03: instr << "INX B"; break;
	case 0x04: instr << "INR B"; break;
	case 0x05: instr << "DCR B"; break;
	case 0x06: instr << "MVI B, " << hex << (int)(imm_byte); break;
	case 0x07: instr << "RLC"; break;
	case 0x08: instr << "NOP (undocumented)"; break;
	case 0x09: instr << "DAD B"; break;
	case 0x0A: instr << "LDAX B"; break;
	case 0x0B: instr << "DCX B"; break;
	case 0x0C: instr << "INR C"; break;
	case 0x0D: instr << "DCR C"; break;
	case 0x0E: instr << "MVI C, " << hex << (int)(imm_byte); break;
	case 0x0F: instr << "RRC"; break;
	case 0x10: instr << "NOP (undocumented)"; break;
	case 0x11: instr << "LXI D, " << hex << (int)(imm_word); break;
	case 0x12: instr << "STAX D"; break;
	case 0x13: instr << "INX D"; break;
	case 0x14: instr << "INR D"; break;
	case 0x15: instr << "DCR D"; break;
	case 0x16: instr << "MVI D, " << hex << (int)(imm_byte); break;
	case 0x17: instr << "RAL"; break;
	case 0x18: instr << "NOP (undocumented)"; break;
	case 0x19: instr << "DAD D"; break;
	case 0x1A: instr << "LDAX D"; break;
	case 0x1B: instr << "DCX D"; break;
	case 0x1C: instr << "INR E"; break;
	case 0x1D: instr << "DCR E"; break;
	case 0x1E: instr << "MVI E, " << hex << (int)(imm_byte); break;
	case 0x1F: instr << "RAR"; break;
	case 0x20: instr << "NOP (undocumented)"; break;
	case 0x21: instr << "LXI H, " << hex << (int)(imm_word); break;
	case 0x22: instr << "SHLD " << hex << (int)(imm_word); break;
	case 0x23: instr << "INX H"; break;
	case 0x24: instr << "INR H"; break;
	case 0x25: instr << "DCR H"; break;
	case 0x26: instr << "MVI H, " << hex << (int)(imm_byte); break;
	case 0x27: instr << "DAA"; break;
	case 0x28: instr << "NOP (undocumented)"; break;
	case 0x29: instr << "DAD H"; break;
	case 0x2A: instr << "LHLD " << hex << (int)(imm_word); break;
	case 0x2B: instr << "DCX H"; break;
	case 0x2C: instr << "INR L"; break;
	case 0x2D: instr << "DCR L"; break;
	case 0x2E: instr << "MVI L, " << hex << (int)(imm_byte); break;
	case 0x2F: instr << "CMA"; break;
	case 0x30: instr << "NOP (undocumented)"; break;
	case 0x31: instr << "LXI SP, " << hex << (int)(imm_word); break;
	case 0x32: instr << "STA " << hex << (int)(imm_word); break;
	case 0x33: instr << "INX SP"; break;
	case 0x34: instr << "INR M"; break;
	case 0x35: instr << "DCR M"; break;
	case 0x36: instr << "MVI M, " << hex << (int)(imm_byte); break;
	case 0x37: instr << "STC"; break;
	case 0x38: instr << "NOP (undocumented)"; break;
	case 0x39: instr << "DAD SP"; break;
	case 0x3A: instr << "LDA " << hex << (int)(imm_word); break;
	case 0x3B: instr << "DCX SP"; break;
	case 0x3C: instr << "INR A"; break;
	case 0x3D: instr << "DCR A"; break;
	case 0x3E: instr << "MVI A, " << hex << (int)(imm_byte); break;
	case 0x3F: instr << "CMC"; break;
	case 0x40: instr << "MOV B, B"; break;
	case 0x41: instr << "MOV B, C"; break;
	case 0x42: instr << "MOV B, D"; break;
	case 0x43: instr << "MOV B, E"; break;
	case 0x44: instr << "MOV B, H"; break;
	case 0x45: instr << "MOV B, L"; break;
	case 0x46: instr << "MOV B, M"; break;
	case 0x47: instr << "MOV B, A"; break;
	case 0x48: instr << "MOV C, B"; break;
	case 0x49: instr << "MOV C, C"; break;
	case 0x4A: instr << "MOV C, D"; break;
	case 0x4B: instr << "MOV C, E"; break;
	case 0x4C: instr << "MOV C, H"; break;
	case 0x4D: instr << "MOV C, L"; break;
	case 0x4E: instr << "MOV C, M"; break;
	case 0x4F: instr << "MOV C, A"; break;
	case 0x50: instr << "MOV D, B"; break;
	case 0x51: instr << "MOV D, C"; break;
	case 0x52: instr << "MOV D, D"; break;
	case 0x53: instr << "MOV D, E"; break;
	case 0x54: instr << "MOV D, H"; break;
	case 0x55: instr << "MOV D, L"; break;
	case 0x56: instr << "MOV D, M"; break;
	case 0x57: instr << "MOV D, A"; break;
	case 0x58: instr << "MOV E, B"; break;
	case 0x59: instr << "MOV E, C"; break;
	case 0x5A: instr << "MOV E, D"; break;
	case 0x5B: instr << "MOV E, E"; break;
	case 0x5C: instr << "MOV E, H"; break;
	case 0x5D: instr << "MOV E, L"; break;
	case 0x5E: instr << "MOV E, M"; break;
	case 0x5F: instr << "MOV E, A"; break;
	case 0x60: instr << "MOV H, B"; break;
	case 0x61: instr << "MOV H, C"; break;
	case 0x62: instr << "MOV H, D"; break;
	case 0x63: instr << "MOV H, E"; break;
	case 0x64: instr << "MOV H, H"; break;
	case 0x65: instr << "MOV H, L"; break;
	case 0x66: instr << "MOV H, M"; break;
	case 0x67: instr << "MOV H, A"; break;
	case 0x68: instr << "MOV L, B"; break;
	case 0x69: instr << "MOV L, C"; break;
	case 0x6A: instr << "MOV L, D"; break;
	case 0x6B: instr << "MOV L, E"; break;
	case 0x6C: instr << "MOV L, H"; break;
	case 0x6D: instr << "MOV L, L"; break;
	case 0x6E: instr << "MOV L, M"; break;
	case 0x6F: instr << "MOV L, A"; break;
	case 0x70: instr << "MOV M, B"; break;
	case 0x71: instr << "MOV M, C"; break;
	case 0x72: instr << "MOV M, D"; break;
	case 0x73: instr << "MOV M, E"; break;
	case 0x74: instr << "MOV M, H"; break;
	case 0x75: instr << "MOV M, L"; break;
	case 0x76: instr << "HLT"; break;
	case 0x77: instr << "MOV M, A"; break;
	case 0x78: instr << "MOV A, B"; break;
	case 0x79: instr << "MOV A, C"; break;
	case 0x7A: instr << "MOV A, D"; break;
	case 0x7B: instr << "MOV A, E"; break;
	case 0x7C: instr << "MOV A, H"; break;
	case 0x7D: instr << "MOV A, L"; break;
	case 0x7E: instr << "MOV A, M"; break;
	case 0x7F: instr << "MOV A, A"; break;
	case 0x80: instr << "ADD B"; break;
	case 0x81: instr << "ADD C"; break;
	case 0x82: instr << "ADD D"; break;
	case 0x83: instr << "ADD E"; break;
	case 0x84: instr << "ADD H"; break;
	case 0x85: instr << "ADD L"; break;
	case 0x86: instr << "ADD M"; break;
	case 0x87: instr << "ADD A"; break;
	case 0x88: instr << "ADC B"; break;
	case 0x89: instr << "ADC C"; break;
	case 0x8A: instr << "ADC D"; break;
	case 0x8B: instr << "ADC E"; break;
	case 0x8C: instr << "ADC H"; break;
	case 0x8D: instr << "ADC L"; break;
	case 0x8E: instr << "ADC M"; break;
	case 0x8F: instr << "ADC A"; break;
	case 0x90: instr << "SUB B"; break;
	case 0x91: instr << "SUB C"; break;
	case 0x92: instr << "SUB D"; break;
	case 0x93: instr << "SUB E"; break;
	case 0x94: instr << "SUB H"; break;
	case 0x95: instr << "SUB L"; break;
	case 0x96: instr << "SUB M"; break;
	case 0x97: instr << "SUB A"; break;
	case 0x98: instr << "SBB B"; break;
	case 0x99: instr << "SBB C"; break;
	case 0x9A: instr << "SBB D"; break;
	case 0x9B: instr << "SBB E"; break;
	case 0x9C: instr << "SBB H"; break;
	case 0x9D: instr << "SBB L"; break;
	case 0x9E: instr << "SBB M"; break;
	case 0x9F: instr << "SBB A"; break;
	case 0xA0: instr << "ANA B"; break;
	case 0xA1: instr << "ANA C"; break;
	case 0xA2: instr << "ANA D"; break;
	case 0xA3: instr << "ANA E"; break;
	case 0xA4: instr << "ANA H"; break;
	case 0xA5: instr << "ANA L"; break;
	case 0xA6: instr << "ANA M"; break;
	case 0xA7: instr << "ANA A"; break;
	case 0xA8: instr << "XRA B"; break;
	case 0xA9: instr << "XRA C"; break;
	case 0xAA: instr << "XRA D"; break;
	case 0xAB: instr << "XRA E"; break;
	case 0xAC: instr << "XRA H"; break;
	case 0xAD: instr << "XRA L"; break;
	case 0xAE: instr << "XRA M"; break;
	case 0xAF: instr << "XRA A"; break;
	case 0xB0: instr << "ORA B"; break;
	case 0xB1: instr << "ORA C"; break;
	case 0xB2: instr << "ORA D"; break;
	case 0xB3: instr << "ORA E"; break;
	case 0xB4: instr << "ORA H"; break;
	case 0xB5: instr << "ORA L"; break;
	case 0xB6: instr << "ORA M"; break;
	case 0xB7: instr << "ORA A"; break;
	case 0xB8: instr << "CMP B"; break;
	case 0xB9: instr << "CMP C"; break;
	case 0xBA: instr << "CMP D"; break;
	case 0xBB: instr << "CMP E"; break;
	case 0xBC: instr << "CMP H"; break;
	case 0xBD: instr << "CMP L"; break;
	case 0xBE: instr << "CMP M"; break;
	case 0xBF: instr << "CMP A"; break;
	case 0xC0: instr << "RNZ"; break;
	case 0xC1: instr << "POP B"; break;
	case 0xC2: instr << "JNZ " << hex << (int)(imm_word); break;
	case 0xC3: instr << "JMP " << hex << (int)(imm_word); break;
	case 0xC4: instr << "CNZ " << hex << (int)(imm_word); break;
	case 0xC5: instr << "PUSH B"; break;
	case 0xC6: instr << "ADI " << hex << (int)(imm_byte); break;
	case 0xC7: instr << "RST 0"; break;
	case 0xC8: instr << "RZ"; break;
	case 0xC9: instr << "RET"; break;
	case 0xCA: instr << "JZ " << hex << (int)(imm_word); break;
	case 0xCB: instr << "JMP " << hex << (int)(imm_word) << " (undocumented)"; break;
	case 0xCC: instr << "CZ " << hex << (int)(imm_word); break;
	case 0xCD: instr << "CALL " << hex << (int)(imm_word); break;
	case 0xCE: instr << "ACI " << hex << (int)(imm_byte); break;
	case 0xCF: instr << "RST 1"; break;
	case 0xD0: instr << "RNC"; break;
	case 0xD1: instr << "POP D"; break;
	case 0xD2: instr << "JNC " << hex << (int)(imm_word); break;
	case 0xD3: instr << "OUT " << hex << (int)(imm_byte); break;
	case 0xD4: instr << "CNC " << hex << (int)(imm_word); break;
	case 0xD5: instr << "PUSH D"; break;
	case 0xD6: instr << "SUI " << hex << (int)(imm_byte); break;
	case 0xD7: instr << "RST 2"; break;
	case 0xD8: instr << "RC"; break;
	case 0xD9: instr << "RET (undocumented)"; break;
	case 0xDA: instr << "JC " << hex << (int)(imm_word); break;
	case 0xDB: instr << "IN " << hex << (int)(imm_byte); break;
	case 0xDC: instr << "CC " << hex << (int)(imm_word); break;
	case 0xDD: instr << "CALL " << hex << (int)(imm_word) << " (undocumented)"; break;
	case 0xDE: instr << "SBI " << hex << (int)(imm_byte) << endl; break;
	case 0xDF: instr << "RST 3"; break;
	case 0xE0: instr << "RPO"; break;
	case 0xE1: instr << "POP H"; break;
	case 0xE2: instr << "JPO " << hex << (int)(imm_word); break;
	case 0xE3: instr << "XTHL"; break;
	case 0xE4: instr << "CPO " << hex << (int)(imm_word); break;
	case 0xE5: instr << "PUSH H"; break;
	case 0xE6: instr << "ANI " << hex << (int)(imm_byte); break;
	case 0xE7: instr << "RST 4"; break;
	case 0xE8: instr << "RPE"; break;
	case 0xE9: instr << "PCHL"; break;
	case 0xEA: instr << "JPE " << hex << (int)(imm_word); break;
	case 0xEB: instr << "XCHG"; break;
	case 0xEC: instr << "CPE " << hex << (int)(imm_word); break;
	case 0xED: instr << "CALL " << hex << (int)(imm_word) << " (undocumented)"; break;
	case 0xEE: instr << "XRI " << hex << (int)(imm_byte); break;
	case 0xEF: instr << "RST 5"; break;
	case 0xF0: instr << "RP"; break;
	case 0xF1: instr << "POP PSW"; break;
	case 0xF2: instr << "JP " << hex << (int)(imm_word); break;
	case 0xF3: instr << "DI"; break;
	case 0xF4: instr << "CP " << hex << (int)(imm_word); break;
	case 0xF5: instr << "PUSH PSW"; break;
	case 0xF6: instr << "ORI " << hex << (int)(imm_byte); break;
	case 0xF7: instr << "RST 6"; break;
	case 0xF8: instr << "RM"; break;
	case 0xF9: instr << "SPHL"; break;
	case 0xFA: instr << "JM " << hex << (int)(imm_word); break;
	case 0xFB: instr << "EI"; break;
	case 0xFC: instr << "CM " << hex << (int)(imm_word); break;
	case 0xFD: instr << "CALL " << hex << (int)(imm_word) << " (undocumented)"; break;
	case 0xFE: instr << "CPI " << hex << (int)(imm_byte); break;
	case 0xFF: instr << "RST 7"; break;
	default: instr << "Undefined"; break;
    }

    return instr.str();
}

// Bit manipulation functions start here

// Returns value of bit "bit" in "reg" as bool
bool Bee8080::testbit(uint32_t reg, int bit)
{
    return (reg & (1 << bit)) ? true : false;
}

// Sets bit "bit" in "reg" to 1
uint32_t Bee8080::setbit(uint32_t reg, int bit)
{
    return (reg | (1 << bit));   
}

// Resets bit "bit" in "reg" to 0
uint32_t Bee8080::resetbit(uint32_t reg, int bit)
{
    return (reg & ~(1 << bit));
}

// Change bit "bit" in "reg" based on whether or not "val" is true
uint32_t Bee8080::changebit(uint32_t reg, int bit, bool val)
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

// Calculates if there was a carry between bit "bit" and "bit - 1"
// when performing an addition or subtraction of two values
bool Bee8080::carry(int bit_num, uint8_t reg, uint8_t val, uint16_t res)
{
    uint16_t carry_reg = (reg ^ val ^ res);
    return testbit(carry_reg, bit_num);
}

// Calculates the parity of a byte
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

// Internal code for arithmetic operations start here

// Internal code for ADD operation
uint8_t Bee8080::add_internal(uint8_t reg, uint8_t val, bool carryflag)
{
    // Perform actual calculation
    uint16_t res = (reg + val + carryflag);

    // Set flags
    setzsp(res);
    sethalf(carry(4, reg, val, res));
    setcarry(carry(8, reg, val, res));

    // Return 8-bit value
    return res;
}

// Internal code for SUB operation
uint8_t Bee8080::sub_internal(uint8_t reg, uint8_t val, bool carryflag)
{
    // Perform actual calculation
    uint16_t res = (reg - val - carryflag);

    // Set flags
    setzsp(res);
    sethalf(!carry(4, reg, val, res));
    setcarry(carry(8, reg, val, res));

    // Return 8-bit value
    return res;
}

// Internal code for setting the zero, sign and parity flags
// given a value of "val"
void Bee8080::setzsp(uint8_t val)
{
    // Zero flag is set if value is equal to zero
    setzero((val == 0));

    // Sign flag is set if bit 7 of value is set
    setsign(testbit(val, 7));

    // Parity flag is set if number of set bits in value is even
    setparity(parity(val));
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

// RST instruction code (takes up 11 cycles)
int Bee8080::rst(int num)
{
    // "num" << 3 equals "num" * 8
    uint16_t pc_val = (num << 3);

    // Push the current PC onto the stack,
    // and jump to the provided address
    push_stack(pc);
    jump(pc_val);
    return 11;
}

// Pushes a 16-bit value onto the stack
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

// Pushes the accumulator and flags onto the stack
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

// Pops a 16-bit value off of the stack
uint16_t Bee8080::pop_stack()
{
    // Fetch the value at the address of the stack pointer...
    uint16_t val = readWord(sp);
    // ...increment the stack pointer by 2...
    sp += 2;
    // ...and return the fetched value
    return val;
}

// Pops the accumulator and flags off of the stack
void Bee8080::pop_psw()
{
    uint16_t reg = pop_stack();
    // Mask of 0xFFD5 = Bits 1, 3, and 5 of flags register cleared
    reg &= 0xFFD5;
    // Set the accumulator and flags
    af.setreg(reg);
}

// Adds an 8-bit value to the accumulator
void Bee8080::add(uint8_t val)
{
    af.sethi(add_internal(af.gethi(), val));
}

// Adds an 8-bit value to the accumulator with carry
void Bee8080::adc(uint8_t val)
{
    af.sethi(add_internal(af.gethi(), val, iscarry()));
}

// Adds a 16-bit value to HL
void Bee8080::dad(uint16_t val)
{
    uint32_t res = (hl.getreg() + val);
    // Carry flag is set is if there is carry from bit 15
    setcarry(testbit(res, 16));
    hl.setreg(res);
}

// Subtracts an 8-bit value from the accumulator
void Bee8080::sub(uint8_t val)
{
    af.sethi(sub_internal(af.gethi(), val));
}

// Subtracts an 8-bit value from the accumulator with borrow
void Bee8080::sbb(uint8_t val)
{
    af.sethi(sub_internal(af.gethi(), val, iscarry()));
}

// Increments an 8-bit value by 1
uint8_t Bee8080::incr(uint8_t val)
{
    uint8_t res = (val + 1);
    sethalf((res & 0xF) == 0);
    setzsp(res);
    return res;
}

// Decrements an 8-bit value by 1
uint8_t Bee8080::decr(uint8_t val)
{
    uint8_t res = (val - 1);
    sethalf(!((res & 0xF) == 0xF));
    setzsp(res);
    return res;
}

// ANDs the accumulator with an 8-bit value
void Bee8080::ana(uint8_t val)
{
    uint8_t res = (af.gethi() & val);
    setzsp(res);
    sethalf(testbit((af.gethi() | val), 3));
    setcarry(false);
    af.sethi(res);
}

// ORs the accumulator with an 8-bit value
void Bee8080::ora(uint8_t val)
{
    uint8_t res = (af.gethi() | val);
    setzsp(res);
    sethalf(false);
    setcarry(false);
    af.sethi(res);
}

// XORs the accumulator with an 8-bit value
void Bee8080::xra(uint8_t val)
{
    uint8_t res = (af.gethi() ^ val);
    setzsp(res);
    sethalf(false);
    setcarry(false);
    af.sethi(res);
}

// Compares an 8-bit value with the accumulator
void Bee8080::cmp(uint8_t val)
{
    sub_internal(af.gethi(), val);
}

// Swaps the values of the DE and HL registers
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

// Swaps the values of [SP] and HL
int Bee8080::xthl()
{
    // Store current value of [SP] in a temporary variable
    uint16_t sp_old = readWord(sp);

    // Set [SP] to the value of HL...
    writeWord(sp, hl.getreg());

    // ...and set HL to the old value of [SP]
    hl.setreg(sp_old);
    return 18;
}

// Adjust the 8-bit number in the accumulator to form
// two 4-bit BCD digits.
// For example, if A=$2B and DAA is executed, A becomes $31.
void Bee8080::daa()
{
    bool carryflag = iscarry();
    uint8_t accum = af.gethi();
    uint8_t correction = 0;

    uint8_t lsb = (accum & 0x0F);
    uint8_t msb = (accum >> 4);

    if (ishalf() || lsb > 9)
    {
	correction += 0x06;
    }

    if (iscarry() || msb > 9 || (msb >= 9 && lsb > 9))
    {
	correction += 0x60;
	carryflag = true;
    }

    af.sethi(add_internal(af.gethi(), correction));
    setcarry(carryflag);
}

// Rotate accumulator left
void Bee8080::rlc()
{
    setcarry(testbit(af.gethi(), 7));
    af.sethi((af.gethi() << 1) | iscarry());
}

// Rotate accumulator right
void Bee8080::rrc()
{
    setcarry(testbit(af.gethi(), 0));
    af.sethi((af.gethi() >> 1) | (iscarry() << 7));
}

// Rotate accumulator left with the carry flag
void Bee8080::ral()
{
    bool carryflag = iscarry();
    setcarry(testbit(af.gethi(), 7));
    af.sethi((af.gethi() << 1) | carryflag);
}

// Rotate accumulator right with the carry flag
void Bee8080::rar()
{
    bool carryflag = iscarry();
    setcarry(testbit(af.gethi(), 0));
    af.sethi((af.gethi() >> 1) | (carryflag << 7));
}

// Emulates the individual Intel 8080 instructions
// Note: An asterisk right next to the instruction mnemonic
// means that the instruction is undocumented
int Bee8080::executenextopcode(uint8_t opcode)
{
    int cycle_count = 0;

    // When EI is executed, interrupts won't be serviced
    // until the end of the next instruction
    if (interrupt_delay)
    {
	interrupt_delay = false;
	interrupt_enable = true;
    }

    switch (opcode)
    {
	case 0x00: cycle_count = 4; break; // NOP
	case 0x01: bc.setreg(getimmWord()); cycle_count = 10; break; // LXI B, d16
	case 0x02: writeByte(bc.getreg(), af.gethi()); cycle_count = 7; break; // STAX B
	case 0x03: bc.setreg(bc.getreg() + 1); cycle_count = 5; break; // INX B
	case 0x04: bc.sethi(incr(bc.gethi())); cycle_count = 5; break; // INR B
	case 0x05: bc.sethi(decr(bc.gethi())); cycle_count = 5; break; // DCR B
	case 0x06: bc.sethi(getimmByte()); cycle_count = 7; break; // MVI B, d8
	case 0x07: rlc(); cycle_count = 4; break; // RLC
	case 0x08: cycle_count = 4; break; // *NOP
	case 0x09: dad(bc.getreg()); cycle_count = 10; break; // DAD B
	case 0x0A: af.sethi(readByte(bc.getreg())); cycle_count = 7; break; // LDAX B
	case 0x0B: bc.setreg(bc.getreg() - 1); cycle_count = 5; break; // DCX B
	case 0x0C: bc.setlo(incr(bc.getlo())); cycle_count = 5; break; // INR C
	case 0x0D: bc.setlo(decr(bc.getlo())); cycle_count = 5; break; // DCR C
	case 0x0E: bc.setlo(getimmByte()); cycle_count = 7; break; // MVI C, d8
	case 0x0F: rrc(); cycle_count = 4; break;
	case 0x10: cycle_count = 4; break; // *NOP
	case 0x11: de.setreg(getimmWord()); cycle_count = 10; break; // LXI D, d16
	case 0x12: writeByte(de.getreg(), af.gethi()); cycle_count = 7; break; // STAX D
	case 0x13: de.setreg(de.getreg() + 1); cycle_count = 5; break; // INX D
	case 0x14: de.sethi(incr(de.gethi())); cycle_count = 5; break; // INR D
	case 0x15: de.sethi(decr(de.gethi())); cycle_count = 5; break; // DCR D
	case 0x16: de.sethi(getimmByte()); cycle_count = 7; break; // MVI D, d8
	case 0x17: ral(); cycle_count = 4; break; // RAL
	case 0x18: cycle_count = 4; break; // *NOP
	case 0x19: dad(de.getreg()); cycle_count = 10; break; // DAD D
	case 0x1A: af.sethi(readByte(de.getreg())); cycle_count = 7; break; // LDAX D
	case 0x1B: de.setreg(de.getreg() - 1); cycle_count = 5; break; // DCX D
	case 0x1C: de.setlo(incr(de.getlo())); cycle_count = 5; break; // INR E
	case 0x1D: de.setlo(decr(de.getlo())); cycle_count = 5; break; // DCR E
	case 0x1E: de.setlo(getimmByte()); cycle_count = 7; break; // MVI E, d8
	case 0x1F: rar(); cycle_count = 4; break; // RAR
	case 0x20: cycle_count = 4; break; // *NOP
	case 0x21: hl.setreg(getimmWord()); cycle_count = 10; break; // LXI H, d16
	case 0x22: writeWord(getimmWord(), hl.getreg()); cycle_count = 16; break; // SHLD a16
	case 0x23: hl.setreg(hl.getreg() + 1); cycle_count = 5; break; // INX H
	case 0x24: hl.sethi(incr(hl.gethi())); cycle_count = 5; break; // INR H
	case 0x25: hl.sethi(decr(hl.gethi())); cycle_count = 5; break; // DCR H
	case 0x26: hl.sethi(getimmByte()); cycle_count = 7; break; // MVI H, d8
	case 0x27: daa(); cycle_count = 4; break;
	case 0x28: cycle_count = 4; break; // *NOP
	case 0x29: dad(hl.getreg()); cycle_count = 10; break; // DAD G
	case 0x2A: hl.setreg(readWord(getimmWord())); cycle_count = 16; break; // LHLD a16
	case 0x2B: hl.setreg(hl.getreg() - 1); cycle_count = 5; break; // DCX H
	case 0x2C: hl.setlo(incr(hl.getlo())); cycle_count = 5; break; // INR L
	case 0x2D: hl.setlo(decr(hl.getlo())); cycle_count = 5; break; // DCR L
	case 0x2E: hl.setlo(getimmByte()); cycle_count = 7; break; // MVI L, d8
	case 0x2F: af.sethi(~af.gethi()); cycle_count = 4; break; // CMA
	case 0x31: sp = getimmWord(); cycle_count = 10; break; // LXI SP, d16
	case 0x32: writeByte(getimmWord(), af.gethi()); cycle_count = 13; break; // STA a16
	case 0x33: sp += 1; cycle_count = 5; break; // INX SP
	case 0x34: writeByte(hl.getreg(), incr(readByte(hl.getreg()))); cycle_count = 10; break; // INR M
	case 0x35: writeByte(hl.getreg(), decr(readByte(hl.getreg()))); cycle_count = 10; break; // DCR M
	case 0x36: writeByte(hl.getreg(), getimmByte()); cycle_count = 10; break; // MVI M, d8
	case 0x37: setcarry(true); cycle_count = 4; break; // STC
	case 0x39: dad(sp); cycle_count = 10; break; // DAD SP
	case 0x3A: af.sethi(readByte(getimmWord())); cycle_count = 13; break; // LDA a16
	case 0x3B: sp -= 1; cycle_count = 5; break; // DCX SP
	case 0x3C: af.sethi(incr(af.gethi())); cycle_count = 5; break; // INR A
	case 0x3D: af.sethi(decr(af.gethi())); cycle_count = 5; break; // DCR A
	case 0x3E: af.sethi(getimmByte()); cycle_count = 7; break; // MVI A, d8
	case 0x3F: setcarry(!iscarry()); cycle_count = 4; break; // CMC
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
	case 0x76: is_halted = true; cycle_count = 7; break; // HLT
	case 0x77: writeByte(hl.getreg(), af.gethi()); cycle_count = 7; break; // MOV M, A
	case 0x78: af.sethi(bc.gethi()); cycle_count = 5; break; // MOV A, B
	case 0x79: af.sethi(bc.getlo()); cycle_count = 5; break; // MOV A, C
	case 0x7A: af.sethi(de.gethi()); cycle_count = 5; break; // MOV A, D
	case 0x7B: af.sethi(de.getlo()); cycle_count = 5; break; // MOV A, E
	case 0x7C: af.sethi(hl.gethi()); cycle_count = 5; break; // MOV A, H
	case 0x7D: af.sethi(hl.getlo()); cycle_count = 5; break; // MOV A, L
	case 0x7E: af.sethi(readByte(hl.getreg())); cycle_count = 7; break; // MOV A, M
	case 0x7F: af.sethi(af.gethi()); cycle_count = 5; break; // MOV A, A
	case 0x80: add(bc.gethi()); cycle_count = 4; break; // ADD B
	case 0x81: add(bc.getlo()); cycle_count = 4; break; // ADD C
	case 0x82: add(de.gethi()); cycle_count = 4; break; // ADD D
	case 0x83: add(de.getlo()); cycle_count = 4; break; // ADD E
	case 0x84: add(hl.gethi()); cycle_count = 4; break; // ADD H
	case 0x85: add(hl.getlo()); cycle_count = 4; break; // ADD L
	case 0x86: add(readByte(hl.getreg())); cycle_count = 7; break; // ADD M
	case 0x87: add(af.gethi()); cycle_count = 4; break; // ADD A
	case 0x88: adc(bc.gethi()); cycle_count = 4; break; // ADC B
	case 0x89: adc(bc.getlo()); cycle_count = 4; break; // ADC C
	case 0x8A: adc(de.gethi()); cycle_count = 4; break; // ADC D
	case 0x8B: adc(de.getlo()); cycle_count = 4; break; // ADC E
	case 0x8C: adc(hl.gethi()); cycle_count = 4; break; // ADC H
	case 0x8D: adc(hl.getlo()); cycle_count = 4; break; // ADC L
	case 0x8E: adc(readByte(hl.getreg())); cycle_count = 7; break; // ADC M
	case 0x8F: adc(af.gethi()); cycle_count = 4; break; // ADD A
	case 0x90: sub(bc.gethi()); cycle_count = 4; break; // SUB B
	case 0x91: sub(bc.getlo()); cycle_count = 4; break; // SUB C
	case 0x92: sub(de.gethi()); cycle_count = 4; break; // SUB D
	case 0x93: sub(de.getlo()); cycle_count = 4; break; // SUB E
	case 0x94: sub(hl.gethi()); cycle_count = 4; break; // SUB H
	case 0x95: sub(hl.getlo()); cycle_count = 4; break; // SUB L
	case 0x96: sub(readByte(hl.getreg())); cycle_count = 7; break; // SUB M
	case 0x97: sub(af.gethi()); cycle_count = 4; break; // SUB A
	case 0x98: sbb(bc.gethi()); cycle_count = 4; break; // SBB B
	case 0x99: sbb(bc.getlo()); cycle_count = 4; break; // SBB C
	case 0x9A: sbb(de.gethi()); cycle_count = 4; break; // SBB D
	case 0x9B: sbb(de.getlo()); cycle_count = 4; break; // SBB E
	case 0x9C: sbb(hl.gethi()); cycle_count = 4; break; // SBB H
	case 0x9D: sbb(hl.getlo()); cycle_count = 4; break; // SBB L
	case 0x9E: sbb(readByte(hl.getreg())); cycle_count = 7; break; // SBB M
	case 0x9F: sbb(af.gethi()); cycle_count = 4; break; // SBB A
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
	case 0xB8: cmp(bc.gethi()); cycle_count = 4; break; // CMP B
	case 0xB9: cmp(bc.getlo()); cycle_count = 4; break; // CMP C
	case 0xBA: cmp(de.gethi()); cycle_count = 4; break; // CMP D
	case 0xBB: cmp(de.getlo()); cycle_count = 4; break; // CMP E
	case 0xBC: cmp(hl.gethi()); cycle_count = 4; break; // CMP H
	case 0xBD: cmp(hl.getlo()); cycle_count = 4; break; // CMP L
	case 0xBE: cmp(readByte(hl.getreg())); cycle_count = 7; break; // CMP M
	case 0xBF: cmp(af.gethi()); cycle_count = 4; break; // CMP A
	case 0xC0: cycle_count = ret_cond(!iszero()); break; // RNZ
	case 0xC1: bc.setreg(pop_stack()); cycle_count = 10; break; // POP B
	case 0xC2: cycle_count = jump(getimmWord(), !iszero()); break; // JNZ a16
	case 0xC3: cycle_count = jump(getimmWord()); break; // JMP a16
	case 0xC4: cycle_count = call(!iszero()); break; // CNZ a16
	case 0xC5: cycle_count = push_stack(bc.getreg()); break; // PUSH B
	case 0xC6: add(getimmByte()); cycle_count = 7; break; // ADI d8
	case 0xC7: cycle_count = rst(0); break; // RST 0
	case 0xC8: cycle_count = ret_cond(iszero()); break; // RZ
	case 0xC9: cycle_count = ret(); break; // RET
	case 0xCA: cycle_count = jump(getimmWord(), iszero()); break; // JZ a16
	case 0xCB: cycle_count = jump(getimmWord()); break; // *JMP a16
	case 0xCC: cycle_count = call(iszero()); break; // CZ a16
	case 0xCD: cycle_count = call(); break; // CALL a16
	case 0xCE: adc(getimmByte()); cycle_count = 7; break; // ACI d8
	case 0xCF: cycle_count = rst(1); break; // RST 1
	case 0xD0: cycle_count = ret_cond(!iscarry()); break; // RNC
	case 0xD1: de.setreg(pop_stack()); cycle_count = 10; break; // POP D
	case 0xD2: cycle_count = jump(getimmWord(), !iscarry()); break; // JNC a16
	case 0xD3: portOut(getimmByte(), af.gethi()); cycle_count = 10; break; // OUT d8
	case 0xD4: cycle_count = call(!iscarry()); break; // CNC a16
	case 0xD5: cycle_count = push_stack(de.getreg()); break; // PUSH D
	case 0xD6: sub(getimmByte()); cycle_count = 7; break; // SUI d8
	case 0xD7: cycle_count = rst(2); break; // RST 2
	case 0xD8: cycle_count = ret_cond(iscarry()); break; // RC
	case 0xD9: cycle_count = ret(); break; // *RET
	case 0xDA: cycle_count = jump(getimmWord(), iscarry()); break; // JC a16
	case 0xDB: af.sethi(portIn(getimmByte())); cycle_count = 10; break; // IN d8
	case 0xDC: cycle_count = call(iscarry()); break; // CC a16
	case 0xDD: cycle_count = call(); break; // *CALL a16
	case 0xDE: sbb(getimmByte()); cycle_count = 7; break;
	case 0xDF: cycle_count = rst(3); break; // RST 3
	case 0xE0: cycle_count = ret_cond(!isparity()); break; // RPO
	case 0xE1: hl.setreg(pop_stack()); cycle_count = 10; break; // POP H
	case 0xE2: cycle_count = jump(getimmWord(), !isparity()); break; // JPO a16
	case 0xE3: cycle_count = xthl(); break; // XTHL
	case 0xE4: cycle_count = call(!isparity()); break; // CPO a16
	case 0xE5: cycle_count = push_stack(hl.getreg()); break; // PUSH H
	case 0xE6: ana(getimmByte()); cycle_count = 7; break; // ANI d8
	case 0xE7: cycle_count = rst(4); break; // RST 4
	case 0xE8: cycle_count = ret_cond(isparity()); break; // RPE
	case 0xE9: pc = hl.getreg(); cycle_count = 5; break; // PCHL
	case 0xEA: cycle_count = jump(getimmWord(), isparity()); break; // JPE a16
	case 0xEB: cycle_count = xchg(); break;  // XCHG
	case 0xEC: cycle_count = call(isparity()); break; // CPE a16
	case 0xED: cycle_count = call(); break; // *CALL a16
	case 0xEE: xra(getimmByte()); cycle_count = 7; break; // XRI d8
	case 0xEF: cycle_count = rst(5); break; // RST 5
	case 0xF0: cycle_count = ret_cond(!issign()); break; // RP
	case 0xF1: pop_psw(); cycle_count = 10; break; // POP PSW
	case 0xF2: cycle_count = jump(getimmWord(), !issign()); break; // JP a16
	case 0xF3: interrupt_enable = false; cycle_count = 4; break; // DI
	case 0xF4: cycle_count = call(!issign()); break; // CP a16
	case 0xF5: cycle_count = push_psw(); break;  // PUSH PSW
	case 0xF6: ora(getimmByte()); cycle_count = 7; break; // ORI d8
	case 0xF7: cycle_count = rst(6); break; // RST 6
	case 0xF8: cycle_count = ret_cond(issign()); break; // RM
	case 0xF9: sp = hl.getreg(); cycle_count = 5; break; // SPHL
	case 0xFA: cycle_count = jump(getimmWord(), issign()); break; // JM a16
	case 0xFB: interrupt_delay = true; cycle_count = 4; break; // EI
	case 0xFC: cycle_count = call(issign()); break; // CM a16
	case 0xFD: cycle_count = call(); break; // *CALL a16
	case 0xFE: cmp(getimmByte()); cycle_count = 7; break; // CPI d8
	case 0xFF: cycle_count = rst(7); break; // RST 7
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