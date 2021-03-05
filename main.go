package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

func init() {
	log.SetFlags(log.Lmicroseconds | log.LstdFlags)
}

func main() {

	var (
		cpuprofile  = flag.String("cpuprofile", "", "write cpu profile to file")
		memprofile  = flag.String("memprofile", "", "write memory profile to file")
	)
	flag.Parse()

	// CPU profile
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	// Memory profile
	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer func() {
			defer f.Close() // error handling omitted for example
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatal("could not write memory profile: ", err)
			}
		}()
	}
	var cpu CPU
	AddressSpace := make(Memory, MaxMemorySize) // Allocate addressable memory space

	// Load reset vector
	AddressSpace[0xfffc] = 0x00 // lo byte address
	AddressSpace[0xfffd] = 0x02 // hi byte address

	// ROM program
	prg := [...]Byte{
		NOP.code,       // No operation (pause 2 cycles)
		SEC.code,       // Set Carry flag
		SEI.code,       // Set InterruptDisabled flag
		CLI.code,       // Clear InterruptDisabled flag
		CLC.code,       // Clear Carry flag
		LDA.code, 0x42, // Load 0x42 -> A register
		AND.code, 0x0,  // AND value in A with 0x0 (side effect: set Zero flag)
		HLT.code,       // Halt CPU
	}

	// Load program at addr 0x0200
	copy(AddressSpace[0x0200:], prg[:])

	// Reset processor
	cpu.Reset()
	cpu.DumpState()

	// Start Fetch/Execute loop
	cpu.FetchAndExecuteLoop(AddressSpace[:])
}

type Byte uint8
type Word uint16

const (
	MaxMemorySize = 1 << 16                // Memory size: 64K 8-bit bytes
	CycleTick     = 250 * time.Millisecond // CPU frequency: 4Hz
	// CycleTick = 1 * time.Microsecond // CPU frequency: 1MHz
)

type Memory = []Byte

type CPU struct {
	cycleCounter uint64

	// Control registers set
	PC    Word // Program counter
	SP    Word // Stack pointer
	Flags Word // Status flags

	// User register set
	RegA Byte // Accumulator
	RegX Byte // Index
	RegY Byte // Output
}

func (cpu *CPU) FetchAndExecuteLoop(mem Memory) {
	// Use PC to fetch addr of the RST vector
	lo := cpu.FetchNextInstruction(mem)
	cpu.DumpState()
	hi := cpu.FetchNextInstruction(mem)
	cpu.DumpState()
	cpu.PC = (Word(hi) << 8) | Word(lo)
	log.Printf("Set PC to RST vector address: 0x%04X", cpu.PC)

	// Execute forever
	for {
		inst := cpu.FetchNextInstruction(mem)
		op := cpu.Decode(inst)
		cpu.Eval(op, mem)
		cpu.DumpState()
	}
}

func (cpu *CPU) fetchByte(mem Memory, addr Word) Byte {
	// Increment cycle count
	cpu.cycleCounter++
	time.Sleep(1 * CycleTick)
	val := mem[int(addr)]
	log.Printf("Fetched 0x%02X from 0x%04X [1 cycle]", val, addr)
	return val
}

func (cpu *CPU) FetchNextInstruction(mem Memory) Byte {
	instr := cpu.fetchByte(mem, cpu.PC)
	cpu.PC++
	return instr
}

func (cpu *CPU) Decode(instr Byte) OpCode {
	// Use look-up table to figure out OpCode based on the instruction
	if op, ok := isa[instr]; ok {
		log.Printf("Decoded instruction 0x%02X as %v", instr, op.mnemonic)
		return op
	}
	log.Printf("Failed to decode instruction: 0x%02X", instr)
	return HLT
}

func (cpu *CPU) Eval(op OpCode, mem Memory) {
	// Load and execute microcode
	op.microcode(cpu, mem, op)
}

func (cpu *CPU) Reset() {
	// Clear flags first
	cpu.Flags = 0

	// Set all general purpose registers to Zero (0)
	cpu.RegX, cpu.RegY = 0, 0
	cpu.setRegA(0)

	// Set stack pointer
	cpu.SP = 0x01ff

	// Set address for the reset vecor
	cpu.PC = 0xfffc
}

func (cpu *CPU) setRegA(val Byte) {
	cpu.RegA = val
	if cpu.RegA == 0 {
		cpu.SetFlag(Zero)
	} else {
		cpu.ClearFlag(Zero)
	}
}

func (cpu CPU) DumpState() {
	//fmt.Print("\033[H\033[2J") // clear screen
	fmt.Fprintf(os.Stderr, "===============================\n")
	fmt.Fprintf(os.Stderr, "====       CPU STATE       ====\n")
	fmt.Fprintf(os.Stderr, "===============================\n")
	fmt.Fprintf(os.Stderr, "==   Flags: C|Z|I|D|B|O|N    ==\n")
	fmt.Fprintf(os.Stderr, "==          %c|%c|%c|%c|%c|%c|%c    ==\n",
		cpu.checkFlag(Carry), cpu.checkFlag(Zero), cpu.checkFlag(InterruptDisabled),
		cpu.checkFlag(DecimalMode), cpu.checkFlag(BreakCommand), cpu.checkFlag(Overflow),
		cpu.checkFlag(Negative))
	fmt.Fprintf(os.Stderr, "==      PC:        0x%04X    ==\n", cpu.PC)
	fmt.Fprintf(os.Stderr, "==      SP:        0x%04X    ==\n", cpu.SP)
	fmt.Fprintf(os.Stderr, "==       A:        0x%04X    ==\n", cpu.RegA)
	fmt.Fprintf(os.Stderr, "==       X:        0x%04X    ==\n", cpu.RegX)
	fmt.Fprintf(os.Stderr, "==       Y:        0x%04X    ==\n", cpu.RegY)
	fmt.Fprintf(os.Stderr, "===============================\n")
}

func (cpu CPU) checkFlag(flag Word) rune {
	if (flag & cpu.Flags) > 0 {
		return '◉'
	}
	return '○'
}

func (cpu *CPU) SetFlag(flag Word) {
	cpu.Flags |= flag
}

func (cpu *CPU) ClearFlag(flag Word) {
	cpu.Flags &^= flag
}

const (
	Carry = 1 << iota
	Zero
	InterruptDisabled
	DecimalMode
	BreakCommand
	Overflow
	Negative
)

type OpCode struct {
	code      Byte
	mode      AddrMode
	size      Byte
	cycles    uint64
	mnemonic  string
	microcode func(*CPU, Memory, OpCode)
}

type AddrMode int

const (
	Implied AddrMode = iota
	//Implicit
	//Accumulator
	Immediate
	//ZeroPage
	//ZeroPageX
	//ZeroPageY
	//Relative
	//Absolute
	//AbsoluteX
	//AbsoluteY
	//Indirect
	//IndexedIndirect
	//IndirectIndexed
)

// Known instructions
var (
	HLT = OpCode{code: 0x00, mode: Implied, size: 1, cycles: 0, mnemonic: "HLT", microcode: func(_ *CPU, _ Memory, _ OpCode) {
		log.Fatal("Halting CPU")
	}}
	NOP = OpCode{code: 0xea, mode: Implied, size: 1, cycles: 2, mnemonic: "NOP", microcode: func(cpu *CPU, mem Memory, op OpCode) {
		cpu.cycleCounter += op.cycles
		time.Sleep(time.Duration(op.cycles) * CycleTick)
		log.Printf("Executed %v [%s]", op.mnemonic, plural(int(op.cycles), "cycle"))
	}}

	// Carry flag ops
	CLC = OpCode{code: 0x18, mode: Implied, size: 1, cycles: 2, mnemonic: "CLC", microcode: func(cpu *CPU, memory Memory, op OpCode) {
		cpu.cycleCounter += op.cycles
		cpu.ClearFlag(Carry)
		time.Sleep(time.Duration(op.cycles) * CycleTick)
		log.Printf("Executed %v [%s]", op.mnemonic, plural(int(op.cycles), "cycle"))
	}}
	SEC = OpCode{code: 0x38, mode: Implied, size: 1, cycles: 2, mnemonic: "SEC", microcode: func(cpu *CPU, memory Memory, op OpCode) {
		cpu.cycleCounter += op.cycles
		cpu.SetFlag(Carry)
		time.Sleep(time.Duration(op.cycles) * CycleTick)
		log.Printf("Executed %v [%s]", op.mnemonic, plural(int(op.cycles), "cycle"))
	}}
	// Interrupt Disable flag ops
	CLI = OpCode{code: 0x58, mode: Implied, size: 1, cycles: 2, mnemonic: "CLI", microcode: func(cpu *CPU, memory Memory, op OpCode) {
		cpu.cycleCounter += op.cycles
		cpu.ClearFlag(InterruptDisabled)
		time.Sleep(time.Duration(op.cycles) * CycleTick)
		log.Printf("Executed %v [%s]", op.mnemonic, plural(int(op.cycles), "cycle"))
	}}
	SEI = OpCode{code: 0x78, mode: Implied, size: 1, cycles: 2, mnemonic: "SEI", microcode: func(cpu *CPU, memory Memory, op OpCode) {
		cpu.cycleCounter += op.cycles
		cpu.SetFlag(InterruptDisabled)
		time.Sleep(time.Duration(op.cycles) * CycleTick)
		log.Printf("Executed %v [%s]", op.mnemonic, plural(int(op.cycles), "cycle"))
	}}

	// LDA -- Immediate
	LDA = OpCode{code: 0xa9, mode: Immediate, size: 2, cycles: 2, mnemonic: "LDA", microcode: func(cpu *CPU, memory Memory, op OpCode) {
		// Load immediate value into A
		cpu.setRegA(cpu.FetchNextInstruction(memory))

		// Account for the rest of the cycles
		delta := op.cycles - 1 // compensate for the memory fetch operation
		cpu.cycleCounter += delta
		time.Sleep(time.Duration(delta) * CycleTick)
		log.Printf("Executed %v [%s]", op.mnemonic, plural(int(op.cycles), "cycle"))
	}}

	// AND -- Immediate
	AND = OpCode{code: 0x29, mode: Immediate, size: 2, cycles: 2, mnemonic: "AND", microcode: func(cpu *CPU, memory Memory, op OpCode) {
		// AND immediate operand with content of A
		cpu.setRegA(cpu.RegA & cpu.FetchNextInstruction(memory))

		// Account for the rest of the cycles
		delta := op.cycles - 1 // compensate for the memory fetch operation
		cpu.cycleCounter += delta
		time.Sleep(time.Duration(delta) * CycleTick)
		log.Printf("Executed %v [%s]", op.mnemonic, plural(int(op.cycles), "cycle"))
	}}
)

var isa = map[Byte]OpCode{
	HLT.code: HLT,
	NOP.code: NOP,
	CLC.code: CLC,
	SEC.code: SEC,
	CLI.code: CLI,
	SEI.code: SEI,
	// LDA
	LDA.code: LDA,
	// AND
	AND.code: AND,
}

func plural(n int, name string) string {
	suf := ""
	if n != 1 {
		suf = "s"
	}

	return fmt.Sprintf("%d %s%s", n, name, suf)
}

// Helper to handle errors
func errHandle(err error, msg string) {
	if err != nil {
		log.Fatalf(msg+": %v", err)
	}
}

