package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	fmt.Println("Matcha")
	// Spawn Process With Args
	debugger()
	// Insert BreakPoints At Basic Blocks
	// Save BreakPoints, save original bytes
	// Continue Execution
	// If Break Remove BreakPoint From List
	// Update Stats
	// Callbacks on breakpoints can be used to modify buffers and fuzz
	// so we put a breakpoint after something returns and modify the buffer for example
	// if process exists
	// loop but with the same breakpoint list
}

func SetBP(pid int, address uintptr) []byte {
	original := make([]byte, 1)
	_, err := syscall.PtracePeekData(pid, address, original)
	if err != nil {
		log.Fatal(err)
	}
	_, err = syscall.PtracePokeData(pid, address, []byte{0xCC})
	if err != nil {
		log.Fatal(err)
	}
	return original
}

func DelBP(pid int, address uintptr, originalBytes []byte) {
	_, err := syscall.PtracePokeData(pid, address, originalBytes)
	if err != nil {
		log.Fatal(err)
	}
}

func SingleStep(pid int) {
	err := syscall.PtraceSingleStep(pid)
	if err != nil {
		log.Fatal(err)
	}
}

func ContinueExec(pid int) {
	err := syscall.PtraceCont(pid, 0)
	if err != nil {
		log.Fatal(err)
	}
}

func GetReg(pid int) syscall.PtraceRegs {
	var reg syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &reg)
	if err != nil {
		log.Fatal(err)
	}
	return reg
}

func debugger() {
	input := "who"
	cmd := exec.Command(input)
	cmd.Args = []string{input}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Wait()
	log.Printf("State: %v\n", err)
	log.Println("Restarting...")
	err = syscall.PtraceCont(cmd.Process.Pid, 0)
	if err != nil {
		log.Panic(err)
	}
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(cmd.Process.Pid, &ws, syscall.WALL, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Exited: %v\n", ws.Exited())
	log.Printf("Exit status: %v\n", ws.ExitStatus())
}
