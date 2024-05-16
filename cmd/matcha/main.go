package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

func main() {
	fmt.Println("Matcha")
	// Spawn Process With Args
	debuggerLoop()
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

func GetPC(pid int) uintptr {
	var reg syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &reg)
	if err != nil {
		log.Fatal(fmt.Sprintf("ERROR: GETPC -> %v", err))
	}
	return uintptr(reg.PC())
}

func SetPC(pid int, pc uint64) {
	var regs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &regs)
	if err != nil {
		log.Fatal(err)
	}
	regs.SetPC(pc)
	err = syscall.PtraceSetRegs(pid, &regs)
	if err != nil {
		log.Fatal(err)
	}
}

func SubRip(pid int) {
	var regs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &regs)
	if err != nil {
		log.Fatal(err)
	}
	regs.Rip -= 1
	err = syscall.PtraceSetRegs(pid, &regs)
	if err != nil {
		log.Fatal(err)
	}
}

func debuggerLoop() {
	runtime.LockOSThread()
	iterations := 0
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0755)
	for {
		input := "who"
		cmd := exec.Command(input)
		cmd.Args = []string{input}
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
		err := cmd.Start()
		if err != nil {
			log.Fatal(err)
		}
		err = cmd.Wait()
		pid := cmd.Process.Pid
		log.Printf("Debugging Pid... %d", pid)
		//log.Printf("State: %v\n", err)
		breakPointAddress := uintptr(GetPC(pid) + 0x8)
		originalBytes := SetBP(pid, breakPointAddress)
		ContinueExec(pid)
		var ws syscall.WaitStatus
		_, err = syscall.Wait4(pid, &ws, syscall.WALL, nil)
		if err != nil {
			log.Println("PTRACE ERROR 1")
			log.Fatal(err)
		}
		DelBP(pid, breakPointAddress, originalBytes)
		SubRip(pid)
		ContinueExec(pid)
		_, err = syscall.Wait4(pid, &ws, syscall.WALL, nil)
		if err != nil {
			log.Println("PTRACE ERROR 2")
			log.Fatal(err)
		}
		//log.Printf("Exited: %v\n", ws.Exited())
		//log.Printf("Exit status: %v\n", ws.ExitStatus())
		log.Printf("Iterations %v\n", iterations)
		iterations++
		time.Sleep(time.Millisecond * 500)
	}
	runtime.UnlockOSThread()
}
