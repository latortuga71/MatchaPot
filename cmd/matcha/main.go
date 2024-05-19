package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type State struct {
	Pid              int
	TotalBreakPoints uint64
	BreakPointsHit   uint64
	BaseAddress      uint64
	Path             string
	BreakPoints      map[uint64][]byte
}

func NewState(path string) *State {
	state := &State{
		Path:        path,
		BreakPoints: make(map[uint64][]byte),
		BaseAddress: 0x0,
	}
	// Get Base Address
	fptr, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	f, err := elf.NewFile(fptr)
	if err != nil {
		log.Fatal(err)
	}
	for i := range f.Sections {
		if f.Sections[i].Type == 1 {
			state.BaseAddress = f.Sections[i].Addr
			break
		}
	}
	if state.BaseAddress == 0 {
		log.Fatal("FAILED TO GET BASE ADDRESS")
	}
	return state
}

func (s *State) Spawn() int {
	path := s.Path
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0755)
	cmd := exec.Command(path)
	cmd.Args = []string{path}
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Wait()
	pid := cmd.Process.Pid
	log.Printf("Debugging Pid... %s (%d)", path, pid)
	s.Pid = pid
	return pid
}

func (s *State) InstrumentProcess(path string) {
	bpFile, err := os.OpenFile(path, os.O_RDONLY, 0755)
	if err != nil {
		log.Fatal(err)
	}
	defer bpFile.Close()
	scanner := bufio.NewScanner(bpFile)
	for scanner.Scan() {
		text := strings.Replace(strings.TrimSuffix(scanner.Text(), "\n"), "0x", "", -1)
		offset, err := strconv.ParseUint(text, 16, 64)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Setting BP 0x%X\n", s.BaseAddress+offset)
		breakPoint := s.BaseAddress + offset
		if breakPoint == 0x401681 {
			log.Fatal(":er")
		}
		originalBytes := SetBP(s.Pid, uintptr(breakPoint))
		s.BreakPoints[breakPoint] = originalBytes
		s.TotalBreakPoints++
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func (s *State) ContinueExec() {
	ContinueExec(s.Pid)
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(s.Pid, &ws, syscall.WALL, nil)
	if err != nil {
		log.Fatal("ERROR: State:::ContinueExec:::Syscall.Wait4 ", err)
	}
}

func (s *State) UpdateCoverage() {
	r := GetReg(s.Pid)
	pc := r.PC() - 1
	if _, ok := s.BreakPoints[pc]; !ok {
		fmt.Printf("Not a breakpoint 0x%x\n", pc)
		os.Exit(-1)
		return
	}
	fmt.Printf("BreakPoint PC -> 0x%x\n", pc)
	s.BreakPointsHit++
	originalBytes := s.BreakPoints[pc]
	DelBP(s.Pid, uintptr(pc), originalBytes)
	SubRip(s.Pid)
}

func (s *State) CoverageLoop() {
	for {
		// Continue
		s.ContinueExec()
		// Hit BreakPoint
		s.UpdateCoverage()
		// Update Converage
	}
}

func main() {
	fState := NewState("./test")
	runtime.LockOSThread()
	fState.Spawn()
	fState.InstrumentProcess("./blocks.txt")
	fState.CoverageLoop()
	runtime.UnlockOSThread()
}

func SetBP(pid int, address uintptr) []byte {
	original := make([]byte, 1)
	_, err := syscall.PtracePeekData(pid, address, original)
	if err != nil {
		log.Fatal("ERROR: SetBP:::PracePeekData ", err)
	}
	_, err = syscall.PtracePokeData(pid, address, []byte{0xCC})
	if err != nil {
		log.Fatal("ERROR: SetBP:::PracePokeData ", err)
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
		input := "./test"
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
