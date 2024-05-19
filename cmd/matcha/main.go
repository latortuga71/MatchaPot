package main

import (
	"bufio"
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
	Pid                 int
	BaseAddress         uint64
	TotalBreakPoints    uint64
	BreakPointsHit      uint64
	PreviousCoverageHit uint64
	FuzzCases           uint64
	Crashes             uint64
	BreakPointAddresses []uint64
	Path                string
	CurrentFuzzCase     string
	Corpus              [][]byte
	BreakPoints         map[uint64][]byte
}

func NewState(path string, baseAddress uint64) *State {
	state := &State{
		Path:                path,
		BreakPoints:         make(map[uint64][]byte),
		BaseAddress:         0x0,
		PreviousCoverageHit: 0,
	}
	// Get Base Address
	/*
		fptr, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		f, err := elf.NewFile(fptr)
		if err != nil {
			log.Fatal(err)
		}
	*/
	state.BaseAddress = baseAddress
	if state.BaseAddress == 0 {
		log.Fatal("FAILED TO GET BASE ADDRESS")
	}
	fmt.Printf("BaseAddress 0x%x \n", state.BaseAddress)
	return state
}

func (s *State) Spawn(arg string) int {
	path := s.Path
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0755)
	cmd := exec.Command(path)
	cmd.Args = []string{path, arg}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Wait()
	pid := cmd.Process.Pid
	//log.Printf("Debugging Pid... %s (%d)", path, pid)
	s.Pid = pid
	return pid
}

func (s *State) GetBreakPointAddresses(path string) []uint64 {
	bpFile, err := os.OpenFile(path, os.O_RDONLY, 0755)
	if err != nil {
		log.Fatal(err)
	}
	defer bpFile.Close()
	bps := make([]uint64, 0)
	scanner := bufio.NewScanner(bpFile)
	for scanner.Scan() {
		text := strings.Replace(strings.TrimSuffix(scanner.Text(), "\n"), "0x", "", -1)
		offset, err := strconv.ParseUint(text, 16, 64)
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Fprintf(os.Stderr, "DEBUG: Setting BP 0x%X\n", s.BaseAddress+offset)
		breakPoint := s.BaseAddress + offset
		bps = append(bps, breakPoint)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return bps
}

func (s *State) InstrumentProcess(firstTime bool) {
	if firstTime {
		for _, breakPoint := range s.BreakPointAddresses {
			originalBytes := SetBP(s.Pid, uintptr(breakPoint))
			s.BreakPoints[breakPoint] = originalBytes
			s.TotalBreakPoints++
		}
	} else {
		for key, _ := range s.BreakPoints {
			SetBP(s.Pid, uintptr(key))
		}
	}
}

func (s *State) ContinueExec() (bool, syscall.Signal) {
	ContinueExec(s.Pid)
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(s.Pid, &ws, syscall.WALL, nil)
	if err != nil {
		log.Fatal("ERROR: State:::ContinueExec:::Syscall.Wait4 ", err)
	}
	if ws.Exited() {
		//fmt.Fprintf(os.Stderr, "\nDEBUG: Child Exited\n")
		return false, 0
	}
	if ws.Signaled() {
		fmt.Fprintf(os.Stderr, "\nDEBUG: SIGNAL")
		panic("HANDLE SIGNALS?")
	}

	// Handle Possible CRASHES Issues Here
	if ws.StopSignal() == syscall.SIGSEGV {
		return true, syscall.SIGSEGV
	}
	return true, 0
}

func (s *State) UpdateCoverage() {
	r := GetReg(s.Pid)
	pc := r.PC() - 1
	if _, ok := s.BreakPoints[pc]; !ok {
		fmt.Printf("Not a breakpoint 0x%x\n", pc)
		os.Exit(-1)
		return
	}
	//fmt.Printf("BreakPoint PC -> 0x%x\n", pc)
	s.BreakPointsHit++
	originalBytes := s.BreakPoints[pc]
	DelBP(s.Pid, uintptr(pc), originalBytes)
	SubRip(s.Pid)
	// remove breakpoint from hashmap
	delete(s.BreakPoints, pc)
}

func (s *State) PrintStats() {
	percent := (float32(s.BreakPointsHit) / float32(s.TotalBreakPoints)) * 100.0
	now := time.Now()
	elapsed := now.Sub(START_TIME)
	//fmt.Printf("INFO: Matcha Stats %s %d\n", s.Path, s.Pid)
	fmt.Printf("INFO: Crashes %d Iterations %d Coverage %d/%d %2f Cases Per Second %f Seconds %f Hours %f\n", s.Crashes, s.FuzzCases, s.BreakPointsHit, s.TotalBreakPoints, percent, float64(s.FuzzCases)/elapsed.Seconds(), elapsed.Seconds(), elapsed.Hours())
	//fmt.Printf("INFO: Iterations %d\n", s.FuzzCases)

}

func (s *State) CoverageLoop() {
	for {
		doBreak, signal := s.ContinueExec()
		if doBreak {
			if signal == syscall.SIGSEGV {
				// record crash
				fmt.Fprintf(os.Stderr, "Crash!\n")
				s.Crashes++
				break
			}
		} else {
			// child exited
			break
		}
		s.UpdateCoverage()
	}
}

var START_TIME time.Time

func main() {
	fState := NewState("./cli_test", 0x400000)
	fState.BreakPointAddresses = fState.GetBreakPointAddresses("cli_blocks.txt")
	panic("Initialize Corpus")
	START_TIME = time.Now()
	runtime.LockOSThread()
	for {
		fState.Spawn("cli_test_case.txt")
		fState.InstrumentProcess(fState.FuzzCases == 0)
		// since were testing an example cli program we can just loop break points until exit.
		// if it was a server we would set a permenant breakpoint at the start of the parsing of the payload
		// and that would be the loop starting point so that would be a custom case
		fState.CoverageLoop()
		if fState.BreakPointsHit > fState.PreviousCoverageHit {
			fState.PreviousCoverageHit = fState.BreakPointsHit
			// Add Fuzz Case To Corpus
		}
		fState.FuzzCases++
		// Query Corpus For New FuzzCase
		// Re Run Loop
		fState.PrintStats()
	}
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
		log.Fatal("ERROR: DelBP::PtracePokeData ", err)
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
		log.Fatal("ERROR: ContinueExec::PtraceCont ", err)
	}
}

func GetReg(pid int) syscall.PtraceRegs {
	var reg syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &reg)
	if err != nil {
		log.Fatal("ERROR: GetReg ", err)
	}
	return reg
}

func GetPC(pid int) uintptr {
	var reg syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &reg)
	if err != nil {
		log.Fatal("ERROR: GetPC ", err)
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
