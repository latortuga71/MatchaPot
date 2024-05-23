package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"matcha/internal/snapshot"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type State struct {
	Pid                  int
	BaseAddress          uint64
	TotalBreakPoints     uint64
	BreakPointsHit       uint64
	PreviousCoverageHit  uint64
	FuzzCases            uint64
	Crashes              uint64
	SnapshotAddress      uint64
	SnapshotAddressBytes []byte
	RestoreAddressBytes  []byte
	RestoreAddress       uint64
	SnapshotData         snapshot.Snapshot
	BreakPointAddresses  []uint64
	Path                 string
	CurrentFuzzCase      []byte
	Corpus               Corpus
	BreakPoints          map[uint64][]byte
}

type InMemoryCorpus struct {
	CorpusBuffers [][]byte
	CorpusDir     string
	CorpusCount   int
}

func (c *InMemoryCorpus) InitCorpus() {
	var err error
	entry, err := os.ReadDir("./corpus")
	if err != nil {
		log.Fatal(err)
	}
	c.CorpusBuffers = make([][]byte, c.CorpusCount)
	for _, e := range entry {
		if e.IsDir() {
			continue
		}
		content, err := os.ReadFile(fmt.Sprintf("./corpus/%s", e.Name()))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(len(content))
		c.CorpusBuffers = append(c.CorpusBuffers, content)
		c.CorpusCount++
	}
}

func (c *InMemoryCorpus) Count() int {
	return c.CorpusCount
}

func (c *InMemoryCorpus) GetCaseByIdx(idx int) []byte {
	return c.CorpusBuffers[idx]
}
func (c *InMemoryCorpus) AddToCorpus(data []byte) {
	c.CorpusBuffers = append(c.CorpusBuffers, data)
	c.CorpusCount++
	os.WriteFile(fmt.Sprintf("./corpus/%d.bin", c.CorpusCount), data, 0644)
}

type OnDiskCorpus struct {
	CurrentFuzzCasePath string
	CurrentFuzzCaseDir  string
}

func NewOnDiskCorpus() *OnDiskCorpus {
	return &OnDiskCorpus{}
}

type Corpus interface {
	InitCorpus()
	Count() int
	GetCaseByIdx(int) []byte
	AddToCorpus([]byte)
}

func NewState(path string, baseAddress uint64, snapshotAddress uint64, restoreAddress uint64) *State {
	state := &State{
		Path:                path,
		BreakPoints:         make(map[uint64][]byte),
		BaseAddress:         0x0,
		PreviousCoverageHit: 0,
		SnapshotAddress:     snapshotAddress,
		RestoreAddress:      restoreAddress,
		Corpus:              &InMemoryCorpus{},
	}
	state.BaseAddress = baseAddress
	if state.BaseAddress == 0 {
		log.Fatal("FAILED TO GET BASE ADDRESS")
	}
	fmt.Printf("BaseAddress 0x%x \n", state.BaseAddress)
	return state
}

func (s *State) Spawn(args []string) int {
	path := s.Path
	//devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0755)
	cmd := exec.Command(path)
	cmd.Args = []string{path}
	cmd.Args = append(cmd.Args, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	//cmd.Stdout = devNull
	//cmd.Stderr = devNull
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
	if ws.Signaled() {
		fmt.Fprintf(os.Stderr, "\nDEBUG: SIGNAL")
		panic("HANDLE SIGNALS?")
	}
	// Handle Possible CRASHES Issues Here
	if ws.StopSignal() == syscall.SIGSEGV {
		panic("SEGFAULT")
		return true, syscall.SIGSEGV
	}
	if ws.StopSignal() == syscall.SIGABRT {
		panic("SEGABORT")
		return true, syscall.SIGSEGV
	}
	if ws.StopSignal() == syscall.SIGBUS {
		panic("SEGBUS")
		return true, syscall.SIGBUS
	}
	if ws.StopSignal() == syscall.SIGTRAP {
		// a breakpoint
		return false, syscall.SIGTRAP
	}
	if ws.Exited() {
		return false, 0
	}
	log.Fatalf("UNKNOWN SIGNAL %d", ws.StopSignal())
	return false, 0
}

func (s *State) UpdateCoverage() bool {
	r := GetReg(s.Pid)
	pc := r.PC() - 1
	if s.RestoreAddress == pc {
		return true
	}
	if _, ok := s.BreakPoints[pc]; !ok {
		log.Fatalf("Not a breakpoint 0x%x\n", pc)
	}
	s.BreakPointsHit++
	originalBytes := s.BreakPoints[pc]
	DelBP(s.Pid, uintptr(pc), originalBytes)
	SubRip(s.Pid)
	delete(s.BreakPoints, pc)
	return false
}

func (s *State) PrintStats() {
	percent := (float32(s.BreakPointsHit) / float32(s.TotalBreakPoints)) * 100.0
	now := time.Now()
	elapsed := now.Sub(START_TIME)
	fmt.Printf("INFO: Crashes %d Iterations %d Coverage %d/%d %2f Cases Per Second %f Seconds %f Hours %f Corpus %d\n", s.Crashes, s.FuzzCases, s.BreakPointsHit, s.TotalBreakPoints, percent, float64(s.FuzzCases)/elapsed.Seconds(), elapsed.Seconds(), elapsed.Hours(), s.Corpus.Count())
}

func (s *State) RestoreSnapshot() {
	SetReg(s.Pid, s.SnapshotData.Registers)
	for i := range s.SnapshotData.Memory {
		snapshot.WriteRegionToProcess(s.Pid, s.SnapshotData.Memory[i])
	}
}

func (s *State) TakeSnapshot() {
	fmt.Println("Taking Child Snapshot")
	s.SnapshotAddressBytes = SetBP(s.Pid, uintptr(s.SnapshotAddress))
	s.RestoreAddressBytes = SetBP(s.Pid, uintptr(s.RestoreAddress))
	// Run Until We Hit Above Snapshot BreakPoint
	s.ContinueExec()
	r := GetReg(s.Pid)
	pc := r.PC() - 1
	if pc != s.SnapshotAddress {
		log.Panicf("ERROR: Wrong breakpoint wanted 0x%x got 0x%x", s.SnapshotAddress, pc)
	}

	DelBP(s.Pid, uintptr(pc), s.SnapshotAddressBytes)
	SubRip(s.Pid)
	// Set BreakPoints for the whole process now to get coverage
	fmt.Println("Instrumenting Child")
	s.InstrumentProcess(true)
	s.SnapshotData = snapshot.NewSnapshot(s.Pid)
	fmt.Println("Snapshot Complete")
}

func (s *State) CoverageLoop() {
	for {
		doBreak, signal := s.ContinueExec()
		if doBreak {
			if signal == syscall.SIGSEGV {
				s.Crashes++
				//s.Corpus.WriteCrashToDisk(int(s.Crashes), []byte(s.CurrentFuzzCase))
				break
			}
		} else {
			// child exited
			break
		}
		s.UpdateCoverage()
	}
}

func (s *State) RestoreLoop() bool {
	for {
		ContinueExec(s.Pid)
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(s.Pid, &ws, syscall.WALL, nil)
		if err != nil {
			log.Fatal("ERROR: State:::ContinueExec:::Syscall.Wait4 ", err)
		}
		if ws.Signaled() {
			fmt.Fprintf(os.Stderr, "\nDEBUG: SIGNAL")
			panic("HANDLE SIGNALS?")
		}
		switch ws.StopSignal() {
		case syscall.SIGSEGV:
			panic("SEGFAULT")
		case syscall.SIGTRAP:
			return s.UpdateCoverage()
		case syscall.SIGABRT:
			panic("SIGRABORT")
		case syscall.SIGBUS:
			panic("SIGBUS")
		default:
			if ws.Exited() {
				panic("child exited")
			}
			log.Fatalf("UNKNOWN SIGNAL %d", ws.StopSignal())
		}
	}
}

var START_TIME time.Time

func Mutate(data []byte) {
	counter := 0
	// Mutate 5% of the bytes
	mutationsPerCycle := 5 * len(data) / 100
	for {
		randStrat := rand.Intn(5-0) + 0
		switch randStrat {
		case 0:
			randBitFlip := rand.Intn((7+1)-0) + 0
			randByte := rand.Intn((len(data))-0) + 0
			data[randByte] ^= (1 << randBitFlip)
		case 1:
			randByte := rand.Intn((len(data))-0) + 0
			randByteFlip := rand.Intn(255-0) + 0
			data[randByte] ^= byte(randByteFlip)
		case 2:
			randByte := rand.Intn((len(data))-0) + 0
			randByteInsert := rand.Intn(255-0) + 0
			data[randByte] = byte(randByteInsert)
		case 3:
			randByte := rand.Intn((len(data))-0) + 0
			data[randByte] = 0x0
		case 4:
			randByte := rand.Intn((len(data))-0) + 0
			data[randByte] = 0xFF
		default:
		}
		counter++
		if counter > mutationsPerCycle {
			break
		}
	}
}

func (s *State) FindEgg(egg string) (int, uint64, int) {
	//panic("Find every possible location for our buffer and replace it")
	for i, memory := range s.SnapshotData.Memory {
		if offset := bytes.LastIndex(memory.RawData, []byte(egg)); offset != -1 {
			return i, memory.Start + uint64(offset), offset
		}
	}
	return 0, 0, 0
}

func (s *State) ReadBufferFromProcess(address uint64, buffer []byte) {
	_, err := syscall.PtracePeekData(s.Pid, uintptr(address), buffer)
	if err != nil {
		log.Fatal("ERROR: ReadBufferFromProcess:::PracePeekData ", err)
	}
	//fmt.Println(string(buffer))
}

func (s *State) WriteBufferToProcess(address uint64, buffer []byte) {
	path := fmt.Sprintf("/proc/%d/mem", s.Pid)
	memPtr, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer memPtr.Close()
	_, err = memPtr.Seek(int64(address), 0)
	if err != nil {
		log.Fatal(err)
	}
	_, err = memPtr.Write(buffer)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	rand.Seed(0x71717171)
	fState := NewState("./cli_test", 0x400000, 0x4012A9, 0x40138A)
	fState.BreakPointAddresses = fState.GetBreakPointAddresses("cli_blocks.txt")
	buffer, err := os.ReadFile("./egg_payload.txt")
	if err != nil {
		log.Fatal(err)
	}
	fState.Corpus.InitCorpus()
	START_TIME = time.Now()
	runtime.LockOSThread()
	fState.Spawn([]string{"./egg_payload.txt"})
	fState.TakeSnapshot()
	regionIdx, memoryAddress, _ := fState.FindEgg(string(buffer))
	if regionIdx == 0 || memoryAddress == 0 {
		panic("FAILED TO FIND EGG")
	}
	//fmt.Printf("0x%x %s\n", fState.SnapshotData.Memory[regionIdx].Start, fState.SnapshotData.Memory[regionIdx].Name)
	//log.Fatalf("FOUND EGG 0x%x\n", memoryAddress)
	for {
		//tmp := make([]byte, bufferSz)
		//fState.ReadBufferFromProcess(memoryAddress, tmp)
		// pick something from corpus
		nextCase := rand.Intn(fState.Corpus.Count()) % fState.Corpus.Count()
		//fmt.Println(nextCase)
		fState.CurrentFuzzCase = fState.Corpus.GetCaseByIdx(nextCase)
		// Mutate Current Fuzz Case Buffer
		Mutate(fState.CurrentFuzzCase)
		// write fuzz case to memory
		fState.WriteBufferToProcess(memoryAddress, fState.CurrentFuzzCase)
		// Continue Execution
		//fmt.Println("Before Continue")
		//snapshot.MemoryDump(fState.Pid)
		if fState.RestoreLoop() {
			fState.RestoreSnapshot()
			fState.FuzzCases++
		}
		if fState.BreakPointsHit > fState.PreviousCoverageHit {
			fState.PreviousCoverageHit = fState.BreakPointsHit
			fState.Corpus.AddToCorpus(fState.CurrentFuzzCase)
		}
		fState.PrintStats()
		if fState.CurrentFuzzCase[0] == 0x41 && fState.CurrentFuzzCase[1] == 0x42 && fState.CurrentFuzzCase[2] == 0x43 {
			panic("A HIT")
		}
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

func SetReg(pid int, r syscall.PtraceRegs) {
	err := syscall.PtraceSetRegs(pid, &r)
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
