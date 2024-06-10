package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"flag"
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

var START_TIME time.Time

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
	DevNull              *os.File
}

func (c *Corpus) InitCorpus(corpusDir string, crashDir string) {
	var err error
	c.CorpusDir = corpusDir
	c.CrashDir = crashDir
	entry, err := os.ReadDir(corpusDir)
	if err != nil {
		log.Fatal(err)
	}
	c.CorpusBuffers = make([][]byte, c.CorpusCount)
	for _, e := range entry {
		if e.IsDir() {
			continue
		}
		content, err := os.ReadFile(fmt.Sprintf("%s/%s", corpusDir, e.Name()))
		if err != nil {
			log.Fatal(err)
		}
		c.CorpusBuffers = append(c.CorpusBuffers, content)
		c.CorpusCount++
	}
	fmt.Printf("Loaded %d items into corpus\n", c.CorpusCount)
}
func (c *Corpus) GetCaseByIdx(idx int) []byte {
	return c.CorpusBuffers[idx]
}

func (c *Corpus) WriteFuzzCaseToDisk(path string, buffer []byte) {
	err := os.WriteFile(path, buffer, 0644)
	if err != nil {
		panic(err)
	}
}

func (c *Corpus) AddToCorpus(data []byte) {
	c.CorpusBuffers = append(c.CorpusBuffers, data)
	c.CorpusCount++
	err := os.WriteFile(fmt.Sprintf("%s/%d.bin", c.CorpusDir, c.CorpusCount), data, 0644)
	if err != nil {
		panic(err)
	}

}
func (c *Corpus) WriteCrashToDisk(data []byte) {
	hash := md5.Sum(data)
	name := hex.EncodeToString(hash[:])
	err := os.WriteFile(fmt.Sprintf("./%s/%s.bin", c.CrashDir, name), data, 0644)
	if err != nil {
		panic(err)
	}
}

type Corpus struct {
	CorpusBuffers [][]byte
	CorpusDir     string
	CrashDir      string
	CorpusCount   int
}

func NewState(path string, baseAddress uint64, snapshotAddress uint64, restoreAddress uint64) *State {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0755)
	if err != nil {
		panic(err)
	}
	state := &State{
		Path:                path,
		BreakPoints:         make(map[uint64][]byte),
		BaseAddress:         0x0,
		PreviousCoverageHit: 0,
		SnapshotAddress:     snapshotAddress,
		RestoreAddress:      restoreAddress,
		DevNull:             devNull,
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
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stder
	cmd.Stdout = s.DevNull
	cmd.Stderr = s.DevNull
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
func (s *State) CoverageLoop() bool {
	for {
		exited, signal := s.ContinueExec()
		// child exited spawn new
		if exited {
			break
		} else {
			// handle a segfault by adding to corpus as well as writing the crash to disk
			if signal == syscall.SIGSEGV {
				s.Corpus.WriteCrashToDisk(s.CurrentFuzzCase)
				s.Corpus.AddToCorpus(s.CurrentFuzzCase)
				s.Crashes++
				break
			}
		}
		if s.UpdateCoverage() {
			return true
		}
	}
	return false
}

func (s *State) ContinueExec() (bool, syscall.Signal) {
	ContinueExec(s.Pid)
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(s.Pid, &ws, syscall.WALL, nil)
	if err != nil {
		log.Fatal("ERROR: State:::ContinueExec:::Syscall.Wait4 ", err)
	}
	// if process exited handle that
	if ws.Exited() {
		return true, -1
	}
	// if we got a signal could mean a crash handle that
	switch ws.StopSignal() {
	case syscall.SIGSEGV:
		return false, syscall.SIGSEGV
	case syscall.SIGBUS:
		return false, syscall.SIGBUS
	case syscall.SIGABRT:
		return false, syscall.SIGABRT
	case syscall.SIGTRAP:
		return false, syscall.SIGTRAP
	default:
		return false, syscall.Signal(-1)
	}
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
	fmt.Printf("INFO: Crashes %d Iterations %d Coverage %d/%d %2f Cases Per Second %f Seconds %f Hours %f Corpus %d\n", s.Crashes, s.FuzzCases, s.BreakPointsHit, s.TotalBreakPoints, percent, float64(s.FuzzCases)/elapsed.Seconds(), elapsed.Seconds(), elapsed.Hours(), s.Corpus.CorpusCount)
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
	exited, signal := s.ContinueExec()
	if signal != syscall.SIGTRAP {
		if exited {
			panic("Something went wrong process should not have exited yet")
		}
	}
	r := GetReg(s.Pid)
	pc := r.PC() - 1
	if pc != s.SnapshotAddress {
		log.Panicf("ERROR: Wrong breakpoint wanted 0x%x got 0x%x", s.SnapshotAddress, pc)
	}

	DelBP(s.Pid, uintptr(pc), s.SnapshotAddressBytes)
	SubRip(s.Pid)
	s.SnapshotData = snapshot.NewSnapshot(s.Pid)
	fmt.Println("Snapshot Complete")
	// Set BreakPoints for the whole process now to get coverage
	// You Instrument AFTER the snapshot and reinstrument on the restore
	fmt.Println("Instrumenting Child")
	s.InstrumentProcess(true)
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
			os.WriteFile("./crashes/crash.bin", s.CurrentFuzzCase, 0644)
			fmt.Println("WROTE CRASH")
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

func MutateCustom(data []byte) {
	for i := range data {
		data[i] = 0x42
	}
}

func Mutate(data []byte) {
	counter := 0
	// Mutate 5% of the bytes
	// ByteFlip Bit Flip And Random Insert
	mutationsPerCycle := 5 * len(data) / 100
	for {
		randByte := rand.Intn((len(data))-0) + 0
		randBitFlip := rand.Intn((7+1)-0) + 0
		randByteFlip := rand.Intn((len(data))-0) + 0
		randByteInsert := rand.Intn(255-0) + 0
		randStrat := rand.Intn(5-0) + 0
		switch randStrat {
		case 0:
			data[randByte] ^= (1 << randBitFlip)
		case 1:
			data[randByte] ^= byte(randByteFlip)
		case 2:
			data[randByte] = byte(randByteInsert)
		case 3:
			data[randByte] = 0x0
		default:
		}
		counter++
		if counter > mutationsPerCycle {
			break
		}
	}
}
func findAllOccurrences(data []byte, search []byte, regionOffset uint64) []uint64 {
	results := make([]uint64, 0)
	searchData := data
	term := search
	for x, d := bytes.Index(searchData, term), 0; x > -1; x, d = bytes.Index(searchData, term), d+x+1 {
		results = append(results, uint64((x+d))+uint64(regionOffset))
		searchData = searchData[x+1:]
	}
	return results
}

func (s *State) FindEgg(egg []byte) ([]uint64, error) {
	locations := make([]uint64, 0)
	for _, mem := range s.SnapshotData.Memory {
		locations = append(locations, findAllOccurrences(mem.RawData, egg, mem.Start)...)
	}
	if len(locations) == 0 {
		return nil, errors.New("Failed to find egg")
	}
	return locations, nil
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

func GenerateEgg(sz int) []byte {
	egg := make([]byte, sz)
	for i := range egg {
		egg[i] = 0x41
	}
	return egg
}

func ReadEggFromDisk(path string) []byte {
	egg, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return egg
}

func SnapShotFuzzMode(target string, baseAddress uint64, blocksFile string, corpusDir string, crashesDir string, snapshotAddress uint64, restoreAddress uint64) {
	fState := NewState(target, baseAddress, snapshotAddress, restoreAddress)
	// init corpus
	fState.Corpus.InitCorpus(corpusDir, crashesDir)
	// Get Fuzz Case Size
	fState.CurrentFuzzCase = make([]byte, len(fState.Corpus.CorpusBuffers[0]))
	START_TIME = time.Now()
	runtime.LockOSThread()
	// Generate Egg
	//GenerateEggPayload()
	//egg := GenerateEgg(len(fState.Corpus.CorpusBuffers[0]))
	egg := ReadEggFromDisk("./egg.bin")
	payloadPath := fmt.Sprintf("%s/tmp.bin", corpusDir)
	err := os.WriteFile(payloadPath, egg, 0644)
	if err != nil {
		panic(err)
	}
	// Load Breakpoints into list
	fState.BreakPointAddresses = fState.GetBreakPointAddresses(blocksFile)
	// spawn using that path with egg payload there
	fState.Spawn([]string{payloadPath})
	// Take Snapshot
	fState.TakeSnapshot()
	// We should be stopped at the restore address with the memory snapshotted
	// Find Egg Now So we know where to overwrite it
	addressesOfEgg, err := fState.FindEgg(egg)
	if err != nil {
		panic(err)
	}
	for {
		nextCase := rand.Intn(len(fState.Corpus.CorpusBuffers))
		copy(fState.CurrentFuzzCase, fState.Corpus.GetCaseByIdx(nextCase))
		// Mutate Copy
		//Mutate(fState.CurrentFuzzCase)
		Mutate(fState.CurrentFuzzCase)
		// Write To Process Memory
		for _, address := range addressesOfEgg {
			fState.WriteBufferToProcess(address, fState.CurrentFuzzCase)
		}
		//snapshot.MemoryDump(fState.Pid)
		hitRestorePoint := fState.CoverageLoop()
		if hitRestorePoint {
			//fState.ContinueExec()
			fState.RestoreSnapshot()
			// Reinstrument the process with the remaining breakpoints
			//fState.InstrumentProcess(fState.FuzzCases == 0)
			fState.FuzzCases++
		}
		if fState.BreakPointsHit > fState.PreviousCoverageHit {
			fState.PreviousCoverageHit = fState.BreakPointsHit
			fState.Corpus.AddToCorpus(fState.CurrentFuzzCase)
		}
		fState.PrintStats()
	}

}
func GetBiggestCorpusItemSize(corpusDir string) int64 {
	var err error
	var biggest int64 = 0
	entry, err := os.ReadDir(corpusDir)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entry {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			panic(err)
		}
		sz := info.Size()
		if sz > biggest {
			biggest = sz
		}
	}
	return biggest
}

func SpawnFuzzMode(target string, baseAddress uint64, blocksFile string, corpusDir string, crashesDir string) {
	fState := NewState(target, baseAddress, 0x0, 0x0)
	// init corpus
	fState.Corpus.InitCorpus(corpusDir, crashesDir)
	// get biggest size from corpus
	fState.CurrentFuzzCase = make([]byte, GetBiggestCorpusItemSize(corpusDir))
	//fState.CurrentFuzzCase = make([]byte, 0)
	START_TIME = time.Now()
	runtime.LockOSThread()
	payloadPath := fmt.Sprintf("%s/tmp.bin", corpusDir)
	fState.BreakPointAddresses = fState.GetBreakPointAddresses(blocksFile)
	var nextCase int = 0
	for {
		nextCase = rand.Intn(len(fState.Corpus.CorpusBuffers))
		copy(fState.CurrentFuzzCase, fState.Corpus.GetCaseByIdx(nextCase))
		// Mutate Copy
		Mutate(fState.CurrentFuzzCase)
		// Write To payload tmp path
		fState.Corpus.WriteFuzzCaseToDisk(payloadPath, fState.CurrentFuzzCase)
		// spawn using that path
		fState.Spawn([]string{payloadPath, "--tree"})
		fState.InstrumentProcess(fState.FuzzCases == 0)
		fState.CoverageLoop()
		if fState.BreakPointsHit > fState.PreviousCoverageHit {
			fState.PreviousCoverageHit = fState.BreakPointsHit
			fState.Corpus.AddToCorpus(fState.CurrentFuzzCase)
		}
		fState.FuzzCases++
		fState.PrintStats()
	}
	runtime.UnlockOSThread()
}

func main() {
	seedPtr := flag.Int64("seed", 0, "seed value")
	flag.Parse()
	if *seedPtr == 0 {
		flag.PrintDefaults()
		return
	}
	rand.Seed(*seedPtr)
	SpawnFuzzMode("./jsonlint", 0x400000, "./libjson_blocks.txt", "./corpus", "./crashes")
	//SpawnFuzzMode("./vpxdec", 0x400000, "./libvpx_blocks.txt", "./corpus", "./crashes")
	//SpawnFuzzMode("./exif", 0x400000, "./exif_blocks.txt", "./corpus", "./crashes")
	//SnapShotFuzzMode("./exif", 0x400000, "./exif_blocks.txt", "./corpus", "./crashes", 0x40B782, 0x402B0E)
	// Attempting Server Example
	//SnapShotFuzzMode("./example/common_server_example", 0x400000, "./example/common_server_example_blocks.txt", "./corpus", "./crashes", 0x4013ef, 0x4012a9)
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
