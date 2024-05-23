package snapshot

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type Snapshot struct {
	Pid       int
	Registers syscall.PtraceRegs
	Memory    []MemoryRegion
}

type MemoryRegion struct {
	Start   uint64
	End     uint64
	Name    string
	RawData []byte
}

func NewSnapshot(pid int) Snapshot {
	snap := Snapshot{
		Pid:       pid,
		Registers: syscall.PtraceRegs{},
		Memory:    GetRegionsFromProcess(pid),
	}
	syscall.PtraceGetRegs(pid, &snap.Registers)
	return snap
}

func ParseRegion(pid int, data string) MemoryRegion {
	sections := strings.Split(data, " ")
	startEnd := strings.Split(sections[0], "-")
	name := sections[len(sections)-1]
	if name == "" {
		name = "Anonymous"
	}
	start, err := strconv.ParseUint(startEnd[0], 16, 64)
	if err != nil {
		log.Fatal(err)
	}
	end, err := strconv.ParseUint(startEnd[1], 16, 64)
	if err != nil {
		log.Fatal(err)
	}
	return NewRegion(pid, start, end, name)
}

func NewRegion(pid int, start uint64, end uint64, name string) MemoryRegion {
	region := MemoryRegion{
		Start: start,
		End:   end,
		Name:  name,
	}
	path := fmt.Sprintf("/proc/%d/mem", pid)
	memPtr, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer memPtr.Close()
	_, err = memPtr.Seek(int64(region.Start), 0)
	if err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, end-start)
	_, err = memPtr.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	region.RawData = buffer
	return region
}

func ReadRegionFromProcess(pid int, start uint64, end uint64) []byte {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	memPtr, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer memPtr.Close()
	_, err = memPtr.Seek(int64(start), 0)
	if err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, end-start)
	_, err = memPtr.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}
	return buffer
}

func WriteRegionToProcess(pid int, region MemoryRegion) {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	memPtr, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer memPtr.Close()
	_, err = memPtr.Seek(int64(region.Start), 0)
	if err != nil {
		log.Fatal(err)
	}
	_, err = memPtr.Write(region.RawData)
	if err != nil {
		log.Fatal(err)
	}
}

func GetRegionsFromProcess(pid int) []MemoryRegion {
	regions := make([]MemoryRegion, 0)
	path := fmt.Sprintf("/proc/%d/maps", pid)
	rawMaps, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	// Only want writable memory regions that could have changed during execution
	segments := strings.Split(string(rawMaps), "\n")
	for _, s := range segments {
		if len(s) < 1 {
			continue
		}
		entry := strings.Split(s, " ")
		if strings.Contains(entry[1], "rw") {
			regions = append(regions, ParseRegion(pid, s))
		}
	}
	return regions
}

func MemoryDump(pid int) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	rawMaps, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	// Only want writable memory regions that could have changed during execution
	segments := strings.Split(string(rawMaps), "\n")
	for i, s := range segments {
		if len(s) < 1 {
			continue
		}
		entry := strings.Split(s, " ")
		if strings.Contains(entry[1], "rw") {
			reg := ParseRegion(pid, s)
			name := fmt.Sprintf("%d_%s.dump", i, reg.Name)
			os.WriteFile(name, reg.RawData, 0644)
		}
	}
}
