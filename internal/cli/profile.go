package cli

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
)

func createProfile(path string, force bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if !force {
		flags = os.O_CREATE | os.O_WRONLY | os.O_EXCL
	}
	return os.OpenFile(path, flags, 0600)
}

// startProfiles begins CPU profiling and returns the function that finishes both
// profiles. Heap data is captured at the end, when the run's peak has passed.
func startProfiles(cpuPath, memPath string, force bool) (func() error, error) {
	var cpu *os.File
	if cpuPath != "" {
		file, err := createProfile(cpuPath, force)
		if err != nil {
			return nil, fmt.Errorf("cpu profile: %w", err)
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("cpu profile: %w", err)
		}
		cpu = file
	}
	return func() error {
		var firstErr error
		if cpu != nil {
			pprof.StopCPUProfile()
			firstErr = cpu.Close()
		}
		if memPath == "" {
			return firstErr
		}
		file, err := createProfile(memPath, force)
		if err != nil {
			return fmt.Errorf("memory profile: %w", err)
		}
		defer file.Close()
		runtime.GC()
		if err := pprof.Lookup("allocs").WriteTo(file, 0); err != nil {
			return fmt.Errorf("memory profile: %w", err)
		}
		return firstErr
	}, nil
}
