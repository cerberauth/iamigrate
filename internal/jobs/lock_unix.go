//go:build !windows

package jobs

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on f without waiting for it. The kernel
// drops the lock when the process dies, so a crashed run never leaves a job
// locked.
func lockFile(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
