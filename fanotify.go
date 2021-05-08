// Slightly simplified and improved https://github.com/ozeidan/gosearch/blob/master/internal/fanotify/fanotify.go
// - add listenDir, isFiltered function for independent usage
// - expanded marks
// - added modify detection
// - returns errors instead of panics
// Must be run on Linux 5.1+
// License: GPLv3

package simplefanotify

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const markFlags = unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM
const markMask = unix.FAN_ONDIR | unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO | unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_MODIFY

type fanotifyInfoHeader struct {
	infoType uint8
	pad      uint8
	Len      uint16
}

type fileHandle struct {
	handleBytes uint32
	handleType  int32
}

type fanotifyEventFid struct {
	kernelFsidT [2]int32
	fileHandle  fileHandle
}

type fanotifyEventInfoFid struct {
	hdr      fanotifyInfoHeader
	eventFid fanotifyEventFid
}

// All notifications, except for Modify, refer to the parent directory, not the child object.
type FileChange struct {
	FolderPath string
	ChangeType int
}

const (
	Create = iota
	Delete
	Modify
)

func Listen(
	listenDir string,
	isFiltered func(path string) bool,
	changeReceiver chan<- FileChange,
) error {
	fan, err := unix.FanotifyInit(unix.FAN_REPORT_FID, 0)
	if err != nil {
		return fmt.Errorf("fanotifyinit: %v", err)
	}

	err = unix.FanotifyMark(fan, markFlags, markMask, unix.AT_FDCWD, listenDir)

	if err != nil {
		return fmt.Errorf("fanotifymark: %v", err)
	}

	f := os.NewFile(uintptr(fan), "")
	r := bufio.NewReader(f)

	for {
		readEvent(r, isFiltered, changeReceiver)
	}
}

var metaBuff = make([]byte, 24)

func readEvent(r io.Reader, isFiltered func(path string) bool, changeReceiver chan<- FileChange) error {
	_, err := r.Read(metaBuff)
	if err != nil {
		return fmt.Errorf("reading meta: %v", err)
	}

	meta := *((*unix.FanotifyEventMetadata)(unsafe.Pointer(&metaBuff[0])))
	bytesLeft := int(meta.Event_len - uint32(meta.Metadata_len))
	infoBuff := make([]byte, bytesLeft)
	n, err := r.Read(infoBuff)
	if err != nil {
		return fmt.Errorf("reading info: %v", err)
	}

	if n < 0 || n > bytesLeft {
		return fmt.Errorf("reading infoBuff gave back strange number of bytes")
	}

	info := *((*fanotifyEventInfoFid)(unsafe.Pointer(&infoBuff[0])))

	if info.hdr.infoType != 1 {
		return nil
	}

	handleStart := uint32(unsafe.Sizeof(info))
	handleLen := info.eventFid.fileHandle.handleBytes
	handleBytes := infoBuff[handleStart : handleStart+handleLen]
	unixFileHandle := unix.NewFileHandle(info.eventFid.fileHandle.handleType, handleBytes)

	fd, err := unix.OpenByHandleAt(unix.AT_FDCWD, unixFileHandle, 0)
	if err != nil {
		return fmt.Errorf("could not call OpenByHandleAt: %v", err)
	}

	defer func() {
		err = syscall.Close(fd)
		if err != nil {
			log.Println("warning: couldn't close file descriptor", err)
		}
	}()

	sym := fmt.Sprintf("/proc/self/fd/%d", fd)
	path := make([]byte, 200)
	pathLength, err := unix.Readlink(sym, path)

	if err != nil {
		return fmt.Errorf("could not call Readlink: %v", err)
	}
	path = path[:pathLength]
	if isFiltered(string(path)) {
		return nil
	}

	changeType := 0
	if meta.Mask&unix.IN_CREATE > 0 ||
		meta.Mask&unix.IN_MOVED_TO > 0 {
		changeType = Create
	}
	if meta.Mask&unix.IN_DELETE > 0 ||
		meta.Mask&unix.IN_MOVED_FROM > 0 {
		changeType = Delete
	}
	if meta.Mask&unix.IN_MODIFY > 0 {
		changeType = Modify
	}

	change := FileChange{
		string(path),
		changeType,
	}

	changeReceiver <- change
	return nil
}
