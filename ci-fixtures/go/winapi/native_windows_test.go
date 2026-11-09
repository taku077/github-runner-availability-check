//go:build windows

package winapi

import (
	"fmt"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// API contracts are public Win32 definitions, not imported from PCFM.
const (
	fileIdInfoClass      = uintptr(18) // FILE_INFO_BY_HANDLE_CLASS: FileIdInfo
	fileReadAttributes   = uint32(0x80)
	fileAttributeDir     = uint32(0x10)
	fileAttributeReparse = uint32(0x400)
	filePersistentACLs   = uint32(0x8)
)

type fileIdentity struct {
	VolumeSerial uint64
	FileID       [16]byte
}

type publicSnapshot struct {
	Identity   fileIdentity
	Filesystem string
	ACLFlag    bool
}

var (
	getInfoEx     = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFileInformationByHandleEx")
	getVolumeInfo = syscall.NewLazyDLL("kernel32.dll").NewProc("GetVolumeInformationByHandleW")
)

// snapshot reads both identity and filesystem properties from one open HANDLE.
// It never returns or logs raw identifiers, paths, volume labels or event logs.
func snapshot(h syscall.Handle) (publicSnapshot, error) {
	var attrs syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &attrs); err != nil {
		return publicSnapshot{}, fmt.Errorf("GetFileInformationByHandle: %w", err)
	}
	if attrs.FileAttributes&fileAttributeDir == 0 || attrs.FileAttributes&fileAttributeReparse != 0 {
		return publicSnapshot{}, fmt.Errorf("unexpected directory attributes")
	}
	var id fileIdentity
	if unsafe.Sizeof(id) != 24 {
		return publicSnapshot{}, fmt.Errorf("unexpected FILE_ID_INFO layout")
	}
	ok, _, err := getInfoEx.Call(uintptr(h), fileIdInfoClass, uintptr(unsafe.Pointer(&id)), unsafe.Sizeof(id))
	if ok == 0 {
		return publicSnapshot{}, fmt.Errorf("GetFileInformationByHandleEx(FileIdInfo): %w", err)
	}
	var fs [32]uint16
	var flags uint32
	ok, _, err = getVolumeInfo.Call(uintptr(h), 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&fs[0])), uintptr(len(fs)))
	if ok == 0 {
		return publicSnapshot{}, fmt.Errorf("GetVolumeInformationByHandleW: %w", err)
	}
	name := syscall.UTF16ToString(fs[:])
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return publicSnapshot{}, fmt.Errorf("unexpected filesystem name")
	}
	return publicSnapshot{Identity: id, Filesystem: name, ACLFlag: flags&filePersistentACLs != 0}, nil
}

// This is a public API/runner compatibility smoke test, NOT a PCFM validation.
// The only filesystem objects used are a fresh, test-owned directory and two
// read-only handles. No Windows logs, persistence, registry or OS settings.
func TestPublicWindowsFileIdAndFilesystemOnSameHandle(t *testing.T) {
	if unsafe.Sizeof(fileIdentity{}) != 24 {
		t.Fatal("FILE_ID_INFO ABI size is not 24")
	}
	path, err := syscall.UTF16PtrFromString(t.TempDir())
	if err != nil {
		t.Fatal("temporary directory path encoding failed")
	}
	open := func() (syscall.Handle, error) {
		return syscall.CreateFile(path, fileReadAttributes, syscall.FILE_SHARE_READ, nil,
			syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	}
	first, err := open()
	if err != nil {
		t.Fatalf("first read-only handle: %v", err)
	}
	defer syscall.CloseHandle(first)
	second, err := open()
	if err != nil {
		t.Fatalf("second read-only handle: %v", err)
	}
	defer syscall.CloseHandle(second)

	one, err := snapshot(first)
	if err != nil {
		t.Fatal(err)
	}
	two, err := snapshot(second)
	if err != nil {
		t.Fatal(err)
	}
	again, err := snapshot(first)
	if err != nil {
		t.Fatal(err)
	}
	if one.Identity != two.Identity || one.Identity != again.Identity {
		t.Fatal("open-handle identity changed")
	}
	if one.Identity.VolumeSerial == 0 || one.Identity.FileID == [16]byte{} {
		t.Fatal("128-bit identity unavailable on runner filesystem")
	}
	if one.Filesystem != two.Filesystem || one.Filesystem != again.Filesystem ||
		one.ACLFlag != two.ACLFlag || one.ACLFlag != again.ACLFlag {
		t.Fatal("filesystem type/capability changed between reads")
	}
	if !one.ACLFlag {
		t.Fatal("FILE_PERSISTENT_ACLS not observed")
	}
	if one.Filesystem != "NTFS" && one.Filesystem != "ReFS" {
		t.Fatalf("unexpected runner filesystem classification: %q", one.Filesystem)
	}
	// The output contains no volume serial, file ID, path, username or logs.
	t.Logf("PUBLIC_WINAPI_PROBE_PASS filesystem=%s same_handle=true dual_handle=true acl_capability=true; no export", one.Filesystem)
}
