//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// getDiskUsageWindows Windows系统获取磁盘使用情况
func getDiskUsageWindows(path string) (*DiskUsage, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	// 将路径转换为UTF16指针
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	var freeBytes, totalBytes, availableBytes int64

	// 调用 GetDiskFreeSpaceExW
	ret, _, err := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&availableBytes)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("获取磁盘空间失败: %v", err)
	}

	return &DiskUsage{
		Total: uint64(totalBytes),
		Free:  uint64(freeBytes),
		Used:  uint64(totalBytes) - uint64(freeBytes),
	}, nil
}

// getDiskUsageUnix Windows系统不需要此函数，但为了编译通过而声明
func getDiskUsageUnix(path string) (*DiskUsage, error) {
	return nil, fmt.Errorf("此函数在Windows系统上不可用")
}
