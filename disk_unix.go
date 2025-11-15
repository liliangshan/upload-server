//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"syscall"
)

// getDiskUsageUnix Unix/Linux系统获取磁盘使用情况
func getDiskUsageUnix(path string) (*DiskUsage, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return nil, err
	}

	// 计算总大小、可用大小和已用大小
	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	used := total - free

	return &DiskUsage{
		Total: total,
		Free:  free,
		Used:  used,
	}, nil
}

// getDiskUsageWindows Unix系统不需要此函数，但为了编译通过而声明
func getDiskUsageWindows(path string) (*DiskUsage, error) {
	return nil, fmt.Errorf("此函数在Unix系统上不可用")
}
