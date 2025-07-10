//go:build !windows
// +build !windows

package main

func runAsService() {
	// On non-Windows platforms, just run as console service
	runAsConsoleService()
}
