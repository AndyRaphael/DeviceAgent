//go:build !windows
// +build !windows

package main

import "fmt"

// captureScreen stub for non-Windows platforms
func captureScreen(params map[string]interface{}) CommandResult {
	return NewErrorResult("Screen capture is only supported on Windows")
}

// handleScreenCaptureHelper stub for non-Windows platforms
func handleScreenCaptureHelper() {
	fmt.Println("Error: Screen capture is only supported on Windows")
}
