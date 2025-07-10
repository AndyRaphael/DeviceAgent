//go:build !windows
// +build !windows

package main

import "fmt"

// captureScreen stub for non-Windows platforms
func captureScreen(params map[string]interface{}) CommandResult {
	return CommandResult{
		Output: map[string]string{"error": "Screen capture is only supported on Windows"},
		Error:  "Screen capture is only supported on Windows",
		Status: "error",
	}
}

// handleScreenCaptureHelper stub for non-Windows platforms
func handleScreenCaptureHelper() {
	fmt.Println("Error: Screen capture is only supported on Windows")
}
