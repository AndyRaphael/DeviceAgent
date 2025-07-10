//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WTS Session States
const (
	WTSActive       = 0
	WTSConnected    = 1
	WTSConnectQuery = 2
	WTSShadow       = 3
	WTSDisconnected = 4
	WTSIdle         = 5
	WTSListen       = 6
	WTSReset        = 7
	WTSDown         = 8
	WTSInit         = 9
)

// WTS Information Classes
const (
	WTSInitialProgram     = 0
	WTSApplicationName    = 1
	WTSWorkingDirectory   = 2
	WTSOEMId              = 3
	WTSSessionId          = 4
	WTSUserName           = 5
	WTSWinStationName     = 6
	WTSDomainName         = 7
	WTSConnectState       = 8
	WTSClientBuildNumber  = 9
	WTSClientName         = 10
	WTSClientDirectory    = 11
	WTSClientProductId    = 12
	WTSClientHardwareId   = 13
	WTSClientAddress      = 14
	WTSClientDisplay      = 15
	WTSClientProtocolType = 16
)

// WTS API structures
type WTS_SESSION_INFO struct {
	SessionId      uint32
	WinStationName *uint16
	State          uint32
}

type WTS_CLIENT_DISPLAY struct {
	HorizontalResolution uint32
	VerticalResolution   uint32
	ColorDepth           uint32
}

// SessionInfo holds detailed information about a Windows session
type SessionInfo struct {
	SessionID   string
	SessionType string
	State       string
	Username    string
	ClientName  string
	Protocol    string
	Resolution  string
	ColorDepth  uint32
}

// IsRDPSession returns true if this is an RDP/Terminal Server session
func (s *SessionInfo) IsRDPSession() bool {
	return s.Protocol == "RDP" || s.ClientName != "" || s.SessionType == "RDP"
}

var (
	// WTS APIs for Terminal Services/RDP/AVD
	procWTSOpenServer              = modwtsapi32.NewProc("WTSOpenServerW")
	procWTSCloseServer             = modwtsapi32.NewProc("WTSCloseServer")
	procWTSEnumerateSessions       = modwtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformation = modwtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory              = modwtsapi32.NewProc("WTSFreeMemory")
	procWTSVirtualChannelOpen      = modwtsapi32.NewProc("WTSVirtualChannelOpen")
	procWTSVirtualChannelClose     = modwtsapi32.NewProc("WTSVirtualChannelClose")
	procWTSVirtualChannelRead      = modwtsapi32.NewProc("WTSVirtualChannelRead")
	procWTSVirtualChannelWrite     = modwtsapi32.NewProc("WTSVirtualChannelWrite")
)

// getSessionInfo retrieves detailed information about a specific session
func getSessionInfo(sessionID string) (*SessionInfo, error) {
	sessionIDInt := uint32(0)
	if _, err := fmt.Sscanf(sessionID, "%d", &sessionIDInt); err != nil {
		return nil, fmt.Errorf("invalid session ID: %v", err)
	}

	info := &SessionInfo{
		SessionID: sessionID,
	}

	// Open WTS server handle (local server)
	serverHandle, _, _ := procWTSOpenServer.Call(0) // NULL for local server
	if serverHandle == 0 {
		return nil, fmt.Errorf("failed to open WTS server")
	}
	defer procWTSCloseServer.Call(serverHandle)

	// Get session state
	var statePtr uintptr
	var stateSize uint32
	result, _, _ := procWTSQuerySessionInformation.Call(
		serverHandle,
		uintptr(sessionIDInt),
		WTSConnectState,
		uintptr(unsafe.Pointer(&statePtr)),
		uintptr(unsafe.Pointer(&stateSize)),
	)
	if result != 0 {
		defer procWTSFreeMemory.Call(statePtr)
		state := *(*uint32)(unsafe.Pointer(statePtr))
		info.State = getSessionStateName(state)
	}

	// Get username
	var usernamePtr uintptr
	var usernameSize uint32
	result, _, _ = procWTSQuerySessionInformation.Call(
		serverHandle,
		uintptr(sessionIDInt),
		WTSUserName,
		uintptr(unsafe.Pointer(&usernamePtr)),
		uintptr(unsafe.Pointer(&usernameSize)),
	)
	if result != 0 {
		defer procWTSFreeMemory.Call(usernamePtr)
		info.Username = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(usernamePtr)))
	}

	// Get client name (indicates RDP session)
	var clientPtr uintptr
	var clientSize uint32
	result, _, _ = procWTSQuerySessionInformation.Call(
		serverHandle,
		uintptr(sessionIDInt),
		WTSClientName,
		uintptr(unsafe.Pointer(&clientPtr)),
		uintptr(unsafe.Pointer(&clientSize)),
	)
	if result != 0 {
		defer procWTSFreeMemory.Call(clientPtr)
		info.ClientName = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(clientPtr)))
	}

	// Get protocol type
	var protocolPtr uintptr
	var protocolSize uint32
	result, _, _ = procWTSQuerySessionInformation.Call(
		serverHandle,
		uintptr(sessionIDInt),
		WTSClientProtocolType,
		uintptr(unsafe.Pointer(&protocolPtr)),
		uintptr(unsafe.Pointer(&protocolSize)),
	)
	if result != 0 {
		defer procWTSFreeMemory.Call(protocolPtr)
		protocolType := *(*uint16)(unsafe.Pointer(protocolPtr))
		info.Protocol = getProtocolName(protocolType)
	}

	// Get display information
	var displayPtr uintptr
	var displaySize uint32
	result, _, _ = procWTSQuerySessionInformation.Call(
		serverHandle,
		uintptr(sessionIDInt),
		WTSClientDisplay,
		uintptr(unsafe.Pointer(&displayPtr)),
		uintptr(unsafe.Pointer(&displaySize)),
	)
	if result != 0 {
		defer procWTSFreeMemory.Call(displayPtr)
		display := (*WTS_CLIENT_DISPLAY)(unsafe.Pointer(displayPtr))
		info.Resolution = fmt.Sprintf("%dx%d", display.HorizontalResolution, display.VerticalResolution)
		info.ColorDepth = display.ColorDepth
	}

	// Determine session type
	if info.ClientName != "" || info.Protocol == "RDP" {
		info.SessionType = "RDP"
	} else if sessionIDInt == 0 {
		info.SessionType = "Console"
	} else {
		info.SessionType = "Unknown"
	}

	return info, nil
}

// getSessionStateName converts WTS session state to readable name
func getSessionStateName(state uint32) string {
	switch state {
	case WTSActive:
		return "Active"
	case WTSConnected:
		return "Connected"
	case WTSConnectQuery:
		return "ConnectQuery"
	case WTSShadow:
		return "Shadow"
	case WTSDisconnected:
		return "Disconnected"
	case WTSIdle:
		return "Idle"
	case WTSListen:
		return "Listen"
	case WTSReset:
		return "Reset"
	case WTSDown:
		return "Down"
	case WTSInit:
		return "Init"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// getProtocolName converts protocol type to readable name
func getProtocolName(protocol uint16) string {
	switch protocol {
	case 0:
		return "Console"
	case 1:
		return "ICA"
	case 2:
		return "RDP"
	default:
		return fmt.Sprintf("Unknown(%d)", protocol)
	}
}

// captureScreenWTS captures screen using WTS APIs for RDP/Terminal Server sessions
func captureScreenWTS(sessionID, timestamp string, sessionInfo *SessionInfo) CommandResult {
	// Parse session ID
	sessionIDInt := uint32(0)
	if _, err := fmt.Sscanf(sessionID, "%d", &sessionIDInt); err != nil {
		return createWTSFailureResult("Invalid session ID")
	}

	// Launch helper in the target session
	result := captureScreenWTSHelper(sessionIDInt, sessionID, timestamp, sessionInfo)

	// Add session info to result
	if result.Output != nil {
		if output, ok := result.Output.(map[string]interface{}); ok {
			output["wts_session_info"] = map[string]interface{}{
				"session_type": sessionInfo.SessionType,
				"state":        sessionInfo.State,
				"username":     sessionInfo.Username,
				"client_name":  sessionInfo.ClientName,
				"protocol":     sessionInfo.Protocol,
				"resolution":   sessionInfo.Resolution,
				"color_depth":  sessionInfo.ColorDepth,
			}
		}
	}

	return result
}

// captureScreenWTSHelper launches helper with enhanced RDP session support
func captureScreenWTSHelper(sessionIDInt uint32, sessionID, timestamp string, sessionInfo *SessionInfo) CommandResult {
	// Create secure temp directory (revert to original working path)
	tempDir := "C:\\ProgramData\\DeviceAgent\\temp"
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		return createWTSFailureResult(fmt.Sprintf("Failed to create temp directory: %v", err))
	}

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return createWTSFailureResult(fmt.Sprintf("Failed to get executable path: %v", err))
	}

	// Validate executable
	if _, err := os.Stat(exePath); err != nil {
		return createWTSFailureResult("Executable not accessible")
	}

	// Generate unique output filename (back to original working path)
	outputPath := fmt.Sprintf("%s\\screenshot_wts_%s_%s.jpg", tempDir, sessionID, timestamp)

	// Launch helper with WTS-specific parameters
	result := launchWTSHelperInSession(exePath, sessionIDInt, sessionID, outputPath, sessionInfo)
	if result.Status == "error" {
		return result
	}

	// Wait for helper to complete
	return waitForWTSHelperAndReadResult(outputPath, sessionID, timestamp)
}

// Enhanced launchWTSHelperInSession with proper desktop context
func launchWTSHelperInSession(exePath string, sessionIDInt uint32, sessionID, outputPath string, sessionInfo *SessionInfo) CommandResult {
	// Get user token for the target session
	var userToken uintptr
	result, _, err := procWTSQueryUserToken.Call(uintptr(sessionIDInt), uintptr(unsafe.Pointer(&userToken)))
	if result == 0 {
		return createWTSFailureResult("Failed to get user token for RDP session")
	}
	defer procCloseHandle.Call(userToken)

	// Duplicate the token
	var duplicatedToken uintptr
	result, _, err = procDuplicateTokenEx.Call(
		userToken,
		TOKEN_ALL_ACCESS,
		0, // no security attributes
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&duplicatedToken)),
	)
	if result == 0 {
		return createWTSFailureResult("Failed to duplicate token")
	}
	defer procCloseHandle.Call(duplicatedToken)

	// Create environment block
	var environment uintptr
	result, _, err = procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&environment)),
		duplicatedToken,
		0, // don't inherit
	)
	if result == 0 {
		environment = 0
	} else {
		defer procDestroyEnvironmentBlock.Call(environment)
	}

	// Prepare command line
	commandLine := fmt.Sprintf(`"%s" capture-screen --session %s --output "%s" --wts-mode`, exePath, sessionID, outputPath)
	commandLinePtr, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return createWTSFailureResult("Failed to prepare command line")
	}

	// Setup startup info for RDP session
	desktopName := "winsta0\\default"
	desktop, _ := windows.UTF16PtrFromString(desktopName)

	startupInfo := STARTUPINFO{
		Cb:         uint32(unsafe.Sizeof(STARTUPINFO{})),
		Desktop:    desktop,
		Flags:      STARTF_USESHOWWINDOW,
		ShowWindow: SW_HIDE,
	}

	var processInfo PROCESS_INFORMATION

	// Create process with INTERACTIVE flag to access user desktop
	processFlags := NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW

	result, _, err = procCreateProcessAsUser.Call(
		duplicatedToken,
		0, // no application name
		uintptr(unsafe.Pointer(commandLinePtr)),
		0, // no process attributes
		0, // no thread attributes
		0, // don't inherit handles
		uintptr(processFlags),
		environment,
		0, // no current directory
		uintptr(unsafe.Pointer(&startupInfo)),
		uintptr(unsafe.Pointer(&processInfo)),
	)

	if result == 0 {
		return createWTSFailureResult("Failed to create process in RDP session")
	}

	// Wait for process completion
	timeoutMs := uint32(75000) // 75 second timeout
	waitResult, _, _ := procWaitForSingleObject.Call(processInfo.Process, uintptr(timeoutMs))

	// Cleanup process handles
	procCloseHandle.Call(processInfo.Process)
	procCloseHandle.Call(processInfo.Thread)

	switch waitResult {
	case WAIT_OBJECT_0:
		return CommandResult{
			Output: map[string]interface{}{
				"success":    true,
				"session_id": sessionID,
				"method":     "WTS Helper Process",
			},
			Error:  "",
			Status: "success",
		}
	case WAIT_TIMEOUT:
		return createWTSFailureResult("Process timed out")
	default:
		return createWTSFailureResult("Wait failed")
	}
}

// createWTSFailureResult creates a failure result for WTS operations with enhanced logging
func createWTSFailureResult(errorMsg string) CommandResult {
	logs := []string{
		"WTS screen capture operation failed",
		fmt.Sprintf("Error: %s", errorMsg),
		"Method: WTS API",
	}

	result := map[string]interface{}{
		"error":   errorMsg,
		"method":  "WTS API",
		"success": false,
	}

	return CommandResult{
		Result: result,
		Logs:   strings.Join(logs, "\n"),
		Status: "error",
	}
}

// waitForWTSHelperAndReadResult waits for helper completion and reads result - SAFE UPDATE
func waitForWTSHelperAndReadResult(outputPath, sessionID, timestamp string) CommandResult {
	var logs []string
	logs = append(logs, "Waiting for WTS helper process to complete")
	logs = append(logs, fmt.Sprintf("Monitoring output file: %s", outputPath))

	timeout := 75 * time.Second
	start := time.Now()
	checkInterval := 1 * time.Second

	for time.Since(start) < timeout {
		if stat, err := os.Stat(outputPath); err == nil {
			currentSize := stat.Size()
			logs = append(logs, fmt.Sprintf("Output file found, size: %d bytes", currentSize))

			// Wait for file to be reasonably sized
			if currentSize > 1000 {
				// Additional wait to ensure file is fully written
				time.Sleep(2 * time.Second)

				// Re-check final size
				if finalStat, err := os.Stat(outputPath); err == nil {
					finalSize := finalStat.Size()

					if finalSize < 100 {
						logs = append(logs, "File too small, continuing to wait")
						time.Sleep(checkInterval)
						continue
					}

					imageData, err := os.ReadFile(outputPath)
					if err != nil {
						errorMsg := fmt.Sprintf("Failed to read result file: %v", err)
						logs = append(logs, errorMsg)
						return createScreenCaptureError(errorMsg, logs)
					}

					// Validate image data
					if len(imageData) < 100 {
						errorMsg := "Result file too small - corrupted or incomplete"
						logs = append(logs, errorMsg)
						return createScreenCaptureError(errorMsg, logs)
					}

					// Clean up the temporary file
					os.Remove(outputPath)
					logs = append(logs, "Temporary file cleaned up")

					base64Image := base64.StdEncoding.EncodeToString(imageData)
					logs = append(logs, fmt.Sprintf("Successfully captured screenshot: %d bytes", len(imageData)))

					result := map[string]interface{}{
						"success":           true,
						"session_id":        sessionID,
						"image_size_bytes":  len(imageData),
						"image_base64_size": len(base64Image),
						"timestamp":         timestamp,
						"method":            "WTS Helper",
					}

					return CommandResult{
						Result:         result,
						Logs:           strings.Join(logs, "\n"),
						Status:         "success",
						ScreenshotData: base64Image,
					}
				}
			}
		}

		time.Sleep(checkInterval)
	}

	errorMsg := "Helper result timeout - no output file created"
	logs = append(logs, errorMsg)
	logs = append(logs, fmt.Sprintf("Waited %v for output file", timeout))
	return createScreenCaptureError(errorMsg, logs)
}
