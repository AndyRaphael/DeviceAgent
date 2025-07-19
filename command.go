package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// CommandResult represents the result of a command execution
type CommandResult struct {
	// Legacy fields - keep for backward compatibility during migration
	Output interface{} `json:"output,omitempty"`
	Error  string      `json:"error,omitempty"`
	Status string      `json:"status"`

	// New fields for improved separation
	Result interface{} `json:"result,omitempty"` // Structured JSON data only
	Logs   string      `json:"logs,omitempty"`   // Human-readable messages, errors, diagnostics

	// Special handling for binary data
	ScreenshotData string `json:"screenshot_data,omitempty"`
}

// Input validation functions to prevent injection attacks
// NOTE: Validation functions moved to validation.go

// CommandResult constructor functions moved to result.go

// ExecuteCommand is the main dispatcher that calls specific command functions
func ExecuteCommand(command string, parameters string, jwtToken string) CommandResult {
	// Parse parameters as JSON if provided
	var params map[string]interface{}
	if parameters != "" {
		if err := json.Unmarshal([]byte(parameters), &params); err != nil {
			return CommandResult{
				Output: map[string]string{"error": fmt.Sprintf("Invalid parameters JSON: %v", err)},
				Error:  fmt.Sprintf("Invalid parameters JSON: %v", err),
				Status: "error",
			}
		}
	}

	switch command {
	case "hostname":
		return getHostname()
	case "whoami":
		return getWhoami()
	case "uptime":
		return getUptime()
	case "disk_space":
		return getDiskSpace()
	case "memory":
		return getMemoryInfo()
	case "processes":
		return getTopProcesses()
	case "network":
		return getNetworkInfo()
	case "system_info":
		return getSystemInfo()
	case "logged_users":
		return getLoggedUsers()
	case "logoff_user":
		return logoffUser(params)
	case "ping":
		return pingDevice()
	case "capture_screen":
		return captureScreen(params)
	case "reboot":
		return rebootComputer(params)
	case "shutdown":
		return shutdownComputer(params)
	case "hyperv_inventory":
		return executeHyperVInventory()
	case "hyperv_inventory_db":
		return executeHyperVInventoryWithDB(jwtToken)
	case "hyperv_get_vms":
		return executeHyperVGetVMsFromDB(jwtToken)
	case "hyperv_sync":
		return executeHyperVSyncAndGet(jwtToken)
	case "hyperv_screenshot":
		return executeHyperVScreenshot(params)
	case "hyperv_start":
		return executeHyperVStart(params)
	case "hyperv_pause":
		return executeHyperVPause(params)
	case "hyperv_reset":
		return executeHyperVReset(params)
	case "hyperv_turnoff":
		return executeHyperVTurnOff(params)
	case "hyperv_shutdown":
		return executeHyperVShutdown(params)
	case "help":
		return getAvailableCommands()
	default:
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Unknown command: %s", command)},
			Error:  fmt.Sprintf("Unknown command: %s", command),
			Status: "error",
		}
	}
}

// System info functions moved to system_info.go

// Storage functions moved to functions/storage.go

// UserSession represents a standardized user session across all platforms
type UserSession struct {
	Username    string `json:"username"`
	SessionID   string `json:"session_id"`
	SessionName string `json:"session_name"`
	State       string `json:"state"`
	LoginTime   string `json:"login_time"`
	Terminal    string `json:"terminal"`
	SessionType string `json:"session_type"`
}

// getLoggedUsers returns all logged in users (including disconnected RDP sessions) with enhanced logging
func getLoggedUsers() CommandResult {
	if runtime.GOOS == "windows" {
		return getLoggedUsersWindows()
	}
	return getLoggedUsersUnix()
}

func getLoggedUsersWindows() CommandResult {
	var logs []string
	logs = append(logs, "Starting Windows user session analysis")

	// Try multiple methods in order of preference
	methods := []func() ([]UserSession, string, error, []string){
		tryQuerySessionEnhanced,
		tryQwinstaEnhanced,
		tryPowerShellSessionsEnhanced,
		tryWMILoggedUsersEnhanced,
	}

	var lastError error

	for i, method := range methods {
		logs = append(logs, fmt.Sprintf("Attempting method %d for user session retrieval", i+1))
		sessions, currentUser, err, methodSpecificLogs := method()

		// Add method-specific logs
		logs = append(logs, methodSpecificLogs...)

		if err == nil && len(sessions) > 0 {
			logs = append(logs, fmt.Sprintf("Successfully retrieved %d user sessions using method %d", len(sessions), i+1))

			// Build structured result
			result := map[string]interface{}{
				"logged_users": sessions,
				"total_users":  len(sessions),
				"current_user": currentUser,
				"platform":     "windows",
				"method_used":  fmt.Sprintf("method_%d", i+1),
				"timestamp":    time.Now().UTC().Format(time.RFC3339),
			}

			// Add session type summary
			sessionSummary := make(map[string]int)
			activeSessions := 0
			for _, session := range sessions {
				sessionSummary[session.SessionType]++
				if session.State == "Active" {
					activeSessions++
				}
			}
			result["session_summary"] = sessionSummary
			result["active_sessions"] = activeSessions

			logs = append(logs, fmt.Sprintf("Session summary: %d active, %v types", activeSessions, sessionSummary))

			return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
		}

		lastError = err
		logs = append(logs, fmt.Sprintf("Method %d failed: %v", i+1, err))
	}

	// All methods failed
	errorMsg := fmt.Sprintf("All user session methods failed, last error: %v", lastError)
	logs = append(logs, errorMsg)
	return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
}

// Enhanced method 1: Try query session command with better logging
func tryQuerySessionEnhanced() ([]UserSession, string, error, []string) {
	var logs []string
	logs = append(logs, "Trying 'query session' command")

	cmd := exec.Command("query", "session")
	out, err := cmd.Output()
	if err != nil {
		logs = append(logs, fmt.Sprintf("'query session' failed: %v", err))
		return nil, "", err, logs
	}

	logs = append(logs, "'query session' command executed successfully")
	sessions := parseWindowsSessions(string(out))
	currentUser := getCurrentWindowsUser()

	logs = append(logs, fmt.Sprintf("Parsed %d sessions from query session output", len(sessions)))
	return sessions, currentUser, nil, logs
}

// Enhanced method 2: Try qwinsta command with better logging
func tryQwinstaEnhanced() ([]UserSession, string, error, []string) {
	var logs []string
	logs = append(logs, "Trying 'qwinsta' command")

	cmd := exec.Command("qwinsta")
	out, err := cmd.Output()
	if err != nil {
		logs = append(logs, fmt.Sprintf("'qwinsta' failed: %v", err))
		return nil, "", err, logs
	}

	logs = append(logs, "'qwinsta' command executed successfully")
	sessions := parseWindowsSessions(string(out))
	currentUser := getCurrentWindowsUser()

	logs = append(logs, fmt.Sprintf("Parsed %d sessions from qwinsta output", len(sessions)))
	return sessions, currentUser, nil, logs
}

// Enhanced method 3: Try PowerShell Get-Process with session info
func tryPowerShellSessionsEnhanced() ([]UserSession, string, error, []string) {
	var logs []string
	logs = append(logs, "Trying PowerShell Get-Process session analysis")

	script := `
	Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
	Where-Object {$_.UserName -and $_.SessionId -ge 0} | 
	Group-Object SessionId, UserName | 
	ForEach-Object {
		$session = $_.Group[0]
		"$($session.SessionId):$($session.UserName):Active"
	} | Sort-Object -Unique
	`

	cmd := exec.Command("powershell", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		logs = append(logs, fmt.Sprintf("PowerShell Get-Process failed: %v", err))
		return nil, "", err, logs
	}

	logs = append(logs, "PowerShell Get-Process executed successfully")

	var sessions []UserSession
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			sessions = append(sessions, UserSession{
				Username:    parts[1],
				SessionID:   parts[0],
				SessionName: "session" + parts[0],
				State:       "Active",
				LoginTime:   "",
				Terminal:    "session" + parts[0],
				SessionType: "Console",
			})
		}
	}

	currentUser := getCurrentWindowsUser()
	logs = append(logs, fmt.Sprintf("PowerShell method found %d unique sessions", len(sessions)))
	return sessions, currentUser, nil, logs
}

// Method 1: Try query session command
func tryQuerySession() ([]UserSession, string, error) {
	cmd := exec.Command("query", "session")
	out, err := cmd.Output()
	if err != nil {
		return nil, "", err
	}

	sessions := parseWindowsSessions(string(out))
	currentUser := getCurrentWindowsUser()
	return sessions, currentUser, nil
}

// Method 2: Try qwinsta command
func tryQwinsta() ([]UserSession, string, error) {
	cmd := exec.Command("qwinsta")
	out, err := cmd.Output()
	if err != nil {
		return nil, "", err
	}

	sessions := parseWindowsSessions(string(out))
	currentUser := getCurrentWindowsUser()
	return sessions, currentUser, nil
}

// Method 3: Try PowerShell Get-Process with session info
func tryPowerShellSessions() ([]UserSession, string, error) {
	script := `
	Get-Process -IncludeUserName | 
	Where-Object {$_.UserName -and $_.SessionId -ge 0} | 
	Group-Object SessionId, UserName | 
	ForEach-Object {
		$session = $_.Group[0]
		"$($session.SessionId):$($session.UserName):Active"
	} | Sort-Object -Unique
	`

	cmd := exec.Command("powershell", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		return nil, "", err
	}

	var sessions []UserSession
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			sessions = append(sessions, UserSession{
				Username:    parts[1],
				SessionID:   parts[0],
				SessionName: "session" + parts[0],
				State:       "Active",
				LoginTime:   "",
				Terminal:    "session" + parts[0],
				SessionType: "Console",
			})
		}
	}

	currentUser := getCurrentWindowsUser()
	return sessions, currentUser, nil
}

// Method 4: Try WMI Win32_LoggedOnUser (most compatible)
func tryWMILoggedUsers() ([]UserSession, string, error) {
	script := `
	Get-WmiObject -Class Win32_LoggedOnUser | 
	ForEach-Object {
		$user = ([wmi]$_.Antecedent)
		$session = ([wmi]$_.Dependent)
		"$($session.LogonId):$($user.Name):Active:$($session.LogonType)"
	} | Sort-Object -Unique
	`

	cmd := exec.Command("powershell", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		return nil, "", err
	}

	var sessions []UserSession
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[1] != "" {
			sessionType := "Unknown"
			if len(parts) >= 4 {
				sessionType = mapLogonType(parts[3])
			}

			sessions = append(sessions, UserSession{
				Username:    parts[1],
				SessionID:   parts[0],
				SessionName: "logon" + parts[0],
				State:       "Active",
				LoginTime:   "",
				Terminal:    "logon" + parts[0],
				SessionType: sessionType,
			})
		}
	}

	currentUser := getCurrentWindowsUser()
	return sessions, currentUser, nil
}

// parseWindowsSessions parses output from query session or qwinsta
func parseWindowsSessions(output string) []UserSession {
	lines := strings.Split(output, "\n")
	var sessions []UserSession

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		re := regexp.MustCompile(`\s*(\S+)\s+(\S*)\s+(\d+)\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?`)
		matches := re.FindStringSubmatch(line)

		if len(matches) >= 5 {
			username := matches[2]
			sessionState := matches[4]

			if username != "" && username != " " {
				session := UserSession{
					Username:    username,
					SessionID:   matches[3],
					SessionName: matches[1],
					State:       mapWindowsState(sessionState),
					LoginTime:   "",
					Terminal:    matches[1],
					SessionType: determineWindowsSessionType(matches[1]),
				}
				sessions = append(sessions, session)
			}
		}
	}

	return sessions
}

// getCurrentWindowsUser gets the current system user
func getCurrentWindowsUser() string {
	// Try multiple methods
	methods := []func() string{
		func() string {
			if result := getPowerShellWMIValue("Win32_ComputerSystem", "UserName"); result != "" {
				return result
			}
			return ""
		},
		func() string {
			cmd := exec.Command("whoami")
			if out, err := cmd.Output(); err == nil {
				return strings.TrimSpace(string(out))
			}
			return ""
		},
		func() string {
			if username := os.Getenv("USERNAME"); username != "" {
				if domain := os.Getenv("USERDOMAIN"); domain != "" {
					return domain + "\\" + username
				}
				return username
			}
			return ""
		},
	}

	for _, method := range methods {
		if user := method(); user != "" {
			return user
		}
	}

	return ""
}

// Enhanced method 4: Try WMI Win32_LoggedOnUser
func tryWMILoggedUsersEnhanced() ([]UserSession, string, error, []string) {
	var logs []string
	logs = append(logs, "Trying WMI Win32_LoggedOnUser query")

	script := `
	Get-WmiObject -Class Win32_LoggedOnUser | 
	ForEach-Object {
		$user = ([wmi]$_.Antecedent)
		$session = ([wmi]$_.Dependent)
		"$($session.LogonId):$($user.Name):Active:$($session.LogonType)"
	} | Sort-Object -Unique
	`

	cmd := exec.Command("powershell", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		logs = append(logs, fmt.Sprintf("WMI Win32_LoggedOnUser failed: %v", err))
		return nil, "", err, logs
	}

	logs = append(logs, "WMI Win32_LoggedOnUser executed successfully")

	var sessions []UserSession
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[1] != "" {
			sessionType := "Unknown"
			if len(parts) >= 4 {
				sessionType = mapLogonType(parts[3])
			}

			sessions = append(sessions, UserSession{
				Username:    parts[1],
				SessionID:   parts[0],
				SessionName: "logon" + parts[0],
				State:       "Active",
				LoginTime:   "",
				Terminal:    "logon" + parts[0],
				SessionType: sessionType,
			})
		}
	}

	currentUser := getCurrentWindowsUser()
	logs = append(logs, fmt.Sprintf("WMI method found %d sessions", len(sessions)))
	return sessions, currentUser, nil, logs
}

// mapLogonType converts Windows logon type numbers to readable names
func mapLogonType(logonType string) string {
	switch logonType {
	case "2":
		return "Interactive"
	case "3":
		return "Network"
	case "4":
		return "Batch"
	case "5":
		return "Service"
	case "7":
		return "Unlock"
	case "8":
		return "NetworkCleartext"
	case "9":
		return "NewCredentials"
	case "10":
		return "RemoteInteractive"
	case "11":
		return "CachedInteractive"
	default:
		return "Unknown"
	}
}

func getLoggedUsersUnix() CommandResult {
	var logs []string
	logs = append(logs, "Starting Unix user session analysis")
	logs = append(logs, "Using 'who' command to get logged users")

	cmd := exec.Command("who")
	out, err := cmd.Output()
	if err != nil {
		errorMsg := fmt.Sprintf("Error getting logged users: %v", err)
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	lines := strings.Split(string(out), "\n")
	var users []UserSession

	logs = append(logs, fmt.Sprintf("Processing %d lines from who command", len(lines)))

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 3 {
			user := UserSession{
				Username:    parts[0],
				SessionID:   fmt.Sprintf("%d", i), // Unix doesn't have session IDs like Windows
				SessionName: parts[1],
				State:       "Active", // If listed in 'who', assume active
				LoginTime:   strings.Join(parts[2:], " "),
				Terminal:    parts[1],
				SessionType: determineUnixSessionType(parts[1]),
			}
			users = append(users, user)
			logs = append(logs, fmt.Sprintf("Found user: %s on %s", parts[0], parts[1]))
		}
	}

	// Get current user
	currentUser := ""
	if whoamiOut, err := exec.Command("whoami").Output(); err == nil {
		currentUser = strings.TrimSpace(string(whoamiOut))
		logs = append(logs, fmt.Sprintf("Current user identified as: %s", currentUser))
	} else {
		logs = append(logs, "Warning: Could not identify current user")
	}

	// Build session type summary
	sessionSummary := make(map[string]int)
	for _, user := range users {
		sessionSummary[user.SessionType]++
	}

	// Standardized response format
	result := map[string]interface{}{
		"logged_users":    users,
		"total_users":     len(users),
		"current_user":    currentUser,
		"platform":        runtime.GOOS,
		"method_used":     "who_command",
		"session_summary": sessionSummary,
		"active_sessions": len(users), // All listed users are considered active
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}

	logs = append(logs, fmt.Sprintf("Successfully found %d active user sessions", len(users)))

	return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
}

// mapWindowsState converts Windows session states to standardized states
func mapWindowsState(windowsState string) string {
	switch strings.ToLower(windowsState) {
	case "active":
		return "Active"
	case "disc":
		return "Disconnected"
	case "listen":
		return "Listening"
	default:
		return windowsState
	}
}

// determineWindowsSessionType determines session type from session name
func determineWindowsSessionType(sessionName string) string {
	sessionName = strings.ToLower(sessionName)
	if strings.Contains(sessionName, "console") {
		return "Console"
	} else if strings.Contains(sessionName, "rdp") {
		return "RDP"
	} else if strings.Contains(sessionName, "services") {
		return "System"
	}
	return "Unknown"
}

// determineUnixSessionType determines session type from terminal name
func determineUnixSessionType(terminal string) string {
	if strings.Contains(terminal, "console") {
		return "Console"
	} else if strings.Contains(terminal, "tty") {
		return "Terminal"
	} else if strings.Contains(terminal, "pts") {
		return "SSH/Terminal"
	}
	return "Unknown"
}

// SECURE REPLACEMENTS for session-based commands in command.go

// logoffUser logs off a user by session ID or username with enhanced security validation
func logoffUser(params map[string]interface{}) CommandResult {
	var logs []string
	logs = append(logs, "User logoff operation initiated with security validation")

	if params == nil {
		errorMsg := "Parameters required for logoff_user command"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	sessionID, hasSessionID := params["session_id"].(string)
	username, hasUsername := params["username"].(string)

	if !hasSessionID && !hasUsername {
		errorMsg := "Either session_id or username parameter is required"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	if runtime.GOOS != "windows" {
		errorMsg := "User logoff is only supported on Windows"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// SECURITY: Validate session ID if provided
	if hasSessionID {
		logs = append(logs, "Validating session ID format for security")
		if err := validateSessionID(sessionID); err != nil {
			errorMsg := fmt.Sprintf("Invalid session ID: %v", err)
			logs = append(logs, errorMsg)
			logs = append(logs, "SECURITY: Session ID validation failed - potential injection attempt")
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}
		logs = append(logs, "Session ID validation passed")
	}

	// SECURITY: Validate username if provided
	if hasUsername {
		logs = append(logs, "Validating username format for security")
		if err := validateUsername(username); err != nil {
			errorMsg := fmt.Sprintf("Invalid username: %v", err)
			logs = append(logs, errorMsg)
			logs = append(logs, "SECURITY: Username validation failed - potential injection attempt")
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}
		logs = append(logs, "Username validation passed")
	}

	// If username is provided, find the session ID first
	if hasUsername && !hasSessionID {
		logs = append(logs, fmt.Sprintf("Looking up session ID for username: %s", username))
		sessionID = findSessionByUsernameSecure(username)
		if sessionID == "" {
			errorMsg := fmt.Sprintf("No active session found for user: %s", username)
			logs = append(logs, errorMsg)
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}
		logs = append(logs, fmt.Sprintf("Found session ID %s for user %s", sessionID, username))
	}

	logs = append(logs, fmt.Sprintf("Attempting to logoff session ID: %s", sessionID))

	// Execute logoff command with validated session ID using full system path
	logoffPath := filepath.Join(os.Getenv("WINDIR"), "System32", "logoff.exe")
	cmd := exec.Command(logoffPath, sessionID)
	out, err := cmd.CombinedOutput()

	if err != nil {
		errorMsg := fmt.Sprintf("Failed to logoff session %s: %v", sessionID, err)
		logs = append(logs, errorMsg)
		if len(out) > 0 {
			logs = append(logs, fmt.Sprintf("Command output: %s", strings.TrimSpace(string(out))))
		}

		result := map[string]interface{}{
			"success":    false,
			"session_id": sessionID,
			"error":      errorMsg,
			"output":     strings.TrimSpace(string(out)),
		}

		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	logs = append(logs, fmt.Sprintf("Successfully initiated logoff for session %s", sessionID))
	if len(out) > 0 {
		logs = append(logs, fmt.Sprintf("Command output: %s", strings.TrimSpace(string(out))))
	}

	result := map[string]interface{}{
		"success":    true,
		"session_id": sessionID,
		"message":    fmt.Sprintf("Successfully logged off session %s", sessionID),
		"output":     strings.TrimSpace(string(out)),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"method":     "secure_logoff_operation",
	}

	if hasUsername {
		result["username"] = username
		logs = append(logs, fmt.Sprintf("Logoff completed for user %s (session %s)", username, sessionID))
	}

	return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
}

// findSessionByUsernameSecure finds the session ID for a given username with security validation
func findSessionByUsernameSecure(username string) string {
	// SECURITY: Validate username before using in commands
	if err := validateUsername(username); err != nil {
		log.Printf("SECURITY: Invalid username in session lookup: %v", err)
		return ""
	}

	// Use quser to get logged in users with session IDs
	cmd := exec.Command("quser")
	out, err := cmd.Output()
	if err != nil {
		// Fallback to query user
		cmd = exec.Command("query", "user")
		out, err = cmd.Output()
		if err != nil {
			return ""
		}
	}

	lines := strings.Split(string(out), "\n")

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header and empty lines
		}

		// Use regex to parse the quser output line (USERNAME SESSIONNAME ID STATE)
		re := regexp.MustCompile(`^\s*(\S+)\s+(\S*)\s+(\d+)\s+(\S+)`)
		matches := re.FindStringSubmatch(line)

		if len(matches) >= 4 {
			sessionUsername := strings.TrimSpace(matches[1])
			sessionID := strings.TrimSpace(matches[3])
			sessionState := strings.TrimSpace(matches[4])

			// SECURITY: Validate the session ID we found before returning it
			if err := validateSessionID(sessionID); err != nil {
				log.Printf("SECURITY: Found invalid session ID in session lookup: %v", err)
				continue
			}

			// Match username (case insensitive) and ensure it's an active or disconnected session
			if strings.EqualFold(sessionUsername, username) &&
				(sessionState == "Active" || sessionState == "Disc") {
				return sessionID
			}
		}
	}

	return ""
}

// SECURE REPLACEMENT for rebootComputer with input validation
func rebootComputer(params map[string]interface{}) CommandResult {
	var logs []string
	logs = append(logs, "Reboot command initiated with security validation")

	// Default delay is 30 seconds, can be overridden with parameters
	delay := "30"
	if params != nil {
		if delayParam, ok := params["delay"].(string); ok {
			logs = append(logs, "Custom delay parameter provided")

			// SECURITY: Validate delay parameter
			if err := validateDelayParameter(delayParam); err != nil {
				errorMsg := fmt.Sprintf("Invalid delay parameter: %v", err)
				logs = append(logs, errorMsg)
				logs = append(logs, "SECURITY: Delay parameter validation failed - potential injection attempt")
				return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
			}

			delay = delayParam
			logs = append(logs, fmt.Sprintf("Delay parameter validation passed: %s seconds", delay))
		} else {
			logs = append(logs, "Using default delay: 30 seconds")
		}
	} else {
		logs = append(logs, "No parameters provided, using default delay: 30 seconds")
	}

	var cmd *exec.Cmd
	var method string

	if runtime.GOOS == "windows" {
		// Windows: shutdown /r /t [seconds] /f (force)
		method = "windows_shutdown_command"
		cmd = exec.Command("shutdown", "/r", "/t", delay, "/f", "/c", "System reboot initiated remotely")
		logs = append(logs, fmt.Sprintf("Using Windows shutdown command: shutdown /r /t %s /f", delay))
	} else if runtime.GOOS == "darwin" {
		// macOS: sudo shutdown -r +[minutes]
		method = "macos_shutdown_command"
		minutes := "1" // Convert seconds to minutes (minimum 1)
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("sudo", "shutdown", "-r", "+"+minutes)
		logs = append(logs, fmt.Sprintf("Using macOS shutdown command: sudo shutdown -r +%s", minutes))
		logs = append(logs, fmt.Sprintf("Note: Converted %s seconds to %s minutes (macOS minimum)", delay, minutes))
	} else {
		// Linux: shutdown -r +[minutes]
		method = "linux_shutdown_command"
		minutes := "1"
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("shutdown", "-r", "+"+minutes)
		logs = append(logs, fmt.Sprintf("Using Linux shutdown command: shutdown -r +%s", minutes))
		logs = append(logs, fmt.Sprintf("Note: Converted %s seconds to %s minutes", delay, minutes))
	}

	logs = append(logs, "Executing reboot command...")
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		errorMsg := fmt.Sprintf("Failed to initiate reboot: %v", err)
		logs = append(logs, errorMsg)
		if outputStr != "" {
			logs = append(logs, fmt.Sprintf("Command output: %s", outputStr))
		}

		result := map[string]interface{}{
			"success": false,
			"error":   errorMsg,
			"output":  outputStr,
			"method":  method,
			"delay":   delay,
		}

		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	logs = append(logs, "Reboot command executed successfully")
	if outputStr != "" {
		logs = append(logs, fmt.Sprintf("Command output: %s", outputStr))
	}
	logs = append(logs, "CRITICAL: System will reboot - agent will be offline during restart")

	result := map[string]interface{}{
		"success":   true,
		"message":   fmt.Sprintf("System reboot initiated - will reboot in %s seconds", delay),
		"delay":     delay,
		"platform":  runtime.GOOS,
		"method":    method + "_secure",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"output":    outputStr,
		"warning":   "System will restart and agent will be temporarily offline",
	}

	return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
}

// SECURE REPLACEMENT for shutdownComputer with input validation
func shutdownComputer(params map[string]interface{}) CommandResult {
	var logs []string
	logs = append(logs, "Shutdown command initiated with security validation")

	// Default delay is 30 seconds, can be overridden with parameters
	delay := "30"
	if params != nil {
		if delayParam, ok := params["delay"].(string); ok {
			logs = append(logs, "Custom delay parameter provided")

			// SECURITY: Validate delay parameter
			if err := validateDelayParameter(delayParam); err != nil {
				errorMsg := fmt.Sprintf("Invalid delay parameter: %v", err)
				logs = append(logs, errorMsg)
				logs = append(logs, "SECURITY: Delay parameter validation failed - potential injection attempt")
				return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
			}

			delay = delayParam
			logs = append(logs, fmt.Sprintf("Delay parameter validation passed: %s seconds", delay))
		} else {
			logs = append(logs, "Using default delay: 30 seconds")
		}
	} else {
		logs = append(logs, "No parameters provided, using default delay: 30 seconds")
	}

	var cmd *exec.Cmd
	var method string

	if runtime.GOOS == "windows" {
		// Windows: shutdown /s /t [seconds] /f (force)
		method = "windows_shutdown_command"
		cmd = exec.Command("shutdown", "/s", "/t", delay, "/f", "/c", "System shutdown initiated remotely")
		logs = append(logs, fmt.Sprintf("Using Windows shutdown command: shutdown /s /t %s /f", delay))
	} else if runtime.GOOS == "darwin" {
		// macOS: sudo shutdown -h +[minutes]
		method = "macos_shutdown_command"
		minutes := "1"
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("sudo", "shutdown", "-h", "+"+minutes)
		logs = append(logs, fmt.Sprintf("Using macOS shutdown command: sudo shutdown -h +%s", minutes))
		logs = append(logs, fmt.Sprintf("Note: Converted %s seconds to %s minutes (macOS minimum)", delay, minutes))
	} else {
		// Linux: shutdown -h +[minutes]
		method = "linux_shutdown_command"
		minutes := "1"
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("shutdown", "-h", "+"+minutes)
		logs = append(logs, fmt.Sprintf("Using Linux shutdown command: shutdown -h +%s", minutes))
		logs = append(logs, fmt.Sprintf("Note: Converted %s seconds to %s minutes", delay, minutes))
	}

	logs = append(logs, "Executing shutdown command...")
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		errorMsg := fmt.Sprintf("Failed to initiate shutdown: %v", err)
		logs = append(logs, errorMsg)
		if outputStr != "" {
			logs = append(logs, fmt.Sprintf("Command output: %s", outputStr))
		}

		result := map[string]interface{}{
			"success": false,
			"error":   errorMsg,
			"output":  outputStr,
			"method":  method,
			"delay":   delay,
		}

		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	logs = append(logs, "Shutdown command executed successfully")
	if outputStr != "" {
		logs = append(logs, fmt.Sprintf("Command output: %s", outputStr))
	}
	logs = append(logs, "CRITICAL: System will shutdown - agent will be offline")

	result := map[string]interface{}{
		"success":   true,
		"message":   fmt.Sprintf("System shutdown initiated - will shutdown in %s seconds", delay),
		"delay":     delay,
		"platform":  runtime.GOOS,
		"method":    method + "_secure",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"output":    outputStr,
		"warning":   "System will shutdown and agent will be offline until manually restarted",
	}

	return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
}

// findSessionByUsername finds the session ID for a given username with enhanced logging
func findSessionByUsername(username string) string {
	// Try query session first
	cmd := exec.Command("query", "session")
	out, err := cmd.Output()
	if err != nil {
		// Fallback to qwinsta
		cmd = exec.Command("qwinsta")
		out, err = cmd.Output()
		if err != nil {
			return ""
		}
	}

	lines := strings.Split(string(out), "\n")

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header and empty lines
		}

		// Use regex to parse the session line
		re := regexp.MustCompile(`\s*(\S+)\s+(\S*)\s+(\d+)\s+(\S+)`)
		matches := re.FindStringSubmatch(line)

		if len(matches) >= 4 {
			sessionUsername := strings.TrimSpace(matches[2])
			sessionID := strings.TrimSpace(matches[3])
			sessionState := strings.TrimSpace(matches[4])

			// Match username (case insensitive) and ensure it's an active or disconnected session
			if strings.EqualFold(sessionUsername, username) &&
				(sessionState == "Active" || sessionState == "Disc") {
				return sessionID
			}
		}
	}

	return ""
}

// getAvailableCommands returns a structured list of available commands with enhanced information
func getAvailableCommands() CommandResult {
	var logs []string
	logs = append(logs, "Generating available commands list")

	commands := []map[string]interface{}{
		{
			"command":     "hostname",
			"category":    "system_info",
			"description": "Get system hostname with timestamp",
			"parameters":  "None",
			"example":     `{"command": "hostname"}`,
			"output_type": "json",
			"security":    "low",
		},
		{
			"command":     "whoami",
			"category":    "system_info",
			"description": "Get current user with platform information",
			"parameters":  "None",
			"example":     `{"command": "whoami"}`,
			"output_type": "json",
			"security":    "low",
		},
		{
			"command":     "uptime",
			"category":    "system_info",
			"description": "Get system uptime with calculated duration",
			"parameters":  "None",
			"example":     `{"command": "uptime"}`,
			"output_type": "json",
			"security":    "low",
		},
		{
			"command":     "disk_space",
			"category":    "system_monitoring",
			"description": "Get disk usage information with summary statistics",
			"parameters":  "None",
			"example":     `{"command": "disk_space"}`,
			"output_type": "json",
			"security":    "low",
		},
		{
			"command":     "memory",
			"category":    "system_monitoring",
			"description": "Get memory information with usage statistics",
			"parameters":  "None",
			"example":     `{"command": "memory"}`,
			"output_type": "json",
			"security":    "low",
		},
		{
			"command":     "processes",
			"category":    "system_monitoring",
			"description": "Get running processes sorted by resource usage",
			"parameters":  "None",
			"example":     `{"command": "processes"}`,
			"output_type": "json",
			"security":    "medium",
		},
		{
			"command":     "network",
			"category":    "system_monitoring",
			"description": "Get network configuration with adapter details",
			"parameters":  "None",
			"example":     `{"command": "network"}`,
			"output_type": "json",
			"security":    "medium",
		},
		{
			"command":     "system_info",
			"category":    "system_info",
			"description": "Get comprehensive system information",
			"parameters":  "None",
			"example":     `{"command": "system_info"}`,
			"output_type": "json",
			"security":    "low",
		},
		{
			"command":     "logged_users",
			"category":    "user_management",
			"description": "Get all logged in users with session details (including RDP)",
			"parameters":  "None",
			"example":     `{"command": "logged_users"}`,
			"output_type": "json",
			"security":    "medium",
		},
		{
			"command":     "logoff_user",
			"category":    "user_management",
			"description": "Log off a user by session ID or username (Windows only)",
			"parameters":  "session_id (string) OR username (string)",
			"example":     `{"command": "logoff_user", "parameters": "{\"session_id\": \"2\"}"} or {"command": "logoff_user", "parameters": "{\"username\": \"john.doe\"}"}`,
			"output_type": "json",
			"security":    "high",
			"platform":    "windows",
		},
		{
			"command":     "capture_screen",
			"category":    "remote_control",
			"description": "Capture and compress screen of a user session",
			"parameters":  "session_id (string) OR username (string)",
			"example":     `{"command": "capture_screen", "parameters": "{\"session_id\": \"1\"}"} or {"command": "capture_screen", "parameters": "{\"username\": \"john.doe\"}"}`,
			"output_type": "json_with_binary",
			"security":    "high",
			"platform":    "windows",
		},
		{
			"command":     "ping",
			"category":    "connectivity",
			"description": "Check if device is online and update last_seen timestamp",
			"parameters":  "None",
			"example":     `{"command": "ping"}`,
			"output_type": "json",
			"security":    "low",
		},
		{
			"command":     "reboot",
			"category":    "power_management",
			"description": "Reboot the computer with optional delay",
			"parameters":  "delay (string, optional) - seconds to wait before reboot (default: 30)",
			"example":     `{"command": "reboot"} or {"command": "reboot", "parameters": "{\"delay\": \"60\"}"}`,
			"output_type": "json",
			"security":    "critical",
		},
		{
			"command":     "shutdown",
			"category":    "power_management",
			"description": "Shutdown the computer with optional delay",
			"parameters":  "delay (string, optional) - seconds to wait before shutdown (default: 30)",
			"example":     `{"command": "shutdown"} or {"command": "shutdown", "parameters": "{\"delay\": \"120\"}"}`,
			"output_type": "json",
			"security":    "critical",
		},
		{
			"command":     "hyperv_inventory",
			"category":    "virtualization",
			"description": "Get inventory of all Hyper-V virtual machines (live data only)",
			"parameters":  "None",
			"example":     `{"command": "hyperv_inventory"}`,
			"output_type": "json",
			"security":    "medium",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_inventory_db",
			"category":    "virtualization",
			"description": "Get inventory of all Hyper-V virtual machines and update database",
			"parameters":  "None",
			"example":     `{"command": "hyperv_inventory_db"}`,
			"output_type": "json",
			"security":    "medium",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_get_vms",
			"category":    "virtualization",
			"description": "Get VMs from database (fast query, no PowerShell)",
			"parameters":  "None",
			"example":     `{"command": "hyperv_get_vms"}`,
			"output_type": "json",
			"security":    "low",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_sync",
			"category":    "virtualization",
			"description": "Sync with PowerShell and return updated database data",
			"parameters":  "None",
			"example":     `{"command": "hyperv_sync"}`,
			"output_type": "json",
			"security":    "medium",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_screenshot",
			"category":    "virtualization",
			"description": "Capture screenshot of a VM console (VM must be running)",
			"parameters":  "vm_id (string) - VM GUID",
			"example":     `{"command": "hyperv_screenshot", "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789abc\"}"}`,
			"output_type": "json_with_binary",
			"security":    "medium",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_start",
			"category":    "virtualization",
			"description": "Start a virtual machine",
			"parameters":  "vm_id (string) - VM GUID",
			"example":     `{"command": "hyperv_start", "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789abc\"}"}`,
			"output_type": "json",
			"security":    "high",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_pause",
			"category":    "virtualization",
			"description": "Pause/suspend a virtual machine",
			"parameters":  "vm_id (string) - VM GUID",
			"example":     `{"command": "hyperv_pause", "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789abc\"}"}`,
			"output_type": "json",
			"security":    "high",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_reset",
			"category":    "virtualization",
			"description": "Reset a virtual machine",
			"parameters":  "vm_id (string) - VM GUID",
			"example":     `{"command": "hyperv_reset", "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789abc\"}"}`,
			"output_type": "json",
			"security":    "high",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_turnoff",
			"category":    "virtualization",
			"description": "Force turn off a virtual machine",
			"parameters":  "vm_id (string) - VM GUID",
			"example":     `{"command": "hyperv_turnoff", "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789abc\"}"}`,
			"output_type": "json",
			"security":    "high",
			"platform":    "windows",
		},
		{
			"command":     "hyperv_shutdown",
			"category":    "virtualization",
			"description": "Gracefully shutdown a virtual machine",
			"parameters":  "vm_id (string) - VM GUID",
			"example":     `{"command": "hyperv_shutdown", "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789abc\"}"}`,
			"output_type": "json",
			"security":    "high",
			"platform":    "windows",
		},
		{
			"command":     "help",
			"category":    "system",
			"description": "Get structured list of available commands with categories",
			"parameters":  "None",
			"example":     `{"command": "help"}`,
			"output_type": "json",
			"security":    "low",
		},
	}

	// Build category summary
	categoryStats := make(map[string]int)
	securityStats := make(map[string]int)
	platformStats := make(map[string]int)

	for _, cmd := range commands {
		if category, ok := cmd["category"].(string); ok {
			categoryStats[category]++
		}
		if security, ok := cmd["security"].(string); ok {
			securityStats[security]++
		}
		if platform, ok := cmd["platform"].(string); ok {
			platformStats[platform]++
		} else {
			platformStats["cross_platform"]++
		}
	}

	logs = append(logs, fmt.Sprintf("Generated %d command definitions", len(commands)))
	logs = append(logs, fmt.Sprintf("Categories: %v", categoryStats))
	logs = append(logs, fmt.Sprintf("Security levels: %v", securityStats))
	logs = append(logs, fmt.Sprintf("Platform distribution: %v", platformStats))

	result := map[string]interface{}{
		"available_commands": commands,
		"total_commands":     len(commands),
		"category_summary":   categoryStats,
		"security_summary":   securityStats,
		"platform_summary":   platformStats,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
		"agent_platform":     runtime.GOOS,
		"command_categories": []string{"system_info", "system_monitoring", "user_management", "remote_control", "connectivity", "power_management", "virtualization", "system"},
		"security_levels":    []string{"low", "medium", "high", "critical"},
	}

	return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
}
