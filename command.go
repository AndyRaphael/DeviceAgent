package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// CommandResult represents the result of a command execution
type CommandResult struct {
	Output         interface{} `json:"output"`
	Error          string      `json:"error"`
	Status         string      `json:"status"`
	ScreenshotData string      `json:"screenshot_data,omitempty"`
}

// ExecuteCommand is the main dispatcher that calls specific command functions
func ExecuteCommand(command string, parameters string) CommandResult {
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

// rebootComputer reboots the computer with optional delay
func rebootComputer(params map[string]interface{}) CommandResult {
	// Default delay is 30 seconds, can be overridden with parameters
	delay := "30"
	if params != nil {
		if delayParam, ok := params["delay"].(string); ok {
			delay = delayParam
		}
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Windows: shutdown /r /t [seconds] /f (force)
		cmd = exec.Command("shutdown", "/r", "/t", delay, "/f", "/c", "System reboot initiated remotely")
	} else if runtime.GOOS == "darwin" {
		// macOS: sudo shutdown -r +[minutes]
		minutes := "1" // Convert seconds to minutes (minimum 1)
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("sudo", "shutdown", "-r", "+"+minutes)
	} else {
		// Linux: shutdown -r +[minutes]
		minutes := "1"
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("shutdown", "-r", "+"+minutes)
	}

	output, err := cmd.CombinedOutput()

	if err != nil {
		return CommandResult{
			Output: map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Failed to initiate reboot: %v", err),
				"output":  strings.TrimSpace(string(output)),
			},
			Error:  fmt.Sprintf("Failed to initiate reboot: %v", err),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"success":   true,
			"message":   fmt.Sprintf("System reboot initiated - will reboot in %s seconds", delay),
			"delay":     delay,
			"platform":  runtime.GOOS,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"output":    strings.TrimSpace(string(output)),
		},
		Error:  "",
		Status: "success",
	}
}

// shutdownComputer shuts down the computer with optional delay
func shutdownComputer(params map[string]interface{}) CommandResult {
	// Default delay is 30 seconds, can be overridden with parameters
	delay := "30"
	if params != nil {
		if delayParam, ok := params["delay"].(string); ok {
			delay = delayParam
		}
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Windows: shutdown /s /t [seconds] /f (force)
		cmd = exec.Command("shutdown", "/s", "/t", delay, "/f", "/c", "System shutdown initiated remotely")
	} else if runtime.GOOS == "darwin" {
		// macOS: sudo shutdown -h +[minutes]
		minutes := "1"
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("sudo", "shutdown", "-h", "+"+minutes)
	} else {
		// Linux: shutdown -h +[minutes]
		minutes := "1"
		if d, err := strconv.Atoi(delay); err == nil && d >= 60 {
			minutes = strconv.Itoa(d / 60)
		}
		cmd = exec.Command("shutdown", "-h", "+"+minutes)
	}

	output, err := cmd.CombinedOutput()

	if err != nil {
		return CommandResult{
			Output: map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Failed to initiate shutdown: %v", err),
				"output":  strings.TrimSpace(string(output)),
			},
			Error:  fmt.Sprintf("Failed to initiate shutdown: %v", err),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"success":   true,
			"message":   fmt.Sprintf("System shutdown initiated - will shutdown in %s seconds", delay),
			"delay":     delay,
			"platform":  runtime.GOOS,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"output":    strings.TrimSpace(string(output)),
		},
		Error:  "",
		Status: "success",
	}
}

// pingDevice responds with system status and updates last_seen
func pingDevice() CommandResult {
	currentTime := time.Now().UTC()

	// Get basic system info
	hostname, _ := exec.Command("hostname").Output()

	uptime := ""
	if runtime.GOOS == "windows" {
		if result := getPowerShellWMIValue("Win32_OperatingSystem", "LastBootUpTime"); result != "" {
			uptime = formatWMIDate(result)
		}
	} else {
		if out, err := exec.Command("uptime").Output(); err == nil {
			uptime = strings.TrimSpace(string(out))
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"status":           "online",
			"hostname":         strings.TrimSpace(string(hostname)),
			"timestamp":        currentTime.Format(time.RFC3339),
			"uptime":           uptime,
			"response_time_ms": "< 1000",
			"message":          "Device is online and responding",
		},
		Error:  "",
		Status: "success",
	}
}

// getHostname returns the system hostname
func getHostname() CommandResult {
	out, err := exec.Command("hostname").Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting hostname: %v", err)},
			Error:  fmt.Sprintf("Error getting hostname: %v", err),
			Status: "error",
		}
	}
	return CommandResult{
		Output: map[string]string{"hostname": strings.TrimSpace(string(out))},
		Error:  "",
		Status: "success",
	}
}

// getWhoami returns the current user
func getWhoami() CommandResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("whoami")
	} else {
		cmd = exec.Command("whoami")
	}

	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting current user: %v", err)},
			Error:  fmt.Sprintf("Error getting current user: %v", err),
			Status: "error",
		}
	}
	return CommandResult{
		Output: map[string]string{"current_user": strings.TrimSpace(string(out))},
		Error:  "",
		Status: "success",
	}
}

// getUptime returns system uptime
func getUptime() CommandResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("wmic", "os", "get", "LastBootUpTime", "/value")
	} else {
		cmd = exec.Command("uptime")
	}

	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting uptime: %v", err)},
			Error:  fmt.Sprintf("Error getting uptime: %v", err),
			Status: "error",
		}
	}

	result := strings.TrimSpace(string(out))
	return CommandResult{
		Output: map[string]string{"uptime": result},
		Error:  "",
		Status: "success",
	}
}

// getDiskSpace returns disk usage information
func getDiskSpace() CommandResult {
	if runtime.GOOS == "windows" {
		return getDiskSpaceWindows()
	}
	return getDiskSpaceUnix()
}

func getDiskSpaceWindows() CommandResult {
	cmd := exec.Command("wmic", "logicaldisk", "get", "size,freespace,caption", "/format:csv")
	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting disk space: %v", err)},
			Error:  fmt.Sprintf("Error getting disk space: %v", err),
			Status: "error",
		}
	}

	lines := strings.Split(string(out), "\n")
	var disks []map[string]interface{}

	for _, line := range lines[1:] { // Skip header
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) >= 4 {
			freeSpace, _ := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
			totalSize, _ := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64)

			if totalSize > 0 {
				disk := map[string]interface{}{
					"drive":        strings.TrimSpace(parts[1]),
					"total_gb":     float64(totalSize) / (1024 * 1024 * 1024),
					"free_gb":      float64(freeSpace) / (1024 * 1024 * 1024),
					"used_gb":      float64(totalSize-freeSpace) / (1024 * 1024 * 1024),
					"used_percent": float64(totalSize-freeSpace) / float64(totalSize) * 100,
				}
				disks = append(disks, disk)
			}
		}
	}

	return CommandResult{
		Output: map[string]interface{}{"disks": disks},
		Error:  "",
		Status: "success",
	}
}

func getDiskSpaceUnix() CommandResult {
	cmd := exec.Command("df", "-h")
	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting disk space: %v", err)},
			Error:  fmt.Sprintf("Error getting disk space: %v", err),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]string{"disk_usage": strings.TrimSpace(string(out))},
		Error:  "",
		Status: "success",
	}
}

// getMemoryInfo returns memory usage information
func getMemoryInfo() CommandResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("wmic", "computersystem", "get", "TotalPhysicalMemory", "/value")
	} else {
		cmd = exec.Command("free", "-h")
	}

	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting memory info: %v", err)},
			Error:  fmt.Sprintf("Error getting memory info: %v", err),
			Status: "error",
		}
	}
	return CommandResult{
		Output: map[string]string{"memory_info": strings.TrimSpace(string(out))},
		Error:  "",
		Status: "success",
	}
}

// getTopProcesses returns top running processes
func getTopProcesses() CommandResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("wmic", "process", "get", "name,processid,workingsetsize", "/format:csv")
	} else {
		cmd = exec.Command("sh", "-c", "ps aux --sort=-%cpu | head -10")
	}

	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting processes: %v", err)},
			Error:  fmt.Sprintf("Error getting processes: %v", err),
			Status: "error",
		}
	}
	return CommandResult{
		Output: map[string]string{"processes": strings.TrimSpace(string(out))},
		Error:  "",
		Status: "success",
	}
}

// getNetworkInfo returns network configuration
func getNetworkInfo() CommandResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ipconfig", "/all")
	} else {
		cmd = exec.Command("ifconfig")
	}

	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting network info: %v", err)},
			Error:  fmt.Sprintf("Error getting network info: %v", err),
			Status: "error",
		}
	}
	return CommandResult{
		Output: map[string]string{"network_config": strings.TrimSpace(string(out))},
		Error:  "",
		Status: "success",
	}
}

// getSystemInfo returns comprehensive system information
func getSystemInfo() CommandResult {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("systeminfo")
	} else {
		cmd = exec.Command("uname", "-a")
	}

	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting system info: %v", err)},
			Error:  fmt.Sprintf("Error getting system info: %v", err),
			Status: "error",
		}
	}
	return CommandResult{
		Output: map[string]string{"system_info": strings.TrimSpace(string(out))},
		Error:  "",
		Status: "success",
	}
}

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

// getLoggedUsers returns all logged in users (including disconnected RDP sessions)
func getLoggedUsers() CommandResult {
	if runtime.GOOS == "windows" {
		return getLoggedUsersWindows()
	}
	return getLoggedUsersUnix()
}

func getLoggedUsersWindows() CommandResult {
	// Try multiple methods in order of preference
	methods := []func() ([]UserSession, string, error){
		tryQuerySession,
		tryQwinsta,
		tryPowerShellSessions,
		tryWMILoggedUsers,
	}

	var lastError error
	for i, method := range methods {
		sessions, currentUser, err := method()
		if err == nil {
			log.Printf("Successfully got logged users using method %d", i+1)
			result := map[string]interface{}{
				"logged_users": sessions,
				"total_users":  len(sessions),
				"current_user": currentUser,
				"platform":     "windows",
			}

			return CommandResult{
				Output: result,
				Error:  "",
				Status: "success",
			}
		}
		lastError = err
		log.Printf("Method %d failed: %v", i+1, err)
	}

	// All methods failed
	return CommandResult{
		Output: map[string]string{"error": fmt.Sprintf("All methods failed, last error: %v", lastError)},
		Error:  fmt.Sprintf("Error getting logged users: %v", lastError),
		Status: "error",
	}
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
	cmd := exec.Command("who")
	out, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Error getting logged users: %v", err)},
			Error:  fmt.Sprintf("Error getting logged users: %v", err),
			Status: "error",
		}
	}

	lines := strings.Split(string(out), "\n")
	var users []UserSession

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 3 {
			user := UserSession{
				Username:    parts[0],
				SessionID:   "", // Unix doesn't have session IDs like Windows
				SessionName: parts[1],
				State:       "Active", // If listed in 'who', assume active
				LoginTime:   strings.Join(parts[2:], " "),
				Terminal:    parts[1],
				SessionType: determineUnixSessionType(parts[1]),
			}
			users = append(users, user)
		}
	}

	// Get current user
	currentUser := ""
	if whoamiOut, err := exec.Command("whoami").Output(); err == nil {
		currentUser = strings.TrimSpace(string(whoamiOut))
	}

	// Standardized response format
	result := map[string]interface{}{
		"logged_users": users,
		"total_users":  len(users),
		"current_user": currentUser,
		"platform":     runtime.GOOS,
	}

	return CommandResult{
		Output: result,
		Error:  "",
		Status: "success",
	}
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

// logoffUser logs off a user by session ID
func logoffUser(params map[string]interface{}) CommandResult {
	if params == nil {
		return CommandResult{
			Output: map[string]string{"error": "Parameters required for logoff_user command"},
			Error:  "Parameters required: {\"session_id\": \"1\"} or {\"username\": \"john.doe\"}",
			Status: "error",
		}
	}

	sessionID, hasSessionID := params["session_id"].(string)
	username, hasUsername := params["username"].(string)

	if !hasSessionID && !hasUsername {
		return CommandResult{
			Output: map[string]string{"error": "Either session_id or username parameter is required"},
			Error:  "Either session_id or username parameter is required",
			Status: "error",
		}
	}

	if runtime.GOOS != "windows" {
		return CommandResult{
			Output: map[string]string{"error": "User logoff is only supported on Windows"},
			Error:  "User logoff is only supported on Windows",
			Status: "error",
		}
	}

	// If username is provided, find the session ID first
	if hasUsername && !hasSessionID {
		sessionID = findSessionByUsername(username)
		if sessionID == "" {
			return CommandResult{
				Output: map[string]string{
					"error": fmt.Sprintf("No active session found for user: %s", username),
				},
				Error:  fmt.Sprintf("No active session found for user: %s", username),
				Status: "error",
			}
		}
	}

	// Execute logoff command
	cmd := exec.Command("logoff", sessionID)
	out, err := cmd.CombinedOutput()

	if err != nil {
		return CommandResult{
			Output: map[string]interface{}{
				"success":    false,
				"session_id": sessionID,
				"error":      fmt.Sprintf("Failed to logoff session %s: %v", sessionID, err),
				"output":     strings.TrimSpace(string(out)),
			},
			Error:  fmt.Sprintf("Failed to logoff session %s: %v", sessionID, err),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"success":    true,
			"session_id": sessionID,
			"message":    fmt.Sprintf("Successfully logged off session %s", sessionID),
			"output":     strings.TrimSpace(string(out)),
		},
		Error:  "",
		Status: "success",
	}
}

// findSessionByUsername finds the session ID for a given username
func findSessionByUsername(username string) string {
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

// getAvailableCommands returns a list of available commands
func getAvailableCommands() CommandResult {
	commands := []map[string]interface{}{
		{
			"command":     "hostname",
			"description": "Get system hostname",
			"parameters":  "None",
			"example":     `{"command": "hostname"}`,
		},
		{
			"command":     "whoami",
			"description": "Get current user",
			"parameters":  "None",
			"example":     `{"command": "whoami"}`,
		},
		{
			"command":     "uptime",
			"description": "Get system uptime",
			"parameters":  "None",
			"example":     `{"command": "uptime"}`,
		},
		{
			"command":     "disk_space",
			"description": "Get disk usage information",
			"parameters":  "None",
			"example":     `{"command": "disk_space"}`,
		},
		{
			"command":     "memory",
			"description": "Get memory information",
			"parameters":  "None",
			"example":     `{"command": "memory"}`,
		},
		{
			"command":     "processes",
			"description": "Get running processes",
			"parameters":  "None",
			"example":     `{"command": "processes"}`,
		},
		{
			"command":     "network",
			"description": "Get network configuration",
			"parameters":  "None",
			"example":     `{"command": "network"}`,
		},
		{
			"command":     "system_info",
			"description": "Get system information",
			"parameters":  "None",
			"example":     `{"command": "system_info"}`,
		},
		{
			"command":     "logged_users",
			"description": "Get all logged in users (including disconnected RDP sessions)",
			"parameters":  "None",
			"example":     `{"command": "logged_users"}`,
		},
		{
			"command":     "logoff_user",
			"description": "Log off a user by session ID or username",
			"parameters":  "session_id (string) OR username (string)",
			"example":     `{"command": "logoff_user", "parameters": "{\"session_id\": \"2\"}"} or {"command": "logoff_user", "parameters": "{\"username\": \"john.doe\"}"}`,
		},
		{
			"command":     "capture_screen",
			"description": "Capture and compress screen of a user session",
			"parameters":  "session_id (string) OR username (string)",
			"example":     `{"command": "capture_screen", "parameters": "{\"session_id\": \"1\"}"} or {"command": "capture_screen", "parameters": "{\"username\": \"john.doe\"}"}`,
		},
		{
			"command":     "ping",
			"description": "Check if device is online and update last_seen timestamp",
			"parameters":  "None",
			"example":     `{"command": "ping"}`,
		},
		{
			"command":     "reboot",
			"description": "Reboot the computer with optional delay",
			"parameters":  "delay (string, optional) - seconds to wait before reboot (default: 30)",
			"example":     `{"command": "reboot"} or {"command": "reboot", "parameters": "{\"delay\": \"60\"}"}`,
		},
		{
			"command":     "shutdown",
			"description": "Shutdown the computer with optional delay",
			"parameters":  "delay (string, optional) - seconds to wait before shutdown (default: 30)",
			"example":     `{"command": "shutdown"} or {"command": "shutdown", "parameters": "{\"delay\": \"120\"}"}`,
		},
		{
			"command":     "help",
			"description": "Get list of available commands",
			"parameters":  "None",
			"example":     `{"command": "help"}`,
		},
	}

	return CommandResult{
		Output: map[string]interface{}{"available_commands": commands},
		Error:  "",
		Status: "success",
	}
}
