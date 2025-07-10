package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
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

// validateVMID validates that a VM ID is a proper UUID format
func validateVMID(vmID string) error {
	if vmID == "" {
		return errors.New("VM ID cannot be empty")
	}

	// UUID v4 format: 8-4-4-4-12 hexadecimal digits
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if !uuidRegex.MatchString(vmID) {
		return errors.New("invalid VM ID format - must be valid UUID")
	}

	return nil
}

// validateSessionID validates that a session ID is numeric and reasonable
func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return errors.New("session ID cannot be empty")
	}

	// Must be numeric
	sessionNum, err := strconv.Atoi(sessionID)
	if err != nil {
		return errors.New("session ID must be numeric")
	}

	// Reasonable range for session IDs (0-999)
	if sessionNum < 0 || sessionNum > 999 {
		return errors.New("session ID out of valid range (0-999)")
	}

	return nil
}

// validateUsername validates that a username contains only safe characters
func validateUsername(username string) error {
	if username == "" {
		return errors.New("username cannot be empty")
	}

	// Check length (reasonable username length)
	if len(username) > 100 {
		return errors.New("username too long (max 100 characters)")
	}

	// Only allow alphanumeric, dots, hyphens, underscores, and backslashes (for domain\user)
	validUsernameRegex := regexp.MustCompile(`^[a-zA-Z0-9._\\-]+$`)
	if !validUsernameRegex.MatchString(username) {
		return errors.New("username contains invalid characters")
	}

	return nil
}

// validateDelayParameter validates delay parameters for reboot/shutdown
func validateDelayParameter(delay string) error {
	if delay == "" {
		return errors.New("delay parameter cannot be empty")
	}

	delayNum, err := strconv.Atoi(delay)
	if err != nil {
		return errors.New("delay must be a number")
	}

	// Reasonable delay range: 0 to 24 hours (86400 seconds)
	if delayNum < 0 || delayNum > 86400 {
		return errors.New("delay out of valid range (0-86400 seconds)")
	}

	return nil
}

// validateGeneralParameter validates general string parameters to prevent injection
func validateGeneralParameter(paramName, paramValue string) error {
	if paramValue == "" {
		return nil // Empty is often okay for optional parameters
	}

	// Check for potentially dangerous characters that could be used for injection
	dangerousChars := []string{
		";", "|", "&", "$", "`", "$(", "${",
		"'", "\"", "<", ">", "*", "?", "[", "]",
		"\n", "\r", "\t",
	}

	for _, char := range dangerousChars {
		if strings.Contains(paramValue, char) {
			return fmt.Errorf("parameter '%s' contains potentially dangerous character: %s", paramName, char)
		}
	}

	// Check for non-printable characters
	for _, char := range paramValue {
		if !unicode.IsPrint(char) && !unicode.IsSpace(char) {
			return fmt.Errorf("parameter '%s' contains non-printable characters", paramName)
		}
	}

	return nil
}

// sanitizeForPowerShell escapes a string for safe use in PowerShell commands
func sanitizeForPowerShell(input string) string {
	// Replace single quotes with doubled single quotes (PowerShell escaping)
	sanitized := strings.ReplaceAll(input, "'", "''")
	return sanitized
}

// NewSuccessResult creates a successful result with structured JSON data
func NewSuccessResult(data interface{}) CommandResult {
	return CommandResult{
		Result: data,
		Status: "success",
	}
}

// NewSuccessResultWithLogs creates a successful result with both data and logs
func NewSuccessResultWithLogs(data interface{}, logs string) CommandResult {
	return CommandResult{
		Result: data,
		Logs:   logs,
		Status: "success",
	}
}

// NewErrorResult creates an error result with logs only
func NewErrorResult(errorMsg string) CommandResult {
	return CommandResult{
		Logs:   errorMsg,
		Status: "error",
	}
}

// NewErrorResultWithDetails creates an error result with detailed logs
func NewErrorResultWithDetails(errorMsg, details string) CommandResult {
	logs := errorMsg
	if details != "" {
		logs += "\n\nDetails:\n" + details
	}
	return CommandResult{
		Logs:   logs,
		Status: "error",
	}
}

// AddLogs appends additional log information to existing logs
func (cr *CommandResult) AddLogs(additionalLogs string) {
	if cr.Logs == "" {
		cr.Logs = additionalLogs
	} else {
		cr.Logs += "\n" + additionalLogs
	}
}

// SetScreenshot adds screenshot data and updates the result with metadata
func (cr *CommandResult) SetScreenshot(base64Data string, metadata map[string]interface{}) {
	cr.ScreenshotData = base64Data
	if cr.Result == nil {
		cr.Result = make(map[string]interface{})
	}
	if resultMap, ok := cr.Result.(map[string]interface{}); ok {
		for key, value := range metadata {
			resultMap[key] = value
		}
	}
}

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

// pingDevice responds with system status and updates last_seen with comprehensive logging
func pingDevice() CommandResult {
	var logs []string
	logs = append(logs, "Ping command initiated")

	currentTime := time.Now().UTC()

	// Get basic system info
	hostname, err := exec.Command("hostname").Output()
	if err != nil {
		logs = append(logs, fmt.Sprintf("Warning: Could not get hostname: %v", err))
	} else {
		logs = append(logs, fmt.Sprintf("Retrieved hostname: %s", strings.TrimSpace(string(hostname))))
	}

	uptime := ""
	if runtime.GOOS == "windows" {
		logs = append(logs, "Retrieving Windows boot time via WMI")
		if result := getPowerShellWMIValue("Win32_OperatingSystem", "LastBootUpTime"); result != "" {
			uptime = formatWMIDate(result)
			logs = append(logs, "Successfully retrieved boot time from WMI")
		} else {
			logs = append(logs, "Warning: Could not retrieve boot time from WMI")
		}
	} else {
		logs = append(logs, "Retrieving uptime via system command")
		if out, err := exec.Command("uptime").Output(); err == nil {
			uptime = strings.TrimSpace(string(out))
			logs = append(logs, "Successfully retrieved uptime from system command")
		} else {
			logs = append(logs, fmt.Sprintf("Warning: Could not retrieve uptime: %v", err))
		}
	}

	// Build structured response
	data := map[string]interface{}{
		"status":           "online",
		"hostname":         strings.TrimSpace(string(hostname)),
		"timestamp":        currentTime.Format(time.RFC3339),
		"uptime":           uptime,
		"response_time_ms": "< 1000",
		"platform":         runtime.GOOS,
		"message":          "Device is online and responding",
	}

	logs = append(logs, "Ping completed successfully - device is online and responding")

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

// getHostname returns the system hostname with detailed logging
func getHostname() CommandResult {
	var logs []string
	logs = append(logs, "Starting hostname retrieval")

	out, err := exec.Command("hostname").Output()
	if err != nil {
		errorMsg := fmt.Sprintf("Error getting hostname: %v", err)
		logs = append(logs, errorMsg)
		logs = append(logs, "Command execution failed")
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	hostname := strings.TrimSpace(string(out))
	logs = append(logs, fmt.Sprintf("Successfully retrieved hostname: %s", hostname))
	logs = append(logs, "Hostname command completed successfully")

	// Return structured JSON data with logs
	data := map[string]interface{}{
		"hostname":  hostname,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"method":    "system_command",
	}

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

// getWhoami returns the current user with logging
func getWhoami() CommandResult {
	var logs []string
	logs = append(logs, "Starting current user lookup")

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("whoami")
		logs = append(logs, "Using Windows whoami command")
	} else {
		cmd = exec.Command("whoami")
		logs = append(logs, "Using Unix whoami command")
	}

	out, err := cmd.Output()
	if err != nil {
		errorMsg := fmt.Sprintf("Error getting current user: %v", err)
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	currentUser := strings.TrimSpace(string(out))
	logs = append(logs, fmt.Sprintf("Successfully identified user: %s", currentUser))

	data := map[string]interface{}{
		"current_user": currentUser,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"platform":     runtime.GOOS,
	}

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

// getUptime returns system uptime with enhanced logging
func getUptime() CommandResult {
	var logs []string
	logs = append(logs, "Starting uptime retrieval")

	var uptimeData map[string]interface{}

	if runtime.GOOS == "windows" {
		logs = append(logs, "Using PowerShell to get Windows last boot time")

		// Use PowerShell instead of deprecated wmic
		script := `(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToString("yyyy-MM-ddTHH:mm:ssZ")`
		cmd := exec.Command("powershell", "-Command", script)

		out, err := cmd.Output()
		if err != nil {
			// Fallback to Get-WmiObject if Get-CimInstance fails
			logs = append(logs, "Get-CimInstance failed, trying Get-WmiObject fallback")
			fallbackScript := `(Get-WmiObject -Class Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject -Class Win32_OperatingSystem).LastBootUpTime).ToString("yyyy-MM-ddTHH:mm:ssZ")`
			cmd = exec.Command("powershell", "-Command", fallbackScript)
			out, err = cmd.Output()

			if err != nil {
				// Final fallback - try to get uptime in a different way
				logs = append(logs, "WMI approaches failed, trying systeminfo command")
				cmd = exec.Command("systeminfo", "/fo", "csv")
				out, err = cmd.Output()

				if err != nil {
					errorMsg := fmt.Sprintf("Error getting uptime: %v", err)
					logs = append(logs, errorMsg)
					logs = append(logs, "All Windows uptime methods failed")
					return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
				}

				result := strings.TrimSpace(string(out))
				logs = append(logs, "Successfully retrieved system info as fallback")

				uptimeData = map[string]interface{}{
					"uptime_raw": result,
					"method":     "systeminfo_csv",
					"platform":   "windows",
					"timestamp":  time.Now().UTC().Format(time.RFC3339),
					"note":       "Fallback method used - contains full system info",
				}
			} else {
				bootTime := strings.TrimSpace(string(out))
				logs = append(logs, "Successfully retrieved boot time using Get-WmiObject fallback")
				logs = append(logs, fmt.Sprintf("Last boot time: %s", bootTime))

				// Calculate uptime duration
				if bootTimeObj, err := time.Parse("2006-01-02T15:04:05Z", bootTime); err == nil {
					uptime := time.Since(bootTimeObj)
					logs = append(logs, fmt.Sprintf("System uptime: %v", uptime))

					uptimeData = map[string]interface{}{
						"last_boot_time": bootTime,
						"uptime_seconds": int(uptime.Seconds()),
						"uptime_minutes": int(uptime.Minutes()),
						"uptime_hours":   int(uptime.Hours()),
						"uptime_days":    int(uptime.Hours() / 24),
						"uptime_human":   uptime.String(),
						"method":         "powershell_wmi_fallback",
						"platform":       "windows",
						"timestamp":      time.Now().UTC().Format(time.RFC3339),
					}
				} else {
					uptimeData = map[string]interface{}{
						"last_boot_time": bootTime,
						"method":         "powershell_wmi_fallback",
						"platform":       "windows",
						"timestamp":      time.Now().UTC().Format(time.RFC3339),
					}
				}
			}
		} else {
			bootTime := strings.TrimSpace(string(out))
			logs = append(logs, "Successfully retrieved boot time using Get-CimInstance")
			logs = append(logs, fmt.Sprintf("Last boot time: %s", bootTime))

			// Calculate uptime duration
			if bootTimeObj, err := time.Parse("2006-01-02T15:04:05Z", bootTime); err == nil {
				uptime := time.Since(bootTimeObj)
				logs = append(logs, fmt.Sprintf("System uptime: %v", uptime))

				uptimeData = map[string]interface{}{
					"last_boot_time": bootTime,
					"uptime_seconds": int(uptime.Seconds()),
					"uptime_minutes": int(uptime.Minutes()),
					"uptime_hours":   int(uptime.Hours()),
					"uptime_days":    int(uptime.Hours() / 24),
					"uptime_human":   uptime.String(),
					"method":         "powershell_ciminstance",
					"platform":       "windows",
					"timestamp":      time.Now().UTC().Format(time.RFC3339),
				}
			} else {
				uptimeData = map[string]interface{}{
					"last_boot_time": bootTime,
					"method":         "powershell_ciminstance",
					"platform":       "windows",
					"timestamp":      time.Now().UTC().Format(time.RFC3339),
				}
			}
		}
	} else {
		logs = append(logs, "Using Unix uptime command")
		cmd := exec.Command("uptime")

		out, err := cmd.Output()
		if err != nil {
			errorMsg := fmt.Sprintf("Error getting uptime: %v", err)
			logs = append(logs, errorMsg)
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}

		result := strings.TrimSpace(string(out))
		logs = append(logs, "Successfully retrieved Unix uptime")

		uptimeData = map[string]interface{}{
			"uptime":    result,
			"method":    "uptime_command",
			"platform":  runtime.GOOS,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
	}

	return NewSuccessResultWithLogs(uptimeData, strings.Join(logs, "\n"))
}

// getDiskSpace returns disk usage information with enhanced logging
func getDiskSpace() CommandResult {
	if runtime.GOOS == "windows" {
		return getDiskSpaceWindows()
	}
	return getDiskSpaceUnix()
}

func getDiskSpaceWindows() CommandResult {
	var logs []string
	logs = append(logs, "Starting Windows disk space analysis")
	logs = append(logs, "Using PowerShell Get-CimInstance to query disk information")

	// Use PowerShell instead of deprecated wmic
	script := `Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, Size, FreeSpace | ConvertTo-Json`
	cmd := exec.Command("powershell", "-Command", script)
	out, err := cmd.Output()

	if err != nil {
		// Fallback to Get-WmiObject
		logs = append(logs, "Get-CimInstance failed, trying Get-WmiObject fallback")
		fallbackScript := `Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, Size, FreeSpace | ConvertTo-Json`
		cmd = exec.Command("powershell", "-Command", fallbackScript)
		out, err = cmd.Output()

		if err != nil {
			// Final fallback to simple PowerShell command
			logs = append(logs, "WMI approaches failed, trying Get-PSDrive fallback")
			simpleScript := `Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{Name="Size";Expression={$_.Used + $_.Free}}, Free | ConvertTo-Json`
			cmd = exec.Command("powershell", "-Command", simpleScript)
			out, err = cmd.Output()

			if err != nil {
				errorMsg := fmt.Sprintf("Error getting disk space: %v", err)
				logs = append(logs, errorMsg)
				logs = append(logs, "All PowerShell disk methods failed - check PowerShell availability")
				return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
			}
			logs = append(logs, "Get-PSDrive fallback succeeded")
		} else {
			logs = append(logs, "Get-WmiObject fallback succeeded")
		}
	} else {
		logs = append(logs, "Get-CimInstance succeeded")
	}

	// Parse JSON output from PowerShell
	result := strings.TrimSpace(string(out))

	// Handle both single disk (object) and multiple disks (array) JSON responses
	var diskData []map[string]interface{}

	// Try to parse as array first
	if err := json.Unmarshal([]byte(result), &diskData); err != nil {
		// If array parsing fails, try as single object
		var singleDisk map[string]interface{}
		if err := json.Unmarshal([]byte(result), &singleDisk); err != nil {
			errorMsg := fmt.Sprintf("Error parsing PowerShell JSON output: %v", err)
			logs = append(logs, errorMsg)
			logs = append(logs, fmt.Sprintf("Raw PowerShell output: %s", result))
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}
		diskData = []map[string]interface{}{singleDisk}
	}

	logs = append(logs, fmt.Sprintf("Successfully parsed data for %d drives", len(diskData)))

	var disks []map[string]interface{}
	var totalSpace, totalUsed, totalFree int64

	for _, rawDisk := range diskData {
		var deviceID string
		var totalSize, freeSpace int64

		// Handle different field names from different PowerShell commands
		if val, ok := rawDisk["DeviceID"]; ok {
			deviceID = fmt.Sprintf("%v", val)
		} else if val, ok := rawDisk["Name"]; ok {
			deviceID = fmt.Sprintf("%v:", val) // Add colon for PSDrive format
		}

		if val, ok := rawDisk["Size"]; ok {
			if size, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
				totalSize = int64(size)
			}
		}

		if val, ok := rawDisk["FreeSpace"]; ok {
			if free, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
				freeSpace = int64(free)
			}
		} else if val, ok := rawDisk["Free"]; ok {
			if free, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
				freeSpace = int64(free)
			}
		}

		if totalSize > 0 && deviceID != "" {
			usedSpace := totalSize - freeSpace
			usedPercent := float64(usedSpace) / float64(totalSize) * 100

			disk := map[string]interface{}{
				"drive":        deviceID,
				"total_gb":     float64(totalSize) / (1024 * 1024 * 1024),
				"free_gb":      float64(freeSpace) / (1024 * 1024 * 1024),
				"used_gb":      float64(usedSpace) / (1024 * 1024 * 1024),
				"used_percent": usedPercent,
				"total_bytes":  totalSize,
				"free_bytes":   freeSpace,
				"used_bytes":   usedSpace,
			}
			disks = append(disks, disk)

			totalSpace += totalSize
			totalUsed += usedSpace
			totalFree += freeSpace

			logs = append(logs, fmt.Sprintf("Drive %s: %.1f GB total, %.1f%% used",
				deviceID, float64(totalSize)/(1024*1024*1024), usedPercent))
		} else {
			logs = append(logs, fmt.Sprintf("Warning: Skipped invalid disk data: %+v", rawDisk))
		}
	}

	if len(disks) == 0 {
		errorMsg := "No valid disk drives found"
		logs = append(logs, errorMsg)
		logs = append(logs, fmt.Sprintf("Raw data received: %s", result))
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	data := map[string]interface{}{
		"disks":        disks,
		"total_drives": len(disks),
		"summary": map[string]interface{}{
			"total_space_gb":       float64(totalSpace) / (1024 * 1024 * 1024),
			"total_used_gb":        float64(totalUsed) / (1024 * 1024 * 1024),
			"total_free_gb":        float64(totalFree) / (1024 * 1024 * 1024),
			"overall_used_percent": float64(totalUsed) / float64(totalSpace) * 100,
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"method":    "powershell_ciminstance",
		"platform":  "windows",
	}

	logs = append(logs, fmt.Sprintf("Successfully analyzed %d drives", len(disks)))
	logs = append(logs, fmt.Sprintf("Total storage: %.1f GB, Used: %.1f%%",
		float64(totalSpace)/(1024*1024*1024), float64(totalUsed)/float64(totalSpace)*100))

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

func getDiskSpaceUnix() CommandResult {
	var logs []string
	logs = append(logs, "Starting Unix disk space analysis")
	logs = append(logs, "Using 'df -h' command to get disk usage")

	cmd := exec.Command("df", "-h")
	out, err := cmd.Output()
	if err != nil {
		errorMsg := fmt.Sprintf("Error getting disk space: %v", err)
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	result := strings.TrimSpace(string(out))
	logs = append(logs, "Successfully retrieved disk usage information")

	data := map[string]interface{}{
		"disk_usage": result,
		"method":     "df_command",
		"platform":   runtime.GOOS,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

// getMemoryInfo returns memory usage information with platform-specific handling
func getMemoryInfo() CommandResult {
	var logs []string
	logs = append(logs, "Starting memory information retrieval")

	var data map[string]interface{}

	if runtime.GOOS == "windows" {
		logs = append(logs, "Using PowerShell to get Windows memory information")

		// Use PowerShell to get both total and available memory
		script := `$cs = Get-CimInstance -ClassName Win32_ComputerSystem; $os = Get-CimInstance -ClassName Win32_OperatingSystem; @{TotalPhysicalMemory=$cs.TotalPhysicalMemory; AvailableMemory=$os.FreePhysicalMemory*1024; TotalVirtualMemory=$os.TotalVirtualMemorySize*1024; AvailableVirtualMemory=$os.FreeVirtualMemory*1024} | ConvertTo-Json`
		cmd := exec.Command("powershell", "-Command", script)

		out, err := cmd.Output()
		if err != nil {
			// Fallback to Get-WmiObject
			logs = append(logs, "Get-CimInstance failed, trying Get-WmiObject fallback")
			fallbackScript := `$cs = Get-WmiObject -Class Win32_ComputerSystem; $os = Get-WmiObject -Class Win32_OperatingSystem; @{TotalPhysicalMemory=$cs.TotalPhysicalMemory; AvailableMemory=$os.FreePhysicalMemory*1024; TotalVirtualMemory=$os.TotalVirtualMemorySize*1024; AvailableVirtualMemory=$os.FreeVirtualMemory*1024} | ConvertTo-Json`
			cmd = exec.Command("powershell", "-Command", fallbackScript)
			out, err = cmd.Output()

			if err != nil {
				// Simple fallback - just get total physical memory
				logs = append(logs, "Complex memory query failed, trying simple approach")
				simpleScript := `(Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory`
				cmd = exec.Command("powershell", "-Command", simpleScript)
				out, err = cmd.Output()

				if err != nil {
					errorMsg := fmt.Sprintf("Error getting memory info: %v", err)
					logs = append(logs, errorMsg)
					logs = append(logs, "All PowerShell memory methods failed")
					return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
				}

				// Parse simple numeric result
				totalMemStr := strings.TrimSpace(string(out))
				if totalMem, err := strconv.ParseInt(totalMemStr, 10, 64); err == nil {
					logs = append(logs, "Simple memory query succeeded")
					logs = append(logs, fmt.Sprintf("Total physical memory: %.2f GB", float64(totalMem)/(1024*1024*1024)))

					data = map[string]interface{}{
						"total_memory_bytes": totalMem,
						"total_memory_gb":    float64(totalMem) / (1024 * 1024 * 1024),
						"method":             "powershell_simple",
						"platform":           "windows",
						"timestamp":          time.Now().UTC().Format(time.RFC3339),
						"note":               "Simple query - only total memory available",
					}
				} else {
					errorMsg := fmt.Sprintf("Failed to parse memory value: %s", totalMemStr)
					logs = append(logs, errorMsg)
					return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
				}
			} else {
				logs = append(logs, "Get-WmiObject fallback succeeded")
				// Parse JSON result
				if err := parseWindowsMemoryJSON(string(out), &data, &logs); err != nil {
					return NewErrorResultWithDetails(err.Error(), strings.Join(logs, "\n"))
				}
				data["method"] = "powershell_wmi_fallback"
			}
		} else {
			logs = append(logs, "Get-CimInstance memory query succeeded")
			// Parse JSON result
			if err := parseWindowsMemoryJSON(string(out), &data, &logs); err != nil {
				return NewErrorResultWithDetails(err.Error(), strings.Join(logs, "\n"))
			}
			data["method"] = "powershell_ciminstance"
		}

		data["platform"] = "windows"
		data["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	} else {
		logs = append(logs, "Using Unix 'free -h' command for memory information")
		cmd := exec.Command("free", "-h")

		out, err := cmd.Output()
		if err != nil {
			errorMsg := fmt.Sprintf("Error getting memory info: %v", err)
			logs = append(logs, errorMsg)
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}

		result := strings.TrimSpace(string(out))
		logs = append(logs, "Successfully retrieved Unix memory information")

		data = map[string]interface{}{
			"memory_info": result,
			"method":      "free_command",
			"platform":    runtime.GOOS,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}

		// Try to parse free command output for additional structured data
		if parsedData := parseUnixMemoryOutput(result); parsedData != nil {
			for key, value := range parsedData {
				data[key] = value
			}
			logs = append(logs, "Successfully parsed structured memory data from free command")
		}
	}

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

// parseWindowsMemoryJSON parses the JSON output from PowerShell memory commands
func parseWindowsMemoryJSON(jsonStr string, data *map[string]interface{}, logs *[]string) error {
	var memoryData map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonStr)), &memoryData); err != nil {
		*logs = append(*logs, fmt.Sprintf("Failed to parse memory JSON: %v", err))
		*logs = append(*logs, fmt.Sprintf("Raw output: %s", jsonStr))
		return fmt.Errorf("failed to parse memory JSON: %v", err)
	}

	*data = make(map[string]interface{})

	// Parse total physical memory
	if val, ok := memoryData["TotalPhysicalMemory"]; ok {
		if totalMem, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
			(*data)["total_memory_bytes"] = int64(totalMem)
			(*data)["total_memory_gb"] = totalMem / (1024 * 1024 * 1024)
			*logs = append(*logs, fmt.Sprintf("Total physical memory: %.2f GB", totalMem/(1024*1024*1024)))
		}
	}

	// Parse available memory
	if val, ok := memoryData["AvailableMemory"]; ok {
		if availMem, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
			(*data)["available_memory_bytes"] = int64(availMem)
			(*data)["available_memory_gb"] = availMem / (1024 * 1024 * 1024)
			*logs = append(*logs, fmt.Sprintf("Available physical memory: %.2f GB", availMem/(1024*1024*1024)))

			// Calculate used memory and percentage
			if totalMem, ok := (*data)["total_memory_bytes"]; ok {
				if total, ok := totalMem.(int64); ok {
					usedMem := total - int64(availMem)
					usedPercent := float64(usedMem) / float64(total) * 100
					(*data)["used_memory_bytes"] = usedMem
					(*data)["used_memory_gb"] = float64(usedMem) / (1024 * 1024 * 1024)
					(*data)["memory_usage_percent"] = usedPercent
					*logs = append(*logs, fmt.Sprintf("Memory usage: %.1f%%", usedPercent))
				}
			}
		}
	}

	// Parse virtual memory if available
	if val, ok := memoryData["TotalVirtualMemory"]; ok {
		if totalVirtual, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
			(*data)["total_virtual_memory_bytes"] = int64(totalVirtual)
			(*data)["total_virtual_memory_gb"] = totalVirtual / (1024 * 1024 * 1024)
		}
	}

	if val, ok := memoryData["AvailableVirtualMemory"]; ok {
		if availVirtual, err := strconv.ParseFloat(fmt.Sprintf("%v", val), 64); err == nil {
			(*data)["available_virtual_memory_bytes"] = int64(availVirtual)
			(*data)["available_virtual_memory_gb"] = availVirtual / (1024 * 1024 * 1024)
		}
	}

	return nil
}

// parseUnixMemoryOutput attempts to parse free command output into structured data
func parseUnixMemoryOutput(freeOutput string) map[string]interface{} {
	lines := strings.Split(freeOutput, "\n")
	if len(lines) < 2 {
		return nil
	}

	// Look for the memory line (usually second line)
	for _, line := range lines {
		if strings.Contains(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				result := make(map[string]interface{})
				result["memory_line"] = line
				result["parsed"] = true
				return result
			}
		}
	}

	return nil
}

// getTopProcesses returns top running processes with enhanced logging
func getTopProcesses() CommandResult {
	var logs []string
	logs = append(logs, "Starting process information retrieval")

	var cmd *exec.Cmd
	var data map[string]interface{}

	if runtime.GOOS == "windows" {
		logs = append(logs, "Using PowerShell Get-Process for Windows process information")

		// Use PowerShell instead of deprecated wmic
		script := `Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, WorkingSet | ConvertTo-Csv -NoTypeInformation`
		cmd = exec.Command("powershell", "-Command", script)

		out, err := cmd.Output()
		if err != nil {
			// Fallback to simpler PowerShell command if the complex one fails
			logs = append(logs, "Complex PowerShell command failed, trying simpler approach")
			simpleScript := `Get-Process | Select-Object -First 10 Name, Id, WorkingSet | ConvertTo-Csv -NoTypeInformation`
			cmd = exec.Command("powershell", "-Command", simpleScript)
			out, err = cmd.Output()

			if err != nil {
				errorMsg := fmt.Sprintf("Error getting processes: %v", err)
				logs = append(logs, errorMsg)
				logs = append(logs, "Both PowerShell commands failed - check PowerShell availability")
				return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
			}
			logs = append(logs, "Fallback PowerShell command succeeded")
		} else {
			logs = append(logs, "PowerShell Get-Process command succeeded")
		}

		result := strings.TrimSpace(string(out))
		lines := strings.Split(result, "\n")
		processCount := len(lines) - 1 // Subtract header
		logs = append(logs, fmt.Sprintf("Retrieved information for %d processes", processCount))

		data = map[string]interface{}{
			"processes":     result,
			"process_count": processCount,
			"method":        "powershell_get_process",
			"format":        "csv",
			"platform":      "windows",
			"timestamp":     time.Now().UTC().Format(time.RFC3339),
		}

	} else {
		logs = append(logs, "Using Unix 'ps aux' command for process information")
		cmd = exec.Command("sh", "-c", "ps aux --sort=-%cpu | head -10")

		out, err := cmd.Output()
		if err != nil {
			errorMsg := fmt.Sprintf("Error getting processes: %v", err)
			logs = append(logs, errorMsg)
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}

		result := strings.TrimSpace(string(out))
		lines := strings.Split(result, "\n")
		processCount := len(lines) - 1 // Subtract header
		logs = append(logs, fmt.Sprintf("Retrieved top %d processes sorted by CPU usage", processCount))

		data = map[string]interface{}{
			"processes":     result,
			"process_count": processCount,
			"method":        "ps_aux_sorted",
			"format":        "text",
			"platform":      runtime.GOOS,
			"timestamp":     time.Now().UTC().Format(time.RFC3339),
		}
	}

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

// getNetworkInfo returns network configuration with enhanced logging
func getNetworkInfo() CommandResult {
	var logs []string
	logs = append(logs, "Starting network configuration retrieval")

	var cmd *exec.Cmd
	var data map[string]interface{}

	if runtime.GOOS == "windows" {
		logs = append(logs, "Using Windows ipconfig command for network information")
		cmd = exec.Command("ipconfig", "/all")

		out, err := cmd.Output()
		if err != nil {
			errorMsg := fmt.Sprintf("Error getting network info: %v", err)
			logs = append(logs, errorMsg)
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}

		result := strings.TrimSpace(string(out))
		logs = append(logs, "Successfully retrieved Windows network configuration")

		// Count network adapters
		adapterCount := strings.Count(result, "adapter")
		logs = append(logs, fmt.Sprintf("Found approximately %d network adapters", adapterCount))

		data = map[string]interface{}{
			"network_config": result,
			"adapter_count":  adapterCount,
			"method":         "ipconfig_all",
			"platform":       "windows",
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		}

		// Try to get additional network info using PowerShell
		logs = append(logs, "Attempting to get additional network adapter details via PowerShell")
		psScript := `Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, InterfaceDescription, LinkSpeed | ConvertTo-Json`
		psCmd := exec.Command("powershell", "-Command", psScript)
		if psOut, err := psCmd.Output(); err == nil {
			psResult := strings.TrimSpace(string(psOut))
			if psResult != "" && psResult != "null" {
				data["active_adapters_json"] = psResult
				logs = append(logs, "Successfully retrieved active network adapter details")
			}
		} else {
			logs = append(logs, "PowerShell network adapter query failed (non-critical)")
		}

	} else {
		logs = append(logs, "Using Unix ifconfig command for network information")
		cmd = exec.Command("ifconfig")

		out, err := cmd.Output()
		if err != nil {
			// Try alternative commands for different Unix systems
			logs = append(logs, "ifconfig failed, trying ip command")
			cmd = exec.Command("ip", "addr", "show")
			out, err = cmd.Output()

			if err != nil {
				errorMsg := fmt.Sprintf("Error getting network info: %v", err)
				logs = append(logs, errorMsg)
				logs = append(logs, "Both ifconfig and ip commands failed")
				return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
			}

			result := strings.TrimSpace(string(out))
			logs = append(logs, "Successfully retrieved network info using ip command")

			data = map[string]interface{}{
				"network_config": result,
				"method":         "ip_addr_show",
				"platform":       runtime.GOOS,
				"timestamp":      time.Now().UTC().Format(time.RFC3339),
			}
		} else {
			result := strings.TrimSpace(string(out))
			logs = append(logs, "Successfully retrieved network info using ifconfig")

			data = map[string]interface{}{
				"network_config": result,
				"method":         "ifconfig",
				"platform":       runtime.GOOS,
				"timestamp":      time.Now().UTC().Format(time.RFC3339),
			}
		}

		// Try to count interfaces
		if config, ok := data["network_config"].(string); ok {
			interfaceCount := strings.Count(config, "inet ")
			logs = append(logs, fmt.Sprintf("Found approximately %d network interfaces with IP addresses", interfaceCount))
			data["interface_count"] = interfaceCount
		}
	}

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
}

// getSystemInfo returns comprehensive system information with enhanced logging
func getSystemInfo() CommandResult {
	var logs []string
	logs = append(logs, "Starting comprehensive system information retrieval")

	var cmd *exec.Cmd
	var data map[string]interface{}

	if runtime.GOOS == "windows" {
		logs = append(logs, "Using Windows systeminfo command")
		cmd = exec.Command("systeminfo")

		out, err := cmd.Output()
		if err != nil {
			// Try PowerShell alternative
			logs = append(logs, "systeminfo failed, trying PowerShell Get-ComputerInfo")
			psScript := `Get-ComputerInfo | ConvertTo-Json -Depth 3`
			cmd = exec.Command("powershell", "-Command", psScript)
			out, err = cmd.Output()

			if err != nil {
				// Fallback to basic system info
				logs = append(logs, "PowerShell Get-ComputerInfo failed, trying basic approach")
				basicScript := `@{
					ComputerName=$env:COMPUTERNAME;
					UserName=$env:USERNAME;
					OS=(Get-CimInstance Win32_OperatingSystem).Caption;
					Version=(Get-CimInstance Win32_OperatingSystem).Version;
					Architecture=$env:PROCESSOR_ARCHITECTURE;
					LastBootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
				} | ConvertTo-Json`
				cmd = exec.Command("powershell", "-Command", basicScript)
				out, err = cmd.Output()

				if err != nil {
					errorMsg := fmt.Sprintf("Error getting system info: %v", err)
					logs = append(logs, errorMsg)
					logs = append(logs, "All Windows system info methods failed")
					return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
				}

				result := strings.TrimSpace(string(out))
				logs = append(logs, "Successfully retrieved basic system info via PowerShell")

				data = map[string]interface{}{
					"system_info_json": result,
					"method":           "powershell_basic",
					"platform":         "windows",
					"timestamp":        time.Now().UTC().Format(time.RFC3339),
					"format":           "json",
				}
			} else {
				result := strings.TrimSpace(string(out))
				logs = append(logs, "Successfully retrieved comprehensive system info via PowerShell Get-ComputerInfo")

				data = map[string]interface{}{
					"system_info_json": result,
					"method":           "powershell_computerinfo",
					"platform":         "windows",
					"timestamp":        time.Now().UTC().Format(time.RFC3339),
					"format":           "json",
				}
			}
		} else {
			result := strings.TrimSpace(string(out))
			logs = append(logs, "Successfully retrieved system info using systeminfo command")

			// Count information lines
			lines := strings.Split(result, "\n")
			infoLines := 0
			for _, line := range lines {
				if strings.Contains(line, ":") && !strings.HasPrefix(strings.TrimSpace(line), "=") {
					infoLines++
				}
			}
			logs = append(logs, fmt.Sprintf("Retrieved %d system information fields", infoLines))

			data = map[string]interface{}{
				"system_info": result,
				"info_fields": infoLines,
				"method":      "systeminfo_command",
				"platform":    "windows",
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
				"format":      "text",
			}
		}
	} else {
		logs = append(logs, "Using Unix uname command for system information")
		cmd = exec.Command("uname", "-a")

		out, err := cmd.Output()
		if err != nil {
			errorMsg := fmt.Sprintf("Error getting system info: %v", err)
			logs = append(logs, errorMsg)
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}

		result := strings.TrimSpace(string(out))
		logs = append(logs, "Successfully retrieved Unix system info using uname")

		data = map[string]interface{}{
			"system_info": result,
			"method":      "uname_all",
			"platform":    runtime.GOOS,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
			"format":      "text",
		}

		// Try to get additional info for Linux/macOS
		additionalInfo := make(map[string]string)

		// Get OS release info (Linux)
		if runtime.GOOS == "linux" {
			if releaseOut, err := exec.Command("cat", "/etc/os-release").Output(); err == nil {
				additionalInfo["os_release"] = strings.TrimSpace(string(releaseOut))
				logs = append(logs, "Retrieved Linux OS release information")
			}
		}

		// Get kernel version
		if kernelOut, err := exec.Command("uname", "-r").Output(); err == nil {
			additionalInfo["kernel_version"] = strings.TrimSpace(string(kernelOut))
			logs = append(logs, "Retrieved kernel version")
		}

		// Get hardware info
		if hwOut, err := exec.Command("uname", "-m").Output(); err == nil {
			additionalInfo["hardware_platform"] = strings.TrimSpace(string(hwOut))
			logs = append(logs, "Retrieved hardware platform info")
		}

		if len(additionalInfo) > 0 {
			data["additional_info"] = additionalInfo
			logs = append(logs, fmt.Sprintf("Retrieved %d additional system information fields", len(additionalInfo)))
		}
	}

	return NewSuccessResultWithLogs(data, strings.Join(logs, "\n"))
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

	// Execute logoff command with validated session ID
	cmd := exec.Command("logoff", sessionID)
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
