package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

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
						"uptime_seconds": int(uptime.Seconds()) % 60,
						"uptime_minutes": int(uptime.Minutes()) % 60,
						"uptime_hours":   int(uptime.Hours()) % 24,
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
					"uptime_seconds": int(uptime.Seconds()) % 60,
					"uptime_minutes": int(uptime.Minutes()) % 60,
					"uptime_hours":   int(uptime.Hours()) % 24,
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

// getMemoryInfo returns memory information with enhanced logging
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
