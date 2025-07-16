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