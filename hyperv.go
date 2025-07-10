package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// HyperVVM represents a Hyper-V virtual machine
type HyperVVM struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	State            string `json:"state"`
	Status           string `json:"status"`
	Health           string `json:"health"`
	InstallationDate string `json:"installation_date"`
	StartTime        string `json:"start_time,omitempty"`
	Uptime           string `json:"uptime,omitempty"`
}

// executeHyperVInventory gets an inventory of all virtual machines and updates the database
func executeHyperVInventory() CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output: map[string]string{"error": "Hyper-V commands are only supported on Windows"},
			Error:  "Hyper-V commands are only supported on Windows",
			Status: "error",
		}
	}

	// Check if Hyper-V is available
	if !isHyperVAvailable() {
		return CommandResult{
			Output: map[string]string{"error": "Hyper-V is not available or enabled on this system"},
			Error:  "Hyper-V is not available or enabled on this system",
			Status: "error",
		}
	}

	// Get VMs from PowerShell (existing logic)
	vms, err := getVMsFromPowerShell()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to get VM inventory: %v", err)},
			Error:  fmt.Sprintf("Failed to get VM inventory: %v", err),
			Status: "error",
		}
	}

	// Return result with both live data and database update status
	result := map[string]interface{}{
		"virtual_machines": vms,
		"total_count":      len(vms),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"source":           "live_powershell",
	}

	return CommandResult{
		Output: result,
		Error:  "",
		Status: "success",
	}
}

// getVMsFromPowerShell extracts the PowerShell logic into a separate function
func getVMsFromPowerShell() ([]HyperVVM, error) {
	// PowerShell script to get VM inventory
	script := `
	Get-VM | ForEach-Object {
		$vm = $_
		$startTime = ""
		$uptime = ""
		
		# Get start time and calculate uptime for running VMs
		if ($vm.State -eq "Running") {
			try {
				# Try to get start time from VM worker process
				$processes = Get-WmiObject -Class Win32_Process -Filter "Name='vmwp.exe'" | Where-Object {
					$_.CommandLine -like "*$($vm.Id)*"
				}
				if ($processes) {
					$startTime = $processes[0].CreationDate
					if ($startTime) {
						$start = [Management.ManagementDateTimeConverter]::ToDateTime($startTime)
						$uptime = (Get-Date) - $start
						$startTime = $start.ToString("yyyy-MM-ddTHH:mm:ssZ")
						$uptime = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
					}
				}
			} catch {
				# If we can't get exact start time, use a placeholder
				$startTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
			}
		}
		
		# Get creation date
		$creationDate = ""
		try {
			$creationDate = $vm.CreationTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
		} catch {
			$creationDate = ""
		}
		
		[PSCustomObject]@{
			Id = $vm.Id.ToString()
			Name = $vm.Name
			State = $vm.State.ToString()
			Status = $vm.Status.ToString()
			Health = $vm.OperationalStatus.ToString()
			InstallationDate = $creationDate
			StartTime = $startTime
			Uptime = $uptime
		}
	} | ConvertTo-Json -Depth 3
	`

	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse the JSON output
	var vms []HyperVVM
	if err := json.Unmarshal(output, &vms); err != nil {
		// Try parsing as single object (in case there's only one VM)
		var singleVM HyperVVM
		if err2 := json.Unmarshal(output, &singleVM); err2 == nil {
			vms = []HyperVVM{singleVM}
		} else {
			return nil, fmt.Errorf("failed to parse VM data: %v", err)
		}
	}

	return vms, nil
}

// executeHyperVInventoryWithDB gets inventory and updates database (new command)
func executeHyperVInventoryWithDB(jwtToken string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output: map[string]string{"error": "Hyper-V commands are only supported on Windows"},
			Error:  "Hyper-V commands are only supported on Windows",
			Status: "error",
		}
	}

	// Check if Hyper-V is available
	if !isHyperVAvailable() {
		return CommandResult{
			Output: map[string]string{"error": "Hyper-V is not available or enabled on this system"},
			Error:  "Hyper-V is not available or enabled on this system",
			Status: "error",
		}
	}

	// Get VMs from PowerShell
	vms, err := getVMsFromPowerShell()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to get VM inventory: %v", err)},
			Error:  fmt.Sprintf("Failed to get VM inventory: %v", err),
			Status: "error",
		}
	}

	// Update database with current inventory
	dbUpdateError := ""
	if err := updateVMDatabase(jwtToken, deviceID, vms); err != nil {
		dbUpdateError = fmt.Sprintf("Database update failed: %v", err)
		log.Printf("Database update error: %v", err)
	}

	// Return result with both live data and database update status
	result := map[string]interface{}{
		"virtual_machines": vms,
		"total_count":      len(vms),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"source":           "live_powershell_with_db_update",
		"database_updated": dbUpdateError == "",
	}

	if dbUpdateError != "" {
		result["database_error"] = dbUpdateError
	}

	return CommandResult{
		Output: result,
		Error:  "",
		Status: "success",
	}
}

// executeHyperVScreenshot captures actual VM screen content using Hyper-V WMI
func executeHyperVScreenshot(params map[string]interface{}) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output: map[string]string{"error": "Hyper-V commands are only supported on Windows"},
			Error:  "Hyper-V commands are only supported on Windows",
			Status: "error",
		}
	}

	if params == nil {
		return CommandResult{
			Output: map[string]string{"error": "VM ID parameter is required"},
			Error:  "VM ID parameter is required",
			Status: "error",
		}
	}

	vmID, ok := params["vm_id"].(string)
	if !ok || vmID == "" {
		return CommandResult{
			Output: map[string]string{"error": "Valid VM ID parameter is required"},
			Error:  "Valid VM ID parameter is required",
			Status: "error",
		}
	}

	// First check if VM exists and is running (using working method)
	checkScript := fmt.Sprintf(`
	try {
		$vm = Get-VM -Id '%s' -ErrorAction Stop
		Write-Output "VM_FOUND:$($vm.Name):$($vm.State)"
	} catch {
		Write-Output "VM_ERROR:$($_.Exception.Message)"
	}
	`, vmID)

	checkCmd := exec.Command("powershell", "-Command", checkScript)
	checkOutput, err := checkCmd.CombinedOutput()

	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("VM lookup failed: %v", err)},
			Error:  fmt.Sprintf("VM lookup failed: %v", err),
			Status: "error",
		}
	}

	checkResult := strings.TrimSpace(string(checkOutput))

	if strings.HasPrefix(checkResult, "VM_ERROR:") {
		errorMsg := strings.TrimPrefix(checkResult, "VM_ERROR:")
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("VM error: %s", errorMsg)},
			Error:  fmt.Sprintf("VM error: %s", errorMsg),
			Status: "error",
		}
	}

	if !strings.HasPrefix(checkResult, "VM_FOUND:") {
		return CommandResult{
			Output: map[string]string{"error": "Unexpected VM lookup result"},
			Error:  "Unexpected VM lookup result",
			Status: "error",
		}
	}

	// Parse VM info
	parts := strings.Split(checkResult, ":")
	if len(parts) < 3 {
		return CommandResult{
			Output: map[string]string{"error": "Invalid VM info format"},
			Error:  "Invalid VM info format",
			Status: "error",
		}
	}

	vmName := parts[1]
	vmState := parts[2]

	if vmState != "Running" {
		return CommandResult{
			Output: map[string]string{
				"error": fmt.Sprintf("Cannot capture screenshot - VM is not running (state: %s)", vmState),
			},
			Error:  fmt.Sprintf("Cannot capture screenshot - VM is not running (state: %s)", vmState),
			Status: "error",
		}
	}

	// Now capture actual VM screen using Hyper-V WMI method
	screenshotScript := fmt.Sprintf(`
	try {
		# Add required assemblies
		Add-Type -AssemblyName "System.Drawing"
		
		# Get the VM using WMI (by VM name since we have it)
		$VMCS = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='%s'"
		
		if (-not $VMCS) {
			Write-Output "WMI_ERROR:VM not found in WMI"
			exit
		}
		
		# Get the video head to determine resolution
		$video = $VMCS.GetRelated("Msvm_VideoHead")
		if (-not $video) {
			Write-Output "WMI_ERROR:No video head found"
			exit
		}
		
		$xResolution = $video.CurrentHorizontalResolution[0]
		$yResolution = $video.CurrentVerticalResolution[0]
		
		if (-not $xResolution -or -not $yResolution -or $xResolution -eq 0 -or $yResolution -eq 0) {
			Write-Output "WMI_ERROR:Invalid resolution: $xResolution x $yResolution"
			exit
		}
		
		# Get the Virtual System Management Service
		$VMMS = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
		
		if (-not $VMMS) {
			Write-Output "WMI_ERROR:Virtual System Management Service not found"
			exit
		}
		
		# Get the actual screenshot
		$result = $VMMS.GetVirtualSystemThumbnailImage($VMCS, $xResolution, $yResolution)
		
		if (-not $result -or -not $result.ImageData) {
			Write-Output "WMI_ERROR:Failed to get thumbnail image"
			exit
		}
		
		$imageData = $result.ImageData
		
		# Create bitmap from the raw image data
		$BitMap = New-Object System.Drawing.Bitmap -Args $xResolution, $yResolution, "Format16bppRgb565"
		$Rect = New-Object System.Drawing.Rectangle 0, 0, $xResolution, $yResolution
		$BmpData = $BitMap.LockBits($Rect, "ReadWrite", "Format16bppRgb565")
		
		# Copy the image data to the bitmap
		[System.Runtime.InteropServices.Marshal]::Copy($imageData, 0, $BmpData.Scan0, $BmpData.Stride * $BmpData.Height)
		$BitMap.UnlockBits($BmpData)
		
		# Convert to PNG and resize to 600px width
		$targetWidth = 600
		$aspectRatio = [double]$yResolution / [double]$xResolution
		$targetHeight = [int]($targetWidth * $aspectRatio)
		
		# Create resized bitmap
		$resizedBitmap = New-Object System.Drawing.Bitmap($targetWidth, $targetHeight)
		$graphics = [System.Drawing.Graphics]::FromImage($resizedBitmap)
		
		# Set high quality scaling
		$graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
		$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
		$graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
		
		# Draw the original image resized
		$graphics.DrawImage($BitMap, 0, 0, $targetWidth, $targetHeight)
		
		# Convert resized image to JPEG with compression and base64
		$ms = New-Object System.IO.MemoryStream
		
		# Create JPEG encoder with quality setting (70% quality for good balance)
		$jpegEncoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq "image/jpeg" }
		$encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
		$qualityParam = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, 70L)
		$encoderParams.Param[0] = $qualityParam
		
		$resizedBitmap.Save($ms, $jpegEncoder, $encoderParams)
		$bytes = $ms.ToArray()
		$base64 = [Convert]::ToBase64String($bytes)
		
		# Cleanup
		$encoderParams.Dispose()
		$graphics.Dispose()
		$resizedBitmap.Dispose()
		$BitMap.Dispose()
		$ms.Dispose()
		
		Write-Output "SUCCESS:$($targetWidth)x$($targetHeight):$base64"
		
	} catch {
		Write-Output "SCREENSHOT_ERROR:$($_.Exception.Message)"
	}
	`, vmName)

	screenshotCmd := exec.Command("powershell", "-Command", screenshotScript)
	screenshotOutput, err := screenshotCmd.CombinedOutput()

	if err != nil {
		return CommandResult{
			Output: map[string]interface{}{
				"error":      fmt.Sprintf("Screenshot command failed: %v", err),
				"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
				"raw_output": string(screenshotOutput),
			},
			Error:  fmt.Sprintf("Screenshot command failed: %v", err),
			Status: "error",
		}
	}

	screenshotResult := strings.TrimSpace(string(screenshotOutput))

	if strings.HasPrefix(screenshotResult, "SUCCESS:") {
		// Parse the result which now includes dimensions
		resultParts := strings.SplitN(screenshotResult, ":", 3)
		if len(resultParts) < 3 {
			return CommandResult{
				Output: map[string]string{"error": "Invalid screenshot result format"},
				Error:  "Invalid screenshot result format",
				Status: "error",
			}
		}

		dimensions := resultParts[1]
		base64Data := resultParts[2]

		// Update VM last_seen in database
		if err := updateVMLastSeen("", vmID); err != nil {
			log.Printf("Failed to update VM last_seen in database: %v", err)
		}

		return CommandResult{
			Output: map[string]interface{}{
				"success":    true,
				"vm_id":      vmID,
				"vm_name":    vmName,
				"vm_state":   vmState,
				"dimensions": dimensions,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
				"message":    "VM screenshot captured, resized, and compressed successfully",
				"method":     "wmi_thumbnail_jpeg_compressed",
				"format":     "JPEG",
				"quality":    "70%",
			},
			ScreenshotData: base64Data,
			Error:          "",
			Status:         "success",
		}
	} else if strings.HasPrefix(screenshotResult, "WMI_ERROR:") {
		errorMsg := strings.TrimPrefix(screenshotResult, "WMI_ERROR:")
		return CommandResult{
			Output: map[string]interface{}{
				"error":      fmt.Sprintf("WMI error: %s", errorMsg),
				"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
				"suggestion": "VM may not support screen capture or video head not available",
			},
			Error:  fmt.Sprintf("WMI error: %s", errorMsg),
			Status: "error",
		}
	} else if strings.HasPrefix(screenshotResult, "SCREENSHOT_ERROR:") {
		errorMsg := strings.TrimPrefix(screenshotResult, "SCREENSHOT_ERROR:")
		return CommandResult{
			Output: map[string]interface{}{
				"error":      fmt.Sprintf("Screenshot error: %s", errorMsg),
				"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
				"raw_output": screenshotResult,
			},
			Error:  fmt.Sprintf("Screenshot error: %s", errorMsg),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"error":      "Unexpected screenshot result",
			"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
			"raw_output": screenshotResult,
		},
		Error:  "Unexpected screenshot result",
		Status: "error",
	}
}

// executeHyperVStart starts a VM and updates database
func executeHyperVStart(params map[string]interface{}) CommandResult {
	result := executeHyperVOperation(params, "Start-VM", "start", "running")

	// If operation was successful, update database state
	if result.Status == "success" {
		if vmID, ok := params["vm_id"].(string); ok {
			// Try to update database state, but don't fail the command if this fails
			if err := updateVMState("", vmID, "Starting"); err != nil {
				log.Printf("Failed to update VM state in database: %v", err)
			}
		}
	}

	return result
}

// executeHyperVPause pauses a VM and updates database
func executeHyperVPause(params map[string]interface{}) CommandResult {
	result := executeHyperVOperation(params, "Suspend-VM", "pause", "paused")

	// If operation was successful, update database state
	if result.Status == "success" {
		if vmID, ok := params["vm_id"].(string); ok {
			if err := updateVMState("", vmID, "Paused"); err != nil {
				log.Printf("Failed to update VM state in database: %v", err)
			}
		}
	}

	return result
}

// executeHyperVReset resets a VM and updates database
func executeHyperVReset(params map[string]interface{}) CommandResult {
	result := executeHyperVOperation(params, "Reset-VM", "reset", "reset")

	// If operation was successful, update database state
	if result.Status == "success" {
		if vmID, ok := params["vm_id"].(string); ok {
			if err := updateVMState("", vmID, "Resetting"); err != nil {
				log.Printf("Failed to update VM state in database: %v", err)
			}
		}
	}

	return result
}

// executeHyperVTurnOff turns off a VM and updates database
func executeHyperVTurnOff(params map[string]interface{}) CommandResult {
	result := executeHyperVOperation(params, "Stop-VM", "turn off", "stopped")

	// If operation was successful, update database state
	if result.Status == "success" {
		if vmID, ok := params["vm_id"].(string); ok {
			if err := updateVMState("", vmID, "Off"); err != nil {
				log.Printf("Failed to update VM state in database: %v", err)
			}
		}
	}

	return result
}

// executeHyperVShutdown gracefully shuts down a VM and updates database
func executeHyperVShutdown(params map[string]interface{}) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output: map[string]string{"error": "Hyper-V commands are only supported on Windows"},
			Error:  "Hyper-V commands are only supported on Windows",
			Status: "error",
		}
	}

	if params == nil {
		return CommandResult{
			Output: map[string]string{"error": "VM ID parameter is required"},
			Error:  "VM ID parameter is required",
			Status: "error",
		}
	}

	vmID, ok := params["vm_id"].(string)
	if !ok || vmID == "" {
		return CommandResult{
			Output: map[string]string{"error": "Valid VM ID parameter is required"},
			Error:  "Valid VM ID parameter is required",
			Status: "error",
		}
	}

	// Use Stop-VM with graceful shutdown using VM object
	script := fmt.Sprintf(`
	try {
		$vm = Get-VM -Id '%s' -ErrorAction Stop
		Stop-VM -VM $vm -Force:$false -ErrorAction Stop
		Write-Output "SUCCESS"
	} catch {
		Write-Output "ERROR:$($_.Exception.Message)"
	}
	`, vmID)

	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()

	if err != nil {
		return CommandResult{
			Output: map[string]interface{}{
				"success": false,
				"vm_id":   vmID,
				"error":   fmt.Sprintf("Failed to shutdown VM: %v", err),
			},
			Error:  fmt.Sprintf("Failed to shutdown VM: %v", err),
			Status: "error",
		}
	}

	result := strings.TrimSpace(string(output))
	if result == "SUCCESS" {
		// Update database state
		if err := updateVMState("", vmID, "Off"); err != nil {
			log.Printf("Failed to update VM state in database: %v", err)
		}

		return CommandResult{
			Output: map[string]interface{}{
				"success":   true,
				"vm_id":     vmID,
				"operation": "shutdown",
				"message":   "VM shutdown initiated successfully",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
			Error:  "",
			Status: "success",
		}
	} else if strings.HasPrefix(result, "ERROR:") {
		errorMsg := strings.TrimPrefix(result, "ERROR:")
		return CommandResult{
			Output: map[string]interface{}{
				"success": false,
				"vm_id":   vmID,
				"error":   fmt.Sprintf("Failed to shutdown VM: %s", errorMsg),
			},
			Error:  fmt.Sprintf("Failed to shutdown VM: %s", errorMsg),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"success": false,
			"vm_id":   vmID,
			"error":   "Unknown error occurred during VM shutdown",
		},
		Error:  "Unknown error occurred during VM shutdown",
		Status: "error",
	}
}

// executeHyperVOperation is a generic function for VM operations
func executeHyperVOperation(params map[string]interface{}, powershellCmd, operation, resultState string) CommandResult {
	if runtime.GOOS != "windows" {
		return CommandResult{
			Output: map[string]string{"error": "Hyper-V commands are only supported on Windows"},
			Error:  "Hyper-V commands are only supported on Windows",
			Status: "error",
		}
	}

	if params == nil {
		return CommandResult{
			Output: map[string]string{"error": "VM ID parameter is required"},
			Error:  "VM ID parameter is required",
			Status: "error",
		}
	}

	vmID, ok := params["vm_id"].(string)
	if !ok || vmID == "" {
		return CommandResult{
			Output: map[string]string{"error": "Valid VM ID parameter is required"},
			Error:  "Valid VM ID parameter is required",
			Status: "error",
		}
	}

	// Use the most compatible approach: get VM object first, then operate on it
	// This works across all Windows versions and Hyper-V versions
	var additionalParams string

	switch powershellCmd {
	case "Stop-VM":
		additionalParams = " -Force"
	default:
		additionalParams = ""
	}

	script := fmt.Sprintf(`
	try {
		# Get the VM object by ID (most compatible approach)
		$vm = Get-VM -Id '%s' -ErrorAction Stop
		
		# Use the VM object with the command (most compatible)
		%s -VM $vm%s -ErrorAction Stop
		Write-Output "SUCCESS"
	} catch {
		Write-Output "ERROR:$($_.Exception.Message)"
	}
	`, vmID, powershellCmd, additionalParams)

	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return CommandResult{
			Output: map[string]interface{}{
				"success": false,
				"vm_id":   vmID,
				"error":   fmt.Sprintf("Failed to %s VM: %v", operation, err),
			},
			Error:  fmt.Sprintf("Failed to %s VM: %v", operation, err),
			Status: "error",
		}
	}

	result := strings.TrimSpace(string(output))
	if result == "SUCCESS" {
		return CommandResult{
			Output: map[string]interface{}{
				"success":   true,
				"vm_id":     vmID,
				"operation": operation,
				"message":   fmt.Sprintf("VM %s completed successfully", operation),
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
			Error:  "",
			Status: "success",
		}
	} else if strings.HasPrefix(result, "ERROR:") {
		errorMsg := strings.TrimPrefix(result, "ERROR:")
		return CommandResult{
			Output: map[string]interface{}{
				"success": false,
				"vm_id":   vmID,
				"error":   fmt.Sprintf("Failed to %s VM: %s", operation, errorMsg),
			},
			Error:  fmt.Sprintf("Failed to %s VM: %s", operation, errorMsg),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"success": false,
			"vm_id":   vmID,
			"error":   fmt.Sprintf("Unknown error occurred during VM %s", operation),
		},
		Error:  fmt.Sprintf("Unknown error occurred during VM %s", operation),
		Status: "error",
	}
}

// executeHyperVGetVMsFromDB gets VMs from database (fast query)
func executeHyperVGetVMsFromDB(jwtToken string) CommandResult {
	if jwtToken == "" {
		return CommandResult{
			Output: map[string]string{"error": "JWT token required for database operations"},
			Error:  "JWT token required for database operations",
			Status: "error",
		}
	}

	// Get VMs from database
	vms, err := getVMsFromDatabase(jwtToken, deviceID, false)
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to get VMs from database: %v", err)},
			Error:  fmt.Sprintf("Failed to get VMs from database: %v", err),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"virtual_machines": vms,
			"total_count":      len(vms),
			"timestamp":        time.Now().UTC().Format(time.RFC3339),
			"source":           "database",
		},
		Error:  "",
		Status: "success",
	}
}

// executeHyperVSyncAndGet does a full sync (PowerShell + DB update) then returns DB data
func executeHyperVSyncAndGet(jwtToken string) CommandResult {
	if jwtToken == "" {
		return CommandResult{
			Output: map[string]string{"error": "JWT token required for database operations"},
			Error:  "JWT token required for database operations",
			Status: "error",
		}
	}

	// First sync with PowerShell
	syncResult := executeHyperVInventoryWithDB(jwtToken)
	if syncResult.Status != "success" {
		return syncResult // Return the sync error
	}

	// Then get updated data from database
	vms, err := getVMsFromDatabase(jwtToken, deviceID, false)
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to get VMs from database after sync: %v", err)},
			Error:  fmt.Sprintf("Failed to get VMs from database after sync: %v", err),
			Status: "error",
		}
	}

	return CommandResult{
		Output: map[string]interface{}{
			"virtual_machines": vms,
			"total_count":      len(vms),
			"timestamp":        time.Now().UTC().Format(time.RFC3339),
			"source":           "database_after_sync",
			"sync_successful":  true,
		},
		Error:  "",
		Status: "success",
	}
}

// isHyperVAvailable checks if Hyper-V is available on the system
func isHyperVAvailable() bool {
	script := `
	try {
		Get-Command Get-VM -ErrorAction Stop | Out-Null
		Write-Output "AVAILABLE"
	} catch {
		Write-Output "NOT_AVAILABLE"
	}
	`

	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "AVAILABLE"
}
