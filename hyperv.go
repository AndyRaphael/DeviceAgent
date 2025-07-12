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
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	State      string  `json:"state"`
	Status     string  `json:"status"`
	Health     string  `json:"health"`
	Uptime     string  `json:"uptime"`
	Generation *int    `json:"generation,omitempty"`
	Version    *string `json:"version,omitempty"`
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

	// Get VMs from PowerShell with enhanced data collection
	vms, err := getVMsFromPowerShell()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to get VM inventory: %v", err)},
			Error:  fmt.Sprintf("Failed to get VM inventory: %v", err),
			Status: "error",
		}
	}

	// Return result with enhanced data
	result := map[string]interface{}{
		"virtual_machines": vms,
		"total_count":      len(vms),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"source":           "live_powershell_enhanced",
		"data_fields":      []string{"id", "name", "state", "status", "health", "installation_date", "start_time", "uptime_seconds", "cpu_cores", "memory_mb", "generation", "version"},
	}

	return CommandResult{
		Output: result,
		Error:  "",
		Status: "success",
	}
}

// getVMsFromPowerShell extracts VM information with enhanced data collection
func getVMsFromPowerShell() ([]HyperVVM, error) {
	// Enhanced PowerShell script to collect all VM properties
	script := `
		Get-VM | ForEach-Object {
		$vm = $_
		$uptime = ""
		
		if ($vm.State -eq "Running" -and $vm.Uptime) {
			$uptime = "$($vm.Uptime.Days)d $($vm.Uptime.Hours)h $($vm.Uptime.Minutes)m"
		}
		
		$generation = $null
		try {
			if ($vm.Generation) {
				$generation = $vm.Generation
			}
		} catch {
			$generation = $null
		}
		
		$version = ""
		try {
			if ($vm.Version) {
				$version = $vm.Version.ToString()
			}
		} catch {
			$version = ""
		}
		
		$healthStatus = ""
		try {
			if ($vm.OperationalStatus) {
				if ($vm.OperationalStatus -is [array]) {
					$healthStatus = ($vm.OperationalStatus | ForEach-Object { $_.ToString() }) -join ", "
				} else {
					$healthStatus = $vm.OperationalStatus.ToString()
				}
			}
		} catch {
			$healthStatus = "Unknown"
		}
		
		[PSCustomObject]@{
			Id = $vm.Id.ToString()
			Name = $vm.Name
			State = $vm.State.ToString()
			Status = $vm.Status.ToString()
			Health = $healthStatus
			Uptime = $uptime
			Generation = if ($generation -ne $null) { [int]$generation } else { $null }
			Version = $version
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

// executeHyperVInventoryWithDB gets enhanced inventory and updates database
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

	// Get VMs from PowerShell with enhanced data collection
	vms, err := getVMsFromPowerShell()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to get VM inventory: %v", err)},
			Error:  fmt.Sprintf("Failed to get VM inventory: %v", err),
			Status: "error",
		}
	}

	// Update database with enhanced inventory
	dbUpdateError := ""
	if err := updateVMDatabase(jwtToken, deviceID, vms); err != nil {
		dbUpdateError = fmt.Sprintf("Database update failed: %v", err)
		log.Printf("Database update error: %v", err)
	}

	// Return result with enhanced data and statistics
	result := map[string]interface{}{
		"virtual_machines": vms,
		"total_count":      len(vms),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"source":           "live_powershell_enhanced_with_db_update",
		"database_updated": dbUpdateError == "",
		"data_fields":      []string{"id", "name", "state", "status", "health", "uptime", "generation", "version"},
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

// SECURE REPLACEMENTS for Hyper-V operation functions in hyperv.go

// executeHyperVScreenshot captures VM screen with input validation
func executeHyperVScreenshot(params map[string]interface{}) CommandResult {
	var logs []string
	logs = append(logs, "Hyper-V screenshot command initiated with security validation")

	if runtime.GOOS != "windows" {
		errorMsg := "Hyper-V commands are only supported on Windows"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	if params == nil {
		errorMsg := "VM ID parameter is required"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	vmID, ok := params["vm_id"].(string)
	if !ok || vmID == "" {
		errorMsg := "Valid VM ID parameter is required"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// SECURITY: Validate VM ID to prevent injection
	logs = append(logs, "Validating VM ID format for security")
	if err := validateVMID(vmID); err != nil {
		errorMsg := fmt.Sprintf("Invalid VM ID: %v", err)
		logs = append(logs, errorMsg)
		logs = append(logs, "SECURITY: VM ID validation failed - potential injection attempt")
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}
	logs = append(logs, "VM ID validation passed")

	// First check if VM exists and is running (using working method with sanitized input)
	sanitizedVMID := sanitizeForPowerShell(vmID)
	checkScript := fmt.Sprintf(`
	try {
		$vm = Get-VM -Id '%s' -ErrorAction Stop
		Write-Output "VM_FOUND:$($vm.Name):$($vm.State)"
	} catch {
		Write-Output "VM_ERROR:$($_.Exception.Message)"
	}
	`, sanitizedVMID)

	logs = append(logs, "Executing VM existence check with sanitized input")
	checkCmd := exec.Command("powershell", "-Command", checkScript)
	checkOutput, err := checkCmd.CombinedOutput()

	if err != nil {
		errorMsg := fmt.Sprintf("VM lookup failed: %v", err)
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	checkResult := strings.TrimSpace(string(checkOutput))

	if strings.HasPrefix(checkResult, "VM_ERROR:") {
		errorMsg := strings.TrimPrefix(checkResult, "VM_ERROR:")
		logs = append(logs, fmt.Sprintf("VM error: %s", errorMsg))
		return NewErrorResultWithDetails(fmt.Sprintf("VM error: %s", errorMsg), strings.Join(logs, "\n"))
	}

	if !strings.HasPrefix(checkResult, "VM_FOUND:") {
		errorMsg := "Unexpected VM lookup result"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// Parse VM info
	parts := strings.Split(checkResult, ":")
	if len(parts) < 3 {
		errorMsg := "Invalid VM info format"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	vmName := parts[1]
	vmState := parts[2]
	logs = append(logs, fmt.Sprintf("VM found: %s (State: %s)", vmName, vmState))

	if vmState != "Running" {
		errorMsg := fmt.Sprintf("Cannot capture screenshot - VM is not running (state: %s)", vmState)
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// Now capture actual VM screen using Hyper-V WMI method with sanitized VM name
	sanitizedVMName := sanitizeForPowerShell(vmName)
	screenshotScript := fmt.Sprintf(`
	try {
		# Add required assemblies
		Add-Type -AssemblyName "System.Drawing"
		
		# Get the VM using WMI (by VM name since we have it) - using sanitized name
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
		
		# Create JPEG encoder with quality setting (70%% quality for good balance)
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
	`, sanitizedVMName)

	logs = append(logs, "Executing VM screenshot capture with sanitized inputs")
	screenshotCmd := exec.Command("powershell", "-Command", screenshotScript)
	screenshotOutput, err := screenshotCmd.CombinedOutput()

	if err != nil {
		errorMsg := fmt.Sprintf("Screenshot command failed: %v", err)
		logs = append(logs, errorMsg)
		result := map[string]interface{}{
			"error":      errorMsg,
			"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
			"raw_output": string(screenshotOutput),
		}
		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	screenshotResult := strings.TrimSpace(string(screenshotOutput))

	if strings.HasPrefix(screenshotResult, "SUCCESS:") {
		// Parse the result which now includes dimensions
		resultParts := strings.SplitN(screenshotResult, ":", 3)
		if len(resultParts) < 3 {
			errorMsg := "Invalid screenshot result format"
			logs = append(logs, errorMsg)
			return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
		}

		dimensions := resultParts[1]
		base64Data := resultParts[2]

		// Update VM last_seen in database
		if err := updateVMLastSeen("", vmID); err != nil {
			logs = append(logs, fmt.Sprintf("Warning: Failed to update VM last_seen: %v", err))
		}

		logs = append(logs, "Screenshot captured successfully with security validation")

		result := map[string]interface{}{
			"success":    true,
			"vm_id":      vmID,
			"vm_name":    vmName,
			"vm_state":   vmState,
			"dimensions": dimensions,
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
			"message":    "VM screenshot captured, resized, and compressed successfully",
			"method":     "wmi_thumbnail_jpeg_compressed_secure",
			"format":     "JPEG",
			"quality":    "70%",
		}

		return CommandResult{
			Result:         result,
			ScreenshotData: base64Data,
			Logs:           strings.Join(logs, "\n"),
			Status:         "success",
		}
	} else if strings.HasPrefix(screenshotResult, "WMI_ERROR:") {
		errorMsg := strings.TrimPrefix(screenshotResult, "WMI_ERROR:")
		logs = append(logs, fmt.Sprintf("WMI error: %s", errorMsg))
		result := map[string]interface{}{
			"error":      fmt.Sprintf("WMI error: %s", errorMsg),
			"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
			"suggestion": "VM may not support screen capture or video head not available",
		}
		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	} else if strings.HasPrefix(screenshotResult, "SCREENSHOT_ERROR:") {
		errorMsg := strings.TrimPrefix(screenshotResult, "SCREENSHOT_ERROR:")
		logs = append(logs, fmt.Sprintf("Screenshot error: %s", errorMsg))
		result := map[string]interface{}{
			"error":      fmt.Sprintf("Screenshot error: %s", errorMsg),
			"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
			"raw_output": screenshotResult,
		}
		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	errorMsg := "Unexpected screenshot result"
	logs = append(logs, errorMsg)
	result := map[string]interface{}{
		"error":      errorMsg,
		"vm_info":    fmt.Sprintf("%s (%s)", vmName, vmState),
		"raw_output": screenshotResult,
	}
	return CommandResult{
		Result: result,
		Logs:   strings.Join(logs, "\n"),
		Status: "error",
	}
}

// SECURE REPLACEMENTS for VM control functions in hyperv.go

// executeHyperVOperation is a generic function for VM operations with security validation
func executeHyperVOperation(params map[string]interface{}, powershellCmd, operation, resultState string) CommandResult {
	var logs []string
	logs = append(logs, fmt.Sprintf("Hyper-V %s operation initiated with security validation", operation))

	if runtime.GOOS != "windows" {
		errorMsg := "Hyper-V commands are only supported on Windows"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	if params == nil {
		errorMsg := "VM ID parameter is required"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	vmID, ok := params["vm_id"].(string)
	if !ok || vmID == "" {
		errorMsg := "Valid VM ID parameter is required"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// SECURITY: Validate VM ID to prevent injection
	logs = append(logs, "Validating VM ID format for security")
	if err := validateVMID(vmID); err != nil {
		errorMsg := fmt.Sprintf("Invalid VM ID: %v", err)
		logs = append(logs, errorMsg)
		logs = append(logs, "SECURITY: VM ID validation failed - potential injection attempt")
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}
	logs = append(logs, "VM ID validation passed")

	// Use the most compatible approach: get VM object first, then operate on it
	// This works across all Windows versions and Hyper-V versions
	var additionalParams string

	switch powershellCmd {
	case "Stop-VM":
		additionalParams = " -Force"
	default:
		additionalParams = ""
	}

	// Sanitize VM ID for PowerShell execution
	sanitizedVMID := sanitizeForPowerShell(vmID)

	script := fmt.Sprintf(`
	try {
		# Get the VM object by ID (most compatible approach) - using sanitized input
		$vm = Get-VM -Id '%s' -ErrorAction Stop
		
		# Use the VM object with the command (most compatible)
		%s -VM $vm%s -ErrorAction Stop
		Write-Output "SUCCESS"
	} catch {
		Write-Output "ERROR:$($_.Exception.Message)"
	}
	`, sanitizedVMID, powershellCmd, additionalParams)

	logs = append(logs, fmt.Sprintf("Executing %s operation with sanitized VM ID", operation))
	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to %s VM: %v", operation, err)
		logs = append(logs, errorMsg)

		result := map[string]interface{}{
			"success": false,
			"vm_id":   vmID,
			"error":   errorMsg,
		}

		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	result := strings.TrimSpace(string(output))
	if result == "SUCCESS" {
		logs = append(logs, fmt.Sprintf("VM %s operation completed successfully", operation))

		resultData := map[string]interface{}{
			"success":   true,
			"vm_id":     vmID,
			"operation": operation,
			"message":   fmt.Sprintf("VM %s completed successfully", operation),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"method":    "secure_powershell_operation",
		}

		return CommandResult{
			Result: resultData,
			Logs:   strings.Join(logs, "\n"),
			Status: "success",
		}
	} else if strings.HasPrefix(result, "ERROR:") {
		errorMsg := strings.TrimPrefix(result, "ERROR:")
		logs = append(logs, fmt.Sprintf("VM %s failed: %s", operation, errorMsg))

		resultData := map[string]interface{}{
			"success": false,
			"vm_id":   vmID,
			"error":   fmt.Sprintf("Failed to %s VM: %s", operation, errorMsg),
		}

		return CommandResult{
			Result: resultData,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	errorMsg := fmt.Sprintf("Unknown error occurred during VM %s", operation)
	logs = append(logs, errorMsg)

	resultData := map[string]interface{}{
		"success": false,
		"vm_id":   vmID,
		"error":   errorMsg,
	}

	return CommandResult{
		Result: resultData,
		Logs:   strings.Join(logs, "\n"),
		Status: "error",
	}
}

// executeHyperVShutdown gracefully shuts down a VM with security validation
func executeHyperVShutdown(params map[string]interface{}) CommandResult {
	var logs []string
	logs = append(logs, "Hyper-V shutdown operation initiated with security validation")

	if runtime.GOOS != "windows" {
		errorMsg := "Hyper-V commands are only supported on Windows"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	if params == nil {
		errorMsg := "VM ID parameter is required"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	vmID, ok := params["vm_id"].(string)
	if !ok || vmID == "" {
		errorMsg := "Valid VM ID parameter is required"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// SECURITY: Validate VM ID to prevent injection
	logs = append(logs, "Validating VM ID format for security")
	if err := validateVMID(vmID); err != nil {
		errorMsg := fmt.Sprintf("Invalid VM ID: %v", err)
		logs = append(logs, errorMsg)
		logs = append(logs, "SECURITY: VM ID validation failed - potential injection attempt")
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}
	logs = append(logs, "VM ID validation passed")

	// Use Stop-VM with graceful shutdown using VM object with sanitized input
	sanitizedVMID := sanitizeForPowerShell(vmID)
	script := fmt.Sprintf(`
	try {
		$vm = Get-VM -Id '%s' -ErrorAction Stop
		Stop-VM -VM $vm -Force:$false -ErrorAction Stop
		Write-Output "SUCCESS"
	} catch {
		Write-Output "ERROR:$($_.Exception.Message)"
	}
	`, sanitizedVMID)

	logs = append(logs, "Executing graceful shutdown with sanitized VM ID")
	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()

	if err != nil {
		errorMsg := fmt.Sprintf("Failed to shutdown VM: %v", err)
		logs = append(logs, errorMsg)

		result := map[string]interface{}{
			"success": false,
			"vm_id":   vmID,
			"error":   errorMsg,
		}

		return CommandResult{
			Result: result,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	result := strings.TrimSpace(string(output))
	if result == "SUCCESS" {
		// Update database state
		if err := updateVMState("", vmID, "Off"); err != nil {
			logs = append(logs, fmt.Sprintf("Warning: Failed to update VM state in database: %v", err))
		}

		logs = append(logs, "VM graceful shutdown completed successfully")

		resultData := map[string]interface{}{
			"success":   true,
			"vm_id":     vmID,
			"operation": "shutdown",
			"message":   "VM shutdown initiated successfully",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"method":    "secure_graceful_shutdown",
		}

		return CommandResult{
			Result: resultData,
			Logs:   strings.Join(logs, "\n"),
			Status: "success",
		}
	} else if strings.HasPrefix(result, "ERROR:") {
		errorMsg := strings.TrimPrefix(result, "ERROR:")
		logs = append(logs, fmt.Sprintf("VM shutdown failed: %s", errorMsg))

		resultData := map[string]interface{}{
			"success": false,
			"vm_id":   vmID,
			"error":   fmt.Sprintf("Failed to shutdown VM: %s", errorMsg),
		}

		return CommandResult{
			Result: resultData,
			Logs:   strings.Join(logs, "\n"),
			Status: "error",
		}
	}

	errorMsg := "Unknown error occurred during VM shutdown"
	logs = append(logs, errorMsg)

	resultData := map[string]interface{}{
		"success": false,
		"vm_id":   vmID,
		"error":   errorMsg,
	}

	return CommandResult{
		Result: resultData,
		Logs:   strings.Join(logs, "\n"),
		Status: "error",
	}
}

// Secure wrapper functions that now call the secure executeHyperVOperation
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

// executeHyperVGetVMsFromDB gets VMs from database with enhanced logging
func executeHyperVGetVMsFromDB(jwtToken string) CommandResult {
	var logs []string
	logs = append(logs, "Retrieving VMs from database (fast query)")

	if jwtToken == "" {
		errorMsg := "JWT token required for database operations"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// Get VMs from database
	logs = append(logs, "Querying VM database")
	vms, err := getVMsFromDatabase(jwtToken, deviceID, false)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to get VMs from database: %v", err)
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	logs = append(logs, fmt.Sprintf("Successfully retrieved %d VMs from database", len(vms)))

	result := map[string]interface{}{
		"virtual_machines": vms,
		"total_count":      len(vms),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"source":           "database",
		"method":           "database_query",
	}

	return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
}

// executeHyperVSyncAndGet does a full sync then returns DB data with enhanced logging
func executeHyperVSyncAndGet(jwtToken string) CommandResult {
	var logs []string
	logs = append(logs, "Starting full VM sync and retrieval")

	if jwtToken == "" {
		errorMsg := "JWT token required for database operations"
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	// First sync with PowerShell
	logs = append(logs, "Phase 1: Syncing with PowerShell")
	syncResult := executeHyperVInventoryWithDB(jwtToken)
	if syncResult.Status != "success" {
		logs = append(logs, "PowerShell sync failed")
		// Add sync logs to our logs
		if syncResult.Logs != "" {
			logs = append(logs, "Sync operation logs:")
			logs = append(logs, syncResult.Logs)
		}
		return NewErrorResultWithDetails("Sync operation failed", strings.Join(logs, "\n"))
	}
	logs = append(logs, "PowerShell sync completed successfully")

	// Then get updated data from database
	logs = append(logs, "Phase 2: Retrieving updated data from database")
	vms, err := getVMsFromDatabase(jwtToken, deviceID, false)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to get VMs from database after sync: %v", err)
		logs = append(logs, errorMsg)
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}

	logs = append(logs, fmt.Sprintf("Successfully retrieved %d VMs from database after sync", len(vms)))

	result := map[string]interface{}{
		"virtual_machines": vms,
		"total_count":      len(vms),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"source":           "database_after_sync",
		"sync_successful":  true,
		"method":           "full_sync_and_retrieve",
	}

	return NewSuccessResultWithLogs(result, strings.Join(logs, "\n"))
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
