package main

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DeviceAssets represents all device asset information
type DeviceAssets struct {
	Name                 string `json:"name"`
	Manufacturer         string `json:"manufacturer"`
	Model                string `json:"model"`
	DeviceType           string `json:"device_type"`
	CPU                  string `json:"cpu"`
	CPUCores             int    `json:"cpu_cores"`
	CPUMaxClockSpeed     int    `json:"cpu_max_clock_speed"`
	CPUProcessors        int    `json:"cpu_processors"`
	CPULogicalProcessors int    `json:"cpu_logical_processors"`
	DNSHostName          string `json:"dns_host_name"`
	Domain               string `json:"domain"`
	SerialNumber         string `json:"serial_number"`
	BIOSName             string `json:"bios_name"`
	BIOSManufacturer     string `json:"bios_manufacturer"`
	SMBIOSVersion        string `json:"smbios_version"`
	BIOSReleaseDate      string `json:"bios_release_date"`
	OSName               string `json:"os_name"`
	OSType               string `json:"os_type"`
	OSVersionFull        string `json:"os_version_full"`
	OSProductKey         string `json:"os_product_key"`
	OSSerialNumber       string `json:"os_serial_number"`
	SystemDevice         string `json:"system_device"`
	SystemDirectory      string `json:"system_directory"`
	WindowsDirectory     string `json:"windows_directory"`
	OSInstallDate        string `json:"os_install_date"`
	LastBootTime         string `json:"last_boot_time"`
}

// getDeviceAssets collects comprehensive device asset information
func getDeviceAssets() DeviceAssets {
	if runtime.GOOS == "windows" {
		return getWindowsAssets()
	}
	return getUnixAssets()
}

// getWindowsAssets collects Windows-specific asset information
func getWindowsAssets() DeviceAssets {
	assets := DeviceAssets{}

	// Computer System Information
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "Name"); result != "" {
		assets.Name = result
	}
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "Manufacturer"); result != "" {
		assets.Manufacturer = result
	}
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "Model"); result != "" {
		assets.Model = result
	}
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "SystemType"); result != "" {
		assets.DeviceType = result
	}
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "DNSHostName"); result != "" {
		assets.DNSHostName = result
	}
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "Domain"); result != "" {
		assets.Domain = result
	}

	// CPU Information - get only first processor to avoid duplicates
	if result := getPowerShellWMIValue("Win32_Processor", "Name"); result != "" {
		// Split by newlines and take first entry to avoid duplicates
		lines := strings.Split(result, "\n")
		if len(lines) > 0 {
			assets.CPU = strings.TrimSpace(lines[0])
		}
	}
	if result := getPowerShellWMIValue("Win32_Processor", "NumberOfCores"); result != "" {
		// For multiple processors, sum the cores
		lines := strings.Split(result, "\n")
		totalCores := 0
		for _, line := range lines {
			if cores, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
				totalCores += cores
			}
		}
		assets.CPUCores = totalCores
	}
	if result := getPowerShellWMIValue("Win32_Processor", "MaxClockSpeed"); result != "" {
		// Take the first processor's max clock speed
		lines := strings.Split(result, "\n")
		if len(lines) > 0 {
			if speed, err := strconv.Atoi(strings.TrimSpace(lines[0])); err == nil {
				assets.CPUMaxClockSpeed = speed
			}
		}
	}
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "NumberOfProcessors"); result != "" {
		if processors, err := strconv.Atoi(result); err == nil {
			assets.CPUProcessors = processors
		}
	}
	if result := getPowerShellWMIValue("Win32_ComputerSystem", "NumberOfLogicalProcessors"); result != "" {
		if logical, err := strconv.Atoi(result); err == nil {
			assets.CPULogicalProcessors = logical
		}
	}

	// BIOS Information
	if result := getPowerShellWMIValue("Win32_BIOS", "Name"); result != "" {
		assets.BIOSName = result
	}
	if result := getPowerShellWMIValue("Win32_BIOS", "Manufacturer"); result != "" {
		assets.BIOSManufacturer = result
	}
	if result := getPowerShellWMIValue("Win32_BIOS", "SMBIOSBIOSVersion"); result != "" {
		assets.SMBIOSVersion = result
	}
	if result := getPowerShellWMIValue("Win32_BIOS", "ReleaseDate"); result != "" {
		assets.BIOSReleaseDate = formatWMIDate(result)
	}
	if result := getPowerShellWMIValue("Win32_BIOS", "SerialNumber"); result != "" {
		assets.SerialNumber = result
	}

	// Operating System Information
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "Caption"); result != "" {
		assets.OSName = result
	}
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "Version"); result != "" {
		assets.OSVersionFull = result
	}
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "SerialNumber"); result != "" {
		assets.OSSerialNumber = result
	}
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "SystemDevice"); result != "" {
		assets.SystemDevice = result
	}
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "SystemDirectory"); result != "" {
		assets.SystemDirectory = result
	}
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "WindowsDirectory"); result != "" {
		assets.WindowsDirectory = result
	}
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "InstallDate"); result != "" {
		assets.OSInstallDate = formatWMIDate(result)
	}
	if result := getPowerShellWMIValue("Win32_OperatingSystem", "LastBootUpTime"); result != "" {
		assets.LastBootTime = formatWMIDate(result)
	}

	// Get OS Product Key (requires different approach)
	assets.OSProductKey = getPowerShellProductKey()

	// Set basic OS info (remove old os_version since we have os_version_full)
	assets.OSType = getOSType()

	return assets
}

// getUnixAssets collects Unix/macOS asset information
func getUnixAssets() DeviceAssets {
	assets := DeviceAssets{}

	// Basic information
	if hostname, err := exec.Command("hostname").Output(); err == nil {
		assets.Name = strings.TrimSpace(string(hostname))
		assets.DNSHostName = strings.TrimSpace(string(hostname))
	}

	// System information
	if uname, err := exec.Command("uname", "-m").Output(); err == nil {
		assets.DeviceType = strings.TrimSpace(string(uname))
	}

	// Set basic OS info (remove old os_version since we have os_version_full)
	assets.OSType = getOSType()

	if runtime.GOOS == "darwin" {
		// macOS specific - use multiple system_profiler data types
		if result := getSystemProfilerValue("SPHardwareDataType", "Model Name"); result != "" {
			assets.Model = result
		}
		if result := getSystemProfilerValue("SPHardwareDataType", "Chip"); result != "" {
			assets.CPU = result
		} else if result := getSystemProfilerValue("SPHardwareDataType", "Processor Name"); result != "" {
			assets.CPU = result
		}
		if result := getSystemProfilerValue("SPHardwareDataType", "Serial Number"); result != "" {
			assets.SerialNumber = result
		}
		if result := getSystemProfilerValue("SPHardwareDataType", "Total Number of Cores"); result != "" {
			if cores, err := strconv.Atoi(result); err == nil {
				assets.CPUCores = cores
			}
		}

		// Get manufacturer (Apple for Mac)
		assets.Manufacturer = "Apple Inc."

		// Get more system info using sw_vers
		if result := getMacOSVersion(); result != "" {
			assets.OSName = result
		}
		if result := getMacOSBuildVersion(); result != "" {
			assets.OSVersionFull = result
		}

		// Try to get CPU speed
		if result := getMacOSCPUSpeed(); result != "" {
			if speed, err := strconv.Atoi(result); err == nil {
				assets.CPUMaxClockSpeed = speed
			}
		}

		// Get memory info
		if result := getMacOSMemory(); result != "" {
			// Memory info is available but in different format
		}

		// Get more detailed model info
		if result := getSystemProfilerValue("SPHardwareDataType", "Model Identifier"); result != "" {
			if assets.DeviceType == "" {
				assets.DeviceType = result
			}
		}

		// Get hostname for DNS name
		if hostname, err := exec.Command("hostname").Output(); err == nil {
			assets.DNSHostName = strings.TrimSpace(string(hostname))
		}

	} else {
		// Linux specific
		if dmidecode, err := exec.Command("dmidecode", "-s", "system-manufacturer").Output(); err == nil {
			assets.Manufacturer = strings.TrimSpace(string(dmidecode))
		}
		if dmidecode, err := exec.Command("dmidecode", "-s", "system-product-name").Output(); err == nil {
			assets.Model = strings.TrimSpace(string(dmidecode))
		}
		if dmidecode, err := exec.Command("dmidecode", "-s", "system-serial-number").Output(); err == nil {
			assets.SerialNumber = strings.TrimSpace(string(dmidecode))
		}
	}

	return assets
}

// getWMICValue executes WMIC command and returns a specific value
func getWMICValue(class, property string) string {
	cmd := exec.Command("wmic", class, "get", property, "/value")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("WMIC command failed for %s.%s: %v", class, property, err)
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, property+"=") {
			value := strings.TrimPrefix(line, property+"=")
			result := strings.TrimSpace(value)
			log.Printf("WMIC %s.%s = '%s'", class, property, result)
			return result
		}
	}
	log.Printf("WMIC %s.%s = no value found", class, property)
	return ""
}

// getMacOSVersion gets macOS version using sw_vers
func getMacOSVersion() string {
	cmd := exec.Command("sw_vers", "-productName")
	productName, err1 := cmd.Output()

	cmd = exec.Command("sw_vers", "-productVersion")
	productVersion, err2 := cmd.Output()

	if err1 == nil && err2 == nil {
		name := strings.TrimSpace(string(productName))
		version := strings.TrimSpace(string(productVersion))
		result := name + " " + version
		log.Printf("getMacOSVersion: %s", result)
		return result
	}

	log.Printf("getMacOSVersion failed: err1=%v, err2=%v", err1, err2)
	return ""
}

// getMacOSBuildVersion gets macOS build version
func getMacOSBuildVersion() string {
	cmd := exec.Command("sw_vers", "-buildVersion")
	output, err := cmd.Output()
	if err == nil {
		result := strings.TrimSpace(string(output))
		log.Printf("getMacOSBuildVersion: %s", result)
		return result
	}
	log.Printf("getMacOSBuildVersion failed: %v", err)
	return ""
}

// getMacOSLastBootTime gets macOS last boot time
func getMacOSLastBootTime() string {
	// Try sysctl kern.boottime
	cmd := exec.Command("sysctl", "-n", "kern.boottime")
	if output, err := cmd.Output(); err == nil {
		boottime := strings.TrimSpace(string(output))
		log.Printf("getMacOSLastBootTime raw: %s", boottime)

		// Parse sysctl boottime format: { sec = 1234567890, usec = 123456 }
		re := regexp.MustCompile(`sec = (\d+)`)
		matches := re.FindStringSubmatch(boottime)
		if len(matches) > 1 {
			if timestamp, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
				bootTime := time.Unix(timestamp, 0)
				result := bootTime.Format(time.RFC3339)
				log.Printf("getMacOSLastBootTime parsed: %s", result)
				return result
			}
		}
	}

	// Alternative: try uptime and calculate
	cmd = exec.Command("uptime")
	if output, err := cmd.Output(); err == nil {
		log.Printf("getMacOSLastBootTime uptime: %s", string(output))
		// This gives relative time, would need parsing
	}

	log.Printf("getMacOSLastBootTime failed")
	return ""
}

// getMacOSMemory gets macOS memory information
func getMacOSMemory() string {
	cmd := exec.Command("sysctl", "-n", "hw.memsize")
	if output, err := cmd.Output(); err == nil {
		if memBytes, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
			memGB := memBytes / (1024 * 1024 * 1024)
			return fmt.Sprintf("%d GB", memGB)
		}
	}
	return ""
}

// getPowerShellWMIValue executes PowerShell Get-WmiObject command and returns a specific property value
func getPowerShellWMIValue(class, property string) string {
	script := fmt.Sprintf("(Get-WmiObject -Class %s).%s", class, property)
	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("PowerShell WMI command failed for %s.%s: %v", class, property, err)
		return ""
	}

	result := strings.TrimSpace(string(output))
	log.Printf("PowerShell WMI %s.%s = '%s'", class, property, result)
	return result
}

// getPowerShellProductKey attempts to get Windows product key using PowerShell
func getPowerShellProductKey() string {
	script := "(Get-WmiObject -Class SoftwareLicensingService).OA3xOriginalProductKey"
	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("PowerShell product key command failed: %v", err)
		return ""
	}

	result := strings.TrimSpace(string(output))
	if result != "" {
		log.Printf("PowerShell Product Key found")
		return result
	}
	return ""
}

// formatWMIDate converts WMI date format to readable format
func formatWMIDate(wmiDate string) string {
	if len(wmiDate) >= 14 {
		// WMI date format: YYYYMMDDHHMMSS.ssssss+/-UUU
		year := wmiDate[0:4]
		month := wmiDate[4:6]
		day := wmiDate[6:8]
		hour := wmiDate[8:10]
		minute := wmiDate[10:12]
		second := wmiDate[12:14]

		return year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second
	}
	return wmiDate
}

// getSystemProfilerValue gets macOS system profiler values
func getSystemProfilerValue(dataType, key string) string {
	cmd := exec.Command("system_profiler", dataType)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("system_profiler failed for %s: %v", dataType, err)
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Look for the key with colon - try multiple patterns
		patterns := []string{
			key + ":",
			key + " :",
		}

		for _, pattern := range patterns {
			if strings.Contains(line, pattern) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					result := strings.TrimSpace(parts[1])
					if result != "" {
						log.Printf("system_profiler %s.%s = '%s'", dataType, key, result)
						return result
					}
				}
			}
		}

		// Also try with different spacing patterns
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, key+":") {
			value := strings.TrimPrefix(trimmedLine, key+":")
			result := strings.TrimSpace(value)
			if result != "" {
				log.Printf("system_profiler %s.%s = '%s'", dataType, key, result)
				return result
			}
		}
	}

	// Debug: Show what keys are actually available
	log.Printf("system_profiler %s.%s = no value found", dataType, key)
	log.Printf("Available keys in %s:", dataType)
	for _, line := range lines {
		if strings.Contains(line, ":") && !strings.HasPrefix(strings.TrimSpace(line), " ") {
			log.Printf("  - %s", strings.TrimSpace(line))
		}
	}

	return ""
}

// getMacOSCPUSpeed tries to get CPU speed from multiple sources
func getMacOSCPUSpeed() string {
	// Try sysctl first
	cmd := exec.Command("sysctl", "-n", "hw.cpufrequency_max")
	if output, err := cmd.Output(); err == nil {
		// Convert from Hz to MHz
		if freq, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
			return strconv.Itoa(int(freq / 1000000))
		}
	}

	// Try alternative sysctl
	cmd = exec.Command("sysctl", "-n", "hw.cpufrequency")
	if output, err := cmd.Output(); err == nil {
		if freq, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
			return strconv.Itoa(int(freq / 1000000))
		}
	}

	// Try system_profiler for CPU speed
	cmd = exec.Command("system_profiler", "SPHardwareDataType")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "processor speed") {
				// Look for speed in GHz format
				re := regexp.MustCompile(`(\d+\.?\d*)\s*GHz`)
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 {
					if ghz, err := strconv.ParseFloat(matches[1], 64); err == nil {
						return strconv.Itoa(int(ghz * 1000)) // Convert GHz to MHz
					}
				}
			}
		}
	}

	return ""
}

// getOSType returns the operating system type
func getOSType() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	default:
		return runtime.GOOS
	}
}
