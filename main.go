package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var deviceID = loadOrCreateDeviceID()

func authenticateDevice() string {
	return createJWT(deviceID)
}

func createJWT(sub string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  sub,
		"role": "authenticated",
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	})
	signedToken, err := token.SignedString([]byte(supabaseJWTSecret))
	if err != nil {
		log.Fatalf("Failed to sign JWT: %v", err)
	}
	return signedToken
}

func connectRealtime(ctx context.Context, jwtToken string) {
	wsURL := fmt.Sprintf("%s?apikey=%s", supabaseWS, supabaseAPIKey)

	headers := http.Header{}
	headers.Add("apikey", supabaseAPIKey)
	headers.Add("Authorization", "Bearer "+jwtToken)

	log.Printf("Connecting to WebSocket...")

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("WebSocket connection failed: %v, Response: %s", err, string(body))
		} else {
			log.Printf("WebSocket connection failed: %v", err)
		}
		log.Printf("Cannot establish WebSocket connection")
		return
	}
	defer conn.Close()

	log.Println("WebSocket connected successfully")

	// Send periodic Phoenix heartbeat
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(25 * time.Second)
				heartbeat := map[string]interface{}{
					"topic":   "phoenix",
					"event":   "heartbeat",
					"payload": map[string]interface{}{},
					"ref":     fmt.Sprintf("%d", time.Now().Unix()),
				}
				if err := conn.WriteJSON(heartbeat); err != nil {
					log.Println("Failed to send heartbeat:", err)
					return
				}
			}
		}
	}()

	// Join the realtime channel
	joinPayload := map[string]interface{}{
		"topic": fmt.Sprintf("realtime:%s:%s", schema, table),
		"event": "phx_join",
		"payload": map[string]interface{}{
			"config": map[string]interface{}{
				"broadcast": map[string]interface{}{"self": false},
				"presence":  map[string]interface{}{"key": ""},
				"postgres_changes": []map[string]interface{}{
					{
						"event":  "INSERT",
						"schema": schema,
						"table":  table,
					},
				},
			},
		},
		"ref": "1",
	}

	if err := conn.WriteJSON(joinPayload); err != nil {
		log.Printf("Failed to send join message: %v", err)
		return
	}

	log.Println("Joined Realtime channel")

	// Modified message reading loop with context support
	for {
		select {
		case <-ctx.Done():
			log.Println("Realtime connection shutting down")
			return
		default:
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("WebSocket read error: %v", err)
				return
			}

			var data map[string]interface{}
			if err := json.Unmarshal(msg, &data); err != nil {
				log.Println("Error decoding WS message:", err)
				continue
			}

			event, _ := data["event"].(string)

			// Handle different event types
			switch event {
			case "postgres_changes":
				payload, ok := data["payload"].(map[string]interface{})
				if !ok {
					continue
				}

				dataField, ok := payload["data"].(map[string]interface{})
				if !ok {
					continue
				}

				record, ok := dataField["record"].(map[string]interface{})
				if !ok {
					continue
				}

				cmdID := fmt.Sprintf("%v", record["id"])
				cmd, _ := record["command"].(string)
				status, _ := record["status"].(string)
				deviceIDFromRecord, _ := record["device_id"].(string)
				parameters, _ := record["parameters"].(string)

				// Check if this command is for our device OR if it's a universal ping command
				if deviceIDFromRecord == deviceID || (cmd == "ping" && deviceIDFromRecord == "") {
					if status == "pending" {
						log.Printf("Processing command: %s", cmd)
						runCommand(jwtToken, cmdID, cmd, parameters)
					}
				}

			case "phx_reply":
				payload, ok := data["payload"].(map[string]interface{})
				if ok {
					status, _ := payload["status"].(string)
					ref, _ := data["ref"].(string)
					if status == "ok" && ref == "1" {
						// Only log success for the initial join (ref="1")
						log.Println("Successfully joined realtime channel")
					} else if status != "ok" {
						log.Printf("Failed to join channel: %+v", payload)
					}
				}
			}
		}
	}
}

func runCommand(jwtToken, cmdID, command, parameters string) {
	log.Printf("Executing command '%s' with ID %s", command, cmdID)

	// Update last_seen whenever any command is executed
	updateLastSeen(jwtToken)

	// Execute the command using the new command system WITH JWT token
	result := ExecuteCommand(command, parameters, jwtToken)

	// Prepare the payload with both old and new formats for transition period
	payload := map[string]interface{}{
		"status": result.Status,
	}

	// Handle the new separate result and logs fields
	if result.Result != nil {
		// New: structured JSON result data goes to result column (JSONB)
		payload["result"] = result.Result
		log.Printf("Command result data: %+v", result.Result)
	} else if result.Output != nil {
		// Backward compatibility: if using old Output field, put it in result
		payload["result"] = result.Output
		log.Printf("Command output (legacy): %+v", result.Output)
	}

	// Handle logs - new dedicated logs field
	var logMessages []string

	if result.Logs != "" {
		logMessages = append(logMessages, result.Logs)
	}

	// Also capture any legacy error messages
	if result.Error != "" {
		logMessages = append(logMessages, "Error: "+result.Error)
	}

	// Combine all log messages
	if len(logMessages) > 0 {
		combinedLogs := strings.Join(logMessages, "\n")
		payload["logs"] = combinedLogs
		log.Printf("Command logs: %s", combinedLogs)
	}

	// Handle screenshot data separately if present
	if result.ScreenshotData != "" {
		payload["screenshot_data"] = result.ScreenshotData
		log.Printf("Screenshot captured (%d bytes base64)", len(result.ScreenshotData))
	}

	// Enhanced logging for better debugging
	if result.Status == "success" {
		if result.Result != nil {
			log.Printf("Command completed successfully with structured result")
		} else {
			log.Printf("Command completed successfully")
		}
	} else {
		if len(logMessages) > 0 {
			log.Printf("Command failed: %s", strings.Join(logMessages, "; "))
		} else {
			log.Printf("Command failed with status: %s", result.Status)
		}
	}

	// Skip command table updates for ping commands since they're universal
	// and multiple devices would conflict updating the same command record
	if command == "ping" {
		log.Printf("Ping command completed - skipping command table update (universal command)")
		return
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal payload: %v", err)
		return
	}

	url := fmt.Sprintf("%s/rest/v1/commands?id=eq.%s", supabaseURL, cmdID)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	// Set headers
	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to update command: %v", err)
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to update command: HTTP %d, Body: %s", resp.StatusCode, string(body))
		return
	}

	log.Printf("Successfully updated command %s with new result/logs structure", cmdID)
}

func heartbeatLoop(ctx context.Context, jwtToken string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(heartbeatPeriod)
			updateLastSeen(jwtToken)
		}
	}
}

func updateLastSeen(jwtToken string) {
	payload := map[string]interface{}{
		"last_seen": time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/rest/v1/devices?id=eq.%s", supabaseURL, deviceID)
	req, _ := http.NewRequest("PATCH", url, bytes.NewBuffer(data))
	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Failed to update last seen:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to update last seen: HTTP %d, Body: %s", resp.StatusCode, string(body))
		return
	}

	log.Println("Heartbeat sent")
}

func registerDevice(jwtToken string) {
	hostname, _ := exec.Command("hostname").Output()

	device := map[string]interface{}{
		"id":        deviceID,
		"name":      strings.TrimSpace(string(hostname)),
		"status":    "online",
		"last_seen": time.Now().UTC().Format(time.RFC3339),
	}

	// Register device immediately with basic info
	data, err := json.Marshal(device)
	if err != nil {
		log.Printf("Failed to marshal device data: %v", err)
		return
	}

	url := supabaseURL + "/rest/v1/devices"
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(data))

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Prefer", "resolution=merge-duplicates")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Register failed:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Registration failed with status %d: %s", resp.StatusCode, string(body))
		return
	}

	log.Println("Device registered successfully")

	// Collect and update asset information in background
	go updateDeviceAssets(jwtToken) // DISABLED FOR TESTING
}

func updateDeviceAssets(jwtToken string) {
	log.Println("Collecting device asset information in background...")
	assets := getDeviceAssets()

	// Debug: Log what we collected
	log.Printf("Asset collection results:")
	log.Printf("- Manufacturer: '%s'", assets.Manufacturer)
	log.Printf("- Model: '%s'", assets.Model)
	log.Printf("- CPU: '%s'", assets.CPU)
	log.Printf("- OS Name: '%s'", assets.OSName)
	log.Printf("- Serial Number: '%s'", assets.SerialNumber)

	// Update device with asset information
	assetData := map[string]interface{}{
		"manufacturer":           assets.Manufacturer,
		"model":                  assets.Model,
		"device_type":            assets.DeviceType,
		"cpu":                    assets.CPU,
		"cpu_cores":              assets.CPUCores,
		"cpu_max_clock_speed":    assets.CPUMaxClockSpeed,
		"cpu_processors":         assets.CPUProcessors,
		"cpu_logical_processors": assets.CPULogicalProcessors,
		"dns_host_name":          assets.DNSHostName,
		"domain":                 assets.Domain,
		"serial_number":          assets.SerialNumber,
		"bios_name":              assets.BIOSName,
		"bios_manufacturer":      assets.BIOSManufacturer,
		"smbios_version":         assets.SMBIOSVersion,
		"bios_release_date":      assets.BIOSReleaseDate,
		"os_name":                assets.OSName,
		"os_type":                assets.OSType,
		"os_version_full":        assets.OSVersionFull,
		"os_product_key":         assets.OSProductKey,
		"os_serial_number":       assets.OSSerialNumber,
		"system_device":          assets.SystemDevice,
		"system_directory":       assets.SystemDirectory,
		"windows_directory":      assets.WindowsDirectory,
		"os_install_date":        assets.OSInstallDate,
		"last_boot_time":         assets.LastBootTime,
	}

	data, err := json.Marshal(assetData)
	if err != nil {
		log.Printf("Failed to marshal asset data: %v", err)
		return
	}

	log.Printf("Asset data JSON size: %d bytes", len(data))

	url := fmt.Sprintf("%s/rest/v1/devices?id=eq.%s", supabaseURL, deviceID)
	req, _ := http.NewRequest("PATCH", url, bytes.NewBuffer(data))

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to update device assets: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		log.Printf("Asset update failed with status %d: %s", resp.StatusCode, string(body))
		return
	}

	log.Println("Device assets updated successfully")
}

func loadOrCreateDeviceID() string {
	var filename string

	// Use platform-appropriate paths
	if runtime.GOOS == "windows" {
		// Windows: Use ProgramData for system-wide data
		filename = `C:\ProgramData\DeviceAgent\agent_id.txt`
		// Create directory if it doesn't exist
		os.MkdirAll(`C:\ProgramData\DeviceAgent`, 0755)
	} else if runtime.GOOS == "darwin" {
		// macOS: Use /Library/Application Support for system-wide data
		filename = filepath.Join("/Library", "Application Support", "DeviceAgent", "agent_id.txt")
		os.MkdirAll(filepath.Join("/Library", "Application Support", "DeviceAgent"), 0755)
	} else {
		// Linux: Use /var/lib for system data
		filename = filepath.Join("/var", "lib", "deviceagent", "agent_id.txt")
		os.MkdirAll(filepath.Join("/var", "lib", "deviceagent"), 0755)
	}

	// Try to read existing ID
	if data, err := os.ReadFile(filename); err == nil {
		return strings.TrimSpace(string(data))
	}

	// Create new ID
	newID := uuid.New().String()
	if err := os.WriteFile(filename, []byte(newID), 0644); err != nil {
		log.Printf("Warning: Could not write device ID to %s: %v", filename, err)
		// Fallback to current directory
		fallbackFile := "agent_id.txt"
		if data, err := os.ReadFile(fallbackFile); err == nil {
			return strings.TrimSpace(string(data))
		}
		os.WriteFile(fallbackFile, []byte(newID), 0644)
	}

	return newID
}

func checkMissedCommands(jwtToken string) {
	// Query for commands: ping commands (universal) + device-specific commands for this device
	url := fmt.Sprintf("%s/rest/v1/commands?or=(and(command.eq.ping,status.eq.pending),and(device_id.eq.%s,status.eq.pending))", supabaseURL, deviceID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Failed to check missed commands:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch missed commands: HTTP %d", resp.StatusCode)
		return
	}

	var commands []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&commands); err != nil {
		log.Println("Failed to decode missed commands:", err)
		return
	}

	if len(commands) > 0 {
		log.Printf("Found %d missed commands", len(commands))
	}

	now := time.Now()
	for _, record := range commands {
		cmdID := fmt.Sprintf("%v", record["id"])
		cmd := fmt.Sprintf("%v", record["command"])
		parameters, _ := record["parameters"].(string)
		
		// Check command age (skip commands older than 10 minutes for non-ping commands)
		if cmd != "ping" {
			if createdAtStr, ok := record["created_at"].(string); ok {
				if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
					if now.Sub(createdAt) > 10*time.Minute {
						log.Printf("Skipping old command %s (age: %v)", cmdID, now.Sub(createdAt))
						continue
					}
				}
			}
		}
		
		runCommand(jwtToken, cmdID, cmd, parameters)
	}
}
