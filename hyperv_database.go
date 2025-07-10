package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// HyperVVMRecord represents a VM record in the database
type HyperVVMRecord struct {
	ID               string    `json:"id,omitempty"`
	VMID             string    `json:"vm_id"`
	VMName           string    `json:"vm_name"`
	DeviceID         string    `json:"device_id"`
	State            string    `json:"state"`
	Status           string    `json:"status"`
	Health           string    `json:"health"`
	InstallationDate *string   `json:"installation_date,omitempty"`
	StartTime        *string   `json:"start_time,omitempty"`
	UptimeSeconds    *int      `json:"uptime_seconds,omitempty"`
	CPUCores         *int      `json:"cpu_cores,omitempty"`
	MemoryMB         *int64    `json:"memory_mb,omitempty"`
	Generation       *int      `json:"generation,omitempty"`
	Version          *string   `json:"version,omitempty"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	LastUpdated      time.Time `json:"last_updated"`
	IsDeleted        bool      `json:"is_deleted"`
}

// SAFE REPLACEMENT for updateVMDatabase function in hyperv_database.go

// updateVMDatabase updates the VM database with current inventory - ENHANCED LOGGING
func updateVMDatabase(jwtToken, deviceID string, vms []HyperVVM) error {
	log.Printf("Starting VM database update for device %s with %d VMs", deviceID, len(vms))

	// Convert VMs to database records
	var vmRecords []HyperVVMRecord
	currentTime := time.Now().UTC()

	log.Printf("Converting %d VMs to database records", len(vms))

	for i, vm := range vms {
		record := HyperVVMRecord{
			VMID:     vm.ID,
			VMName:   vm.Name,
			DeviceID: deviceID,
			State:    vm.State,
			Status:   vm.Status,
			Health:   vm.Health,
			LastSeen: currentTime,
		}

		// Parse installation date
		if vm.InstallationDate != "" {
			record.InstallationDate = &vm.InstallationDate
		}

		// Parse start time and calculate uptime
		if vm.StartTime != "" {
			record.StartTime = &vm.StartTime

			// Calculate uptime in seconds if we have start time
			if startTime, err := time.Parse(time.RFC3339, vm.StartTime); err == nil {
				uptimeSeconds := int(currentTime.Sub(startTime).Seconds())
				record.UptimeSeconds = &uptimeSeconds
			}
		}

		vmRecords = append(vmRecords, record)
		log.Printf("Processed VM %d/%d: %s (%s)", i+1, len(vms), vm.Name, vm.State)
	}

	log.Printf("Starting upsert operations for %d VM records", len(vmRecords))

	// Process each VM record
	successCount := 0
	errorCount := 0
	for i, record := range vmRecords {
		if err := upsertVMRecord(jwtToken, record); err != nil {
			log.Printf("Failed to upsert VM %s (%d/%d): %v", record.VMID, i+1, len(vmRecords), err)
			errorCount++
			// Continue with other VMs rather than failing completely
		} else {
			successCount++
		}
	}

	log.Printf("Upsert operations completed: %d successful, %d failed", successCount, errorCount)

	// Mark VMs not in current inventory as potentially deleted
	log.Printf("Marking missing VMs as stale for device %s", deviceID)
	if err := markMissingVMsAsStale(jwtToken, deviceID, vmRecords); err != nil {
		log.Printf("Failed to mark missing VMs as stale: %v", err)
		// Don't fail the entire operation for this
	} else {
		log.Printf("Successfully marked missing VMs as stale")
	}

	if errorCount > 0 {
		return fmt.Errorf("VM database update completed with %d errors out of %d operations", errorCount, len(vmRecords))
	}

	log.Printf("VM database update completed successfully for device %s", deviceID)
	return nil
}

// SAFE REPLACEMENT for upsertVMRecord function in hyperv_database.go

// upsertVMRecord inserts or updates a VM record - ENHANCED LOGGING
func upsertVMRecord(jwtToken string, record HyperVVMRecord) error {
	log.Printf("Upserting VM record: %s (%s)", record.VMName, record.VMID)

	// Check if VM already exists
	existingVM, err := getVMByIDAndDevice(jwtToken, record.VMID, record.DeviceID)
	if err != nil {
		log.Printf("Error checking existing VM %s: %v", record.VMID, err)
		// Continue with insert attempt
	}

	if existingVM != nil {
		log.Printf("VM %s exists in database, updating record (ID: %s)", record.VMName, existingVM.ID)
		// Update existing record
		return updateVMRecord(jwtToken, existingVM.ID, record)
	} else {
		log.Printf("VM %s is new, inserting record", record.VMName)
		// Insert new record
		return insertVMRecord(jwtToken, record)
	}
}

// SAFE REPLACEMENT for insertVMRecord function in hyperv_database.go

// insertVMRecord inserts a new VM record - ENHANCED LOGGING
func insertVMRecord(jwtToken string, record HyperVVMRecord) error {
	log.Printf("Inserting new VM record: %s (%s)", record.VMName, record.VMID)

	// Set timestamps for new record
	now := time.Now().UTC()
	record.FirstSeen = now
	record.LastSeen = now
	record.LastUpdated = now
	record.IsDeleted = false

	data, err := json.Marshal(record)
	if err != nil {
		log.Printf("Failed to marshal VM record for %s: %v", record.VMName, err)
		return err
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms", supabaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to create HTTP request for VM %s: %v", record.VMName, err)
		return err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("HTTP request failed for VM %s: %v", record.VMName, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to insert VM %s: HTTP %d, Body: %s", record.VMName, resp.StatusCode, string(body))
		return fmt.Errorf("failed to insert VM: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully inserted new VM record: %s (%s)", record.VMName, record.VMID)
	return nil
}

// SAFE REPLACEMENT for updateVMRecord function in hyperv_database.go

// updateVMRecord updates an existing VM record - ENHANCED LOGGING
func updateVMRecord(jwtToken, recordID string, record HyperVVMRecord) error {
	log.Printf("Updating existing VM record: %s (%s) with ID %s", record.VMName, record.VMID, recordID)

	// Prepare update data (exclude fields that shouldn't be updated)
	updateData := map[string]interface{}{
		"vm_name":    record.VMName,
		"state":      record.State,
		"status":     record.Status,
		"health":     record.Health,
		"last_seen":  record.LastSeen.Format(time.RFC3339),
		"is_deleted": false, // Mark as active again if it was deleted
	}

	// Include optional fields if they have values
	if record.InstallationDate != nil {
		updateData["installation_date"] = *record.InstallationDate
	}
	if record.StartTime != nil {
		updateData["start_time"] = *record.StartTime
	}
	if record.UptimeSeconds != nil {
		updateData["uptime_seconds"] = *record.UptimeSeconds
	}
	if record.CPUCores != nil {
		updateData["cpu_cores"] = *record.CPUCores
	}
	if record.MemoryMB != nil {
		updateData["memory_mb"] = *record.MemoryMB
	}
	if record.Generation != nil {
		updateData["generation"] = *record.Generation
	}
	if record.Version != nil {
		updateData["version"] = *record.Version
	}

	data, err := json.Marshal(updateData)
	if err != nil {
		log.Printf("Failed to marshal update data for VM %s: %v", record.VMName, err)
		return err
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms?id=eq.%s", supabaseURL, recordID)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to create HTTP request for VM update %s: %v", record.VMName, err)
		return err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("HTTP request failed for VM update %s: %v", record.VMName, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to update VM %s: HTTP %d, Body: %s", record.VMName, resp.StatusCode, string(body))
		return fmt.Errorf("failed to update VM: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully updated VM record: %s (%s)", record.VMName, record.VMID)
	return nil
}

// getVMByIDAndDevice retrieves a VM by its ID and device
func getVMByIDAndDevice(jwtToken, vmID, deviceID string) (*HyperVVMRecord, error) {
	url := fmt.Sprintf("%s/rest/v1/hyperv_vms?vm_id=eq.%s&device_id=eq.%s&is_deleted=eq.false&select=*",
		supabaseURL, vmID, deviceID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get VM: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	var vms []HyperVVMRecord
	if err := json.NewDecoder(resp.Body).Decode(&vms); err != nil {
		return nil, err
	}

	if len(vms) == 0 {
		return nil, nil // VM not found
	}

	return &vms[0], nil
}

// markMissingVMsAsStale marks VMs that weren't in the current inventory as stale
func markMissingVMsAsStale(jwtToken, deviceID string, currentVMs []HyperVVMRecord) error {
	// Get all current VM IDs
	currentVMIDs := make([]string, len(currentVMs))
	for i, vm := range currentVMs {
		currentVMIDs[i] = vm.VMID
	}

	// If no VMs, mark all as stale for this device
	var notInClause string
	if len(currentVMIDs) > 0 {
		quotedIDs := make([]string, len(currentVMIDs))
		for i, id := range currentVMIDs {
			quotedIDs[i] = fmt.Sprintf("\"%s\"", id)
		}
		notInClause = fmt.Sprintf("&vm_id=not.in.(%s)", strings.Join(quotedIDs, ","))
	}

	updateData := map[string]interface{}{
		"is_deleted": true,
		"last_seen":  time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms?device_id=eq.%s&is_deleted=eq.false%s",
		supabaseURL, deviceID, notInClause)

	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to mark missing VMs as stale: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// updateVMState updates a specific VM's state
func updateVMState(jwtToken, vmID, newState string) error {
	updateData := map[string]interface{}{
		"state":     newState,
		"last_seen": time.Now().UTC().Format(time.RFC3339),
	}

	// Update start_time if starting
	if newState == "Running" {
		updateData["start_time"] = time.Now().UTC().Format(time.RFC3339)
		updateData["uptime_seconds"] = 0
	}

	data, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms?vm_id=eq.%s&is_deleted=eq.false", supabaseURL, vmID)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update VM state: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	log.Printf("Updated VM %s state to: %s", vmID, newState)
	return nil
}

// updateVMLastSeen updates a VM's last_seen timestamp
func updateVMLastSeen(jwtToken, vmID string) error {
	updateData := map[string]interface{}{
		"last_seen": time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms?vm_id=eq.%s&is_deleted=eq.false", supabaseURL, vmID)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update VM last_seen: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// getVMsFromDatabase retrieves VMs from database for a device
func getVMsFromDatabase(jwtToken, deviceID string, includeDeleted bool) ([]HyperVVMRecord, error) {
	deletedFilter := "&is_deleted=eq.false"
	if includeDeleted {
		deletedFilter = ""
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms?device_id=eq.%s%s&select=*&order=vm_name.asc",
		supabaseURL, deviceID, deletedFilter)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get VMs from database: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	var vms []HyperVVMRecord
	if err := json.NewDecoder(resp.Body).Decode(&vms); err != nil {
		return nil, err
	}

	return vms, nil
}
