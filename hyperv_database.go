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
	ID          string    `json:"id,omitempty"`
	VMID        string    `json:"vm_id"`
	VMName      string    `json:"vm_name"`
	DeviceID    string    `json:"device_id"`
	State       string    `json:"state"`
	Status      string    `json:"status"`
	Health      string    `json:"health"`
	Uptime      string    `json:"uptime"`
	Generation  *int      `json:"generation,omitempty"`
	Version     *string   `json:"version,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	LastUpdated time.Time `json:"last_updated"`
	IsDeleted   bool      `json:"is_deleted"`
}

// SAFE REPLACEMENT for updateVMDatabase function in hyperv_database.go

// Enhanced updateVMDatabase function to properly map all VM properties
func updateVMDatabase(jwtToken, deviceID string, vms []HyperVVM) error {
	log.Printf("Updating VM database for device %s with %d VMs (enhanced)", deviceID, len(vms))

	// Convert VMs to database records with enhanced mapping
	var vmRecords []HyperVVMRecord
	currentTime := time.Now().UTC()

	for _, vm := range vms {
		record := HyperVVMRecord{
			VMID:     vm.ID,
			VMName:   vm.Name,
			DeviceID: deviceID,
			State:    vm.State,
			Status:   vm.Status,
			Health:   vm.Health,
			Uptime:   vm.Uptime,
			LastSeen: currentTime,
		}

		// Set generation
		if vm.Generation != nil && *vm.Generation > 0 {
			record.Generation = vm.Generation
			log.Printf("VM %s: generation set to %d", vm.Name, *vm.Generation)
		} else {
			log.Printf("VM %s: generation not available", vm.Name)
		}

		// Set version
		if vm.Version != nil && *vm.Version != "" {
			record.Version = vm.Version
			log.Printf("VM %s: version set to %s", vm.Name, *vm.Version)
		} else {
			log.Printf("VM %s: version not available", vm.Name)
		}

		// Debug Uptime
		log.Printf("VM %s: uptime set to '%s'", vm.Name, record.Uptime)

		vmRecords = append(vmRecords, record)
	}

	// Process each VM record with enhanced error handling
	successCount := 0
	errorCount := 0
	for _, record := range vmRecords {
		if err := upsertVMRecord(jwtToken, record); err != nil {
			log.Printf("Failed to upsert VM %s (%s): %v", record.VMName, record.VMID, err)
			errorCount++
		} else {
			successCount++
		}
	}

	log.Printf("VM upsert results: %d successful, %d failed", successCount, errorCount)

	// Mark VMs not in current inventory as potentially deleted
	if err := markMissingVMsAsStale(jwtToken, deviceID, vmRecords); err != nil {
		log.Printf("Failed to mark missing VMs as stale: %v", err)
	}

	log.Printf("Enhanced VM database update completed for device %s", deviceID)

	// Return error only if all operations failed
	if errorCount > 0 && successCount == 0 {
		return fmt.Errorf("all VM database operations failed")
	}

	return nil
}

// upsertVMRecord inserts or updates a VM record
func upsertVMRecord(jwtToken string, record HyperVVMRecord) error {
	// Check if VM already exists
	existingVM, err := getVMByIDAndDevice(jwtToken, record.VMID, record.DeviceID)
	if err != nil {
		log.Printf("Error checking existing VM: %v", err)
	}

	if existingVM != nil {
		// Update existing record
		return updateVMRecord(jwtToken, existingVM.ID, record)
	} else {
		// Insert new record
		return insertVMRecord(jwtToken, record)
	}
}

// Enhanced updateVMRecord to handle all the new fields properly
func updateVMRecord(jwtToken, recordID string, record HyperVVMRecord) error {
	// Prepare update data with all enhanced fields
	updateData := map[string]interface{}{
		"vm_name":      record.VMName,
		"state":        record.State,
		"status":       record.Status,
		"health":       record.Health,
		"last_seen":    record.LastSeen.Format(time.RFC3339),
		"last_updated": time.Now().UTC().Format(time.RFC3339),
		"is_deleted":   false, // Mark as active again if it was deleted
	}

	// Include optional fields if they have values
	if record.Uptime != "" {
		updateData["uptime"] = record.Uptime
	}
	if record.Generation != nil {
		updateData["generation"] = *record.Generation
	}
	if record.Version != nil {
		updateData["version"] = *record.Version
	}

	data, err := json.Marshal(updateData)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms?id=eq.%s", supabaseURL, recordID)
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
		return fmt.Errorf("failed to update VM: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	log.Printf("Enhanced update completed for VM: %s (%s)", record.VMName, record.VMID)
	return nil
}

// SAFE REPLACEMENT for insertVMRecord function in hyperv_database.go

// Enhanced insertVMRecord for new VM records
func insertVMRecord(jwtToken string, record HyperVVMRecord) error {
	// Set timestamps for new record
	now := time.Now().UTC()
	record.FirstSeen = now
	record.LastSeen = now
	record.LastUpdated = now
	record.IsDeleted = false

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/rest/v1/hyperv_vms", supabaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("apikey", supabaseAPIKey)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to insert VM: HTTP %d, Body: %s", resp.StatusCode, string(body))
	}

	log.Printf("Enhanced insert completed for new VM: %s (%s)", record.VMName, record.VMID)
	return nil
}

// SAFE REPLACEMENT for updateVMRecord function in hyperv_database.go

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
