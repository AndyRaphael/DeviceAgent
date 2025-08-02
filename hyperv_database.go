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
	ID                           string      `json:"id,omitempty"`
	VMID                         string      `json:"vm_id"`
	VMName                       string      `json:"vm_name"`
	DeviceID                     string      `json:"device_id"`
	State                        string      `json:"state"`
	Status                       string      `json:"status"`
	Health                       string      `json:"health"`
	Uptime                       string      `json:"uptime"`
	Generation                   *int        `json:"generation,omitempty"`
	Version                      *string     `json:"version,omitempty"`
	ProcessorCount               *int        `json:"processor_count,omitempty"`
	MemoryAssignedMB             *int        `json:"memory_assigned_mb,omitempty"`
	HardDrives                   interface{} `json:"hard_drives,omitempty"`
	DynamicMemoryEnabled         *bool       `json:"dynamic_memory_enabled,omitempty"`
	EnhancedSessionTransportType *string     `json:"enhanced_session_transport_type,omitempty"`
	GuestServiceInterfaceEnabled *bool       `json:"guest_service_interface_enabled,omitempty"`
	CreationTime                 *string     `json:"creation_time,omitempty"`
	GuestInterfaceAddresses      interface{} `json:"guest_interface_addresses,omitempty"`
	TrustedPlatformModule        *bool       `json:"trusted_platform_module,omitempty"`
	SecureBoot                   *bool       `json:"secure_boot,omitempty"`
	AutomaticCheckpointsEnabled  *bool       `json:"automatic_checkpoints_enabled,omitempty"`
	OperationalStatus            interface{} `json:"operational_status,omitempty"`
	ReplicationState             *string     `json:"replication_state,omitempty"`
	ReplicationHealth            *string     `json:"replication_health,omitempty"`
	ReplicationMode              *string     `json:"replication_mode,omitempty"`
	FirstSeen                    time.Time   `json:"first_seen"`
	LastSeen                     time.Time   `json:"last_seen"`
	LastUpdated                  time.Time   `json:"last_updated"`
	IsDeleted                    bool        `json:"is_deleted"`
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
			VMID:                         vm.ID,
			VMName:                       vm.Name,
			DeviceID:                     deviceID,
			State:                        vm.State,
			Status:                       vm.Status,
			Health:                       vm.Health,
			Uptime:                       vm.Uptime,
			LastSeen:                     currentTime,
			Generation:                   vm.Generation,
			Version:                      vm.Version,
			ProcessorCount:               vm.ProcessorCount,
			MemoryAssignedMB:             vm.MemoryAssignedMB,
			HardDrives:                   vm.HardDrives,
			DynamicMemoryEnabled:         vm.DynamicMemoryEnabled,
			EnhancedSessionTransportType: vm.EnhancedSessionTransportType,
			GuestServiceInterfaceEnabled: vm.GuestServiceInterfaceEnabled,
			CreationTime:                 vm.CreationTime,
			GuestInterfaceAddresses:      vm.GuestInterfaceAddresses,
			TrustedPlatformModule:        vm.TrustedPlatformModule,
			SecureBoot:                   vm.SecureBoot,
			AutomaticCheckpointsEnabled:  vm.AutomaticCheckpointsEnabled,
			OperationalStatus:            vm.OperationalStatus,
			ReplicationState:             vm.ReplicationState,
			ReplicationHealth:            vm.ReplicationHealth,
			ReplicationMode:              vm.ReplicationMode,
		}

		// Debug logging for key fields
		log.Printf("VM %s: generation=%v, version=%v, processor_count=%v, memory_assigned_mb=%v",
			vm.Name, record.Generation, record.Version, record.ProcessorCount, record.MemoryAssignedMB)
		log.Printf("VM %s: dynamic_memory=%v",
			vm.Name, record.DynamicMemoryEnabled)

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
	if record.ProcessorCount != nil {
		updateData["processor_count"] = *record.ProcessorCount
	}
	if record.MemoryAssignedMB != nil {
		updateData["memory_assigned_mb"] = *record.MemoryAssignedMB
	}
	if record.HardDrives != nil {
		updateData["hard_drives"] = record.HardDrives
	}
	if record.DynamicMemoryEnabled != nil {
		updateData["dynamic_memory_enabled"] = *record.DynamicMemoryEnabled
	}
	if record.EnhancedSessionTransportType != nil {
		updateData["enhanced_session_transport_type"] = *record.EnhancedSessionTransportType
	}
	if record.GuestServiceInterfaceEnabled != nil {
		updateData["guest_service_interface_enabled"] = *record.GuestServiceInterfaceEnabled
	}
	if record.CreationTime != nil {
		updateData["creation_time"] = *record.CreationTime
	}
	if record.GuestInterfaceAddresses != nil {
		updateData["guest_interface_addresses"] = record.GuestInterfaceAddresses
	}
	if record.TrustedPlatformModule != nil {
		updateData["trusted_platform_module"] = *record.TrustedPlatformModule
	}
	if record.SecureBoot != nil {
		updateData["secure_boot"] = *record.SecureBoot
	}
	if record.AutomaticCheckpointsEnabled != nil {
		updateData["automatic_checkpoints_enabled"] = *record.AutomaticCheckpointsEnabled
	}
	if record.OperationalStatus != nil {
		updateData["operational_status"] = record.OperationalStatus
	}
	if record.ReplicationState != nil {
		updateData["replication_state"] = *record.ReplicationState
	}
	if record.ReplicationHealth != nil {
		updateData["replication_health"] = *record.ReplicationHealth
	}
	if record.ReplicationMode != nil {
		updateData["replication_mode"] = *record.ReplicationMode
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

	// Create a clean record for insertion (remove the ID field)
	insertRecord := map[string]interface{}{
		"vm_id":        record.VMID,
		"vm_name":      record.VMName,
		"device_id":    record.DeviceID,
		"state":        record.State,
		"status":       record.Status,
		"health":       record.Health,
		"uptime":       record.Uptime,
		"first_seen":   record.FirstSeen.Format(time.RFC3339),
		"last_seen":    record.LastSeen.Format(time.RFC3339),
		"last_updated": record.LastUpdated.Format(time.RFC3339),
		"is_deleted":   record.IsDeleted,
	}

	// Add optional fields if they have values
	if record.Generation != nil {
		insertRecord["generation"] = *record.Generation
	}
	if record.Version != nil {
		insertRecord["version"] = *record.Version
	}
	if record.ProcessorCount != nil {
		insertRecord["processor_count"] = *record.ProcessorCount
	}
	if record.MemoryAssignedMB != nil {
		insertRecord["memory_assigned_mb"] = *record.MemoryAssignedMB
	}
	if record.HardDrives != nil {
		insertRecord["hard_drives"] = record.HardDrives
	}
	if record.DynamicMemoryEnabled != nil {
		insertRecord["dynamic_memory_enabled"] = *record.DynamicMemoryEnabled
	}
	if record.EnhancedSessionTransportType != nil {
		insertRecord["enhanced_session_transport_type"] = *record.EnhancedSessionTransportType
	}
	if record.GuestServiceInterfaceEnabled != nil {
		insertRecord["guest_service_interface_enabled"] = *record.GuestServiceInterfaceEnabled
	}
	if record.CreationTime != nil {
		insertRecord["creation_time"] = *record.CreationTime
	}
	if record.GuestInterfaceAddresses != nil {
		insertRecord["guest_interface_addresses"] = record.GuestInterfaceAddresses
	}
	if record.TrustedPlatformModule != nil {
		insertRecord["trusted_platform_module"] = *record.TrustedPlatformModule
	}
	if record.SecureBoot != nil {
		insertRecord["secure_boot"] = *record.SecureBoot
	}
	if record.AutomaticCheckpointsEnabled != nil {
		insertRecord["automatic_checkpoints_enabled"] = *record.AutomaticCheckpointsEnabled
	}
	if record.OperationalStatus != nil {
		insertRecord["operational_status"] = record.OperationalStatus
	}
	if record.ReplicationState != nil {
		insertRecord["replication_state"] = *record.ReplicationState
	}
	if record.ReplicationHealth != nil {
		insertRecord["replication_health"] = *record.ReplicationHealth
	}
	if record.ReplicationMode != nil {
		insertRecord["replication_mode"] = *record.ReplicationMode
	}

	data, err := json.Marshal(insertRecord)
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
