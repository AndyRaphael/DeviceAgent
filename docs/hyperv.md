# Hyper-V Management Documentation

## Overview

The Hyper-V management system provides comprehensive virtual machine inventory, monitoring, and control capabilities for Windows Hyper-V environments. The system consists of two main components:

- **hyperv.go**: Core Hyper-V operations and PowerShell integration
- **hyperv_database.go**: Database persistence and synchronization

## Architecture

### Core Components

#### HyperVVM Struct
The primary data structure representing a Hyper-V virtual machine with comprehensive hardware and system information:

```go
type HyperVVM struct {
    // Basic Information
    ID         string  `json:"id"`
    Name       string  `json:"name"`
    State      string  `json:"state"`
    Status     string  `json:"status"`
    Health     string  `json:"health"`
    Uptime     string  `json:"uptime"`
    
    // Hardware Configuration
    Generation                      *int        `json:"generation,omitempty"`
    Version                         *string     `json:"version,omitempty"`
    ProcessorCount                  *int        `json:"processor_count,omitempty"`
    MemoryAssignedMB                *int        `json:"memory_assigned_mb,omitempty"`
    HardDrives                      interface{} `json:"hard_drives,omitempty"`
    DynamicMemoryEnabled            *bool       `json:"dynamic_memory_enabled,omitempty"`
    
    // Session & Services
    EnhancedSessionTransportType    *string     `json:"enhanced_session_transport_type,omitempty"`
    GuestServiceInterfaceEnabled    *bool       `json:"guest_service_interface_enabled,omitempty"`
    
    // Guest Operating System
    GuestOperatingSystem            *string     `json:"guest_operating_system,omitempty"`
    GuestOperatingSystemVersion     *string     `json:"guest_operating_system_version,omitempty"`
    GuestOperatingSystemArchitecture *string    `json:"guest_operating_system_architecture,omitempty"`
    GuestOperatingSystemFamily      *string     `json:"guest_operating_system_family,omitempty"`
    
    // Timestamps
    CreationTime                    *string     `json:"creation_time,omitempty"`
    LastBootTime                    *string     `json:"last_boot_time,omitempty"`
    LastShutdownTime                *string     `json:"last_shutdown_time,omitempty"`
    
    // Network Information
    GuestInterfaceAddresses         interface{} `json:"guest_interface_addresses,omitempty"`
    GuestInterfaceSubnets           interface{} `json:"guest_interface_subnets,omitempty"`
    
    // Security Features
    TrustedPlatformModule           *bool       `json:"trusted_platform_module,omitempty"`
    SecureBoot                      *bool       `json:"secure_boot,omitempty"`
    AutomaticCheckpointsEnabled     *bool       `json:"automatic_checkpoints_enabled,omitempty"`
    
    // Status & Health
    OperationalStatus               interface{} `json:"operational_status,omitempty"`
    HealthStatus                    *string     `json:"health_status,omitempty"`
    CompatibilityVersion            *string     `json:"compatibility_version,omitempty"`
    
    // Replication
    ReplicationState                *string     `json:"replication_state,omitempty"`
    ReplicationHealth               *string     `json:"replication_health,omitempty"`
    ReplicationMode                 *string     `json:"replication_mode,omitempty"`
    ReplicationRelationshipType     *string     `json:"replication_relationship_type,omitempty"`
    ReplicationFrequencySec         *int        `json:"replication_frequency_sec,omitempty"`
    
    // Backup
    BackupEnabled                   *bool       `json:"backup_enabled,omitempty"`
    BackupState                     *string     `json:"backup_state,omitempty"`
    
    // Performance Metrics
    CPUUsagePercent                 *float64    `json:"cpu_usage_percent,omitempty"`
    MemoryUsagePercent              *float64    `json:"memory_usage_percent,omitempty"`
}
```

## Commands

### 1. Hyper-V Inventory Commands

#### `hyperv_inventory`
- **Purpose**: Collects basic VM inventory without database persistence
- **Function**: `executeHyperVInventory()`
- **Returns**: Live PowerShell data only
- **Use Case**: Quick inventory check without database overhead

#### `hyperv_inventory_db`
- **Purpose**: Collects comprehensive VM inventory and updates database
- **Function**: `executeHyperVInventoryWithDB(jwtToken string)`
- **Returns**: Enhanced data with database synchronization
- **Use Case**: Full inventory management with persistence

#### `hyperv_get_vms`
- **Purpose**: Retrieves VMs from database (fast query)
- **Function**: `executeHyperVGetVMsFromDB(jwtToken string)`
- **Returns**: Database-stored VM data
- **Use Case**: Quick retrieval of previously collected data

#### `hyperv_sync`
- **Purpose**: Full sync with PowerShell then returns updated database data
- **Function**: `executeHyperVSyncAndGet(jwtToken string)`
- **Returns**: Fresh data after database synchronization
- **Use Case**: Complete inventory refresh with database update

### 2. VM Control Commands

#### `hyperv_start`
- **Purpose**: Starts a virtual machine
- **Function**: `executeHyperVStart(params map[string]interface{})`
- **Parameters**: `{"vm_id": "vm-uuid"}`
- **Security**: Input validation and sanitization

#### `hyperv_pause`
- **Purpose**: Pauses/suspends a virtual machine
- **Function**: `executeHyperVPause(params map[string]interface{})`
- **Parameters**: `{"vm_id": "vm-uuid"}`

#### `hyperv_reset`
- **Purpose**: Hard resets a virtual machine
- **Function**: `executeHyperVReset(params map[string]interface{})`
- **Parameters**: `{"vm_id": "vm-uuid"}`

#### `hyperv_turnoff`
- **Purpose**: Force stops a virtual machine
- **Function**: `executeHyperVTurnOff(params map[string]interface{})`
- **Parameters**: `{"vm_id": "vm-uuid"}`

#### `hyperv_shutdown`
- **Purpose**: Gracefully shuts down a virtual machine
- **Function**: `executeHyperVShutdown(params map[string]interface{})`
- **Parameters**: `{"vm_id": "vm-uuid"}`

### 3. VM Monitoring Commands

#### `hyperv_screenshot`
- **Purpose**: Captures VM screen with security validation
- **Function**: `executeHyperVScreenshot(params map[string]interface{})`
- **Parameters**: `{"vm_id": "vm-uuid"}`
- **Returns**: Base64-encoded JPEG image
- **Security**: Comprehensive input validation and sanitization

## Data Collection

### PowerShell Integration

The system uses enhanced PowerShell scripts to collect comprehensive VM information:

#### Hardware Information
- **Processor Count**: Number of virtual CPUs
- **Memory Assigned**: Currently assigned memory in MB
- **Hard Drives**: Array of virtual hard disk information including:
  - Path
  - Controller type
  - Controller number and location
  - Size (if available)

#### Guest Operating System
- **OS Name**: Guest operating system name
- **OS Version**: Guest OS version
- **OS Architecture**: Guest OS architecture (x86, x64, ARM64)
- **OS Family**: Guest OS family (Windows, Linux, etc.)

#### Network Information
- **IP Addresses**: Guest interface IP addresses (for running VMs)
- **Subnets**: Guest interface subnet information

#### Performance Metrics
- **CPU Usage**: Current CPU usage percentage
- **Memory Usage**: Current memory usage percentage
- **Resource Metering**: Enhanced performance data collection

#### Security Features
- **Trusted Platform Module**: TPM status
- **Secure Boot**: Secure boot status
- **Enhanced Session Transport**: Session transport type

#### Backup & Replication
- **Backup Status**: Backup enabled/disabled and current state
- **Replication State**: Replication status, health, mode, and frequency

### Database Schema

The `hyperv_vms` table stores comprehensive VM information:

```sql
CREATE TABLE public.hyperv_vms (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    vm_id character varying(36) NOT NULL,
    vm_name character varying(255) NOT NULL,
    device_id uuid NOT NULL,
    
    -- Basic Information
    state character varying(50) NULL,
    status character varying(50) NULL,
    health character varying(50) NULL,
    uptime character varying NULL,
    generation integer NULL,
    version character varying(10) NULL,
    
    -- Hardware Configuration
    processor_count integer NULL,
    memory_assigned_mb integer NULL,
    hard_drives jsonb NULL,
    dynamic_memory_enabled boolean NULL,
    
    -- Session & Services
    enhanced_session_transport_type character varying(50) NULL,
    guest_service_interface_enabled boolean NULL,
    
    -- Guest Operating System
    guest_operating_system character varying(100) NULL,
    guest_operating_system_version character varying(100) NULL,
    guest_operating_system_architecture character varying(50) NULL,
    guest_operating_system_family character varying(50) NULL,
    
    -- Timestamps
    creation_time timestamp with time zone NULL,
    last_boot_time timestamp with time zone NULL,
    last_shutdown_time timestamp with time zone NULL,
    
    -- Network Information
    guest_interface_addresses jsonb NULL,
    guest_interface_subnets jsonb NULL,
    
    -- Security Features
    trusted_platform_module boolean NULL,
    secure_boot boolean NULL,
    automatic_checkpoints_enabled boolean NULL,
    
    -- Status & Health
    operational_status jsonb NULL,
    health_status character varying(50) NULL,
    compatibility_version character varying(20) NULL,
    
    -- Replication
    replication_state character varying(50) NULL,
    replication_health character varying(50) NULL,
    replication_mode character varying(50) NULL,
    replication_relationship_type character varying(50) NULL,
    replication_frequency_sec integer NULL,
    
    -- Backup
    backup_enabled boolean NULL,
    backup_state character varying(50) NULL,
    
    -- Performance Metrics
    cpu_usage_percent numeric(5,2) NULL,
    memory_usage_percent numeric(5,2) NULL,
    
    -- Audit Trail
    first_seen timestamp with time zone NULL DEFAULT now(),
    last_seen timestamp with time zone NULL DEFAULT now(),
    last_updated timestamp with time zone NULL DEFAULT now(),
    is_deleted boolean NULL DEFAULT false,
    
    -- Constraints
    CONSTRAINT hyperv_vms_pkey PRIMARY KEY (id),
    CONSTRAINT hyperv_vms_vm_id_device_id_key UNIQUE (vm_id, device_id),
    CONSTRAINT hyperv_vms_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
);
```

## Database Operations

### Upsert Logic
The system implements intelligent upsert operations:

1. **Check Existing**: Query database for existing VM by `vm_id` and `device_id`
2. **Update or Insert**: Update existing records or insert new ones
3. **Soft Delete**: Mark VMs not in current inventory as deleted
4. **Audit Trail**: Track first seen, last seen, and last updated timestamps

### Key Functions

#### `updateVMDatabase(jwtToken, deviceID string, vms []HyperVVM)`
- Converts PowerShell VM data to database records
- Maps all enhanced fields from HyperVVM to HyperVVMRecord
- Processes each VM with error handling
- Marks missing VMs as stale

#### `upsertVMRecord(jwtToken string, record HyperVVMRecord)`
- Checks if VM already exists in database
- Calls appropriate insert or update function
- Handles all new fields with proper validation

#### `updateVMRecord(jwtToken, recordID string, record HyperVVMRecord)`
- Updates existing VM records with all enhanced fields
- Includes optional field handling
- Maintains audit trail

#### `insertVMRecord(jwtToken string, record HyperVVMRecord)`
- Inserts new VM records with all enhanced fields
- Sets proper timestamps for new records
- Handles JSONB fields for complex data

## Security Features

### Input Validation
- **VM ID Validation**: UUID format validation to prevent injection
- **Parameter Sanitization**: PowerShell input sanitization
- **Error Handling**: Comprehensive error handling without sensitive data exposure

### Command Security
- **Platform Validation**: Windows-only operation enforcement
- **Hyper-V Availability Check**: Verifies Hyper-V is available and enabled
- **Graceful Error Handling**: Structured error reporting

### Screenshot Security
- **Input Sanitization**: VM ID and name sanitization
- **WMI Validation**: VM existence verification before capture
- **Secure Image Processing**: Safe image handling and compression

## Performance Considerations

### PowerShell Optimization
- **Single Script Execution**: Efficient PowerShell script design
- **Error Suppression**: Silent error handling for optional features
- **Depth Control**: JSON depth control for complex objects

### Database Optimization
- **Indexed Queries**: Optimized database queries with proper indexing
- **Batch Operations**: Efficient batch processing of VM records
- **Connection Management**: Proper HTTP client management

### Memory Management
- **JSON Depth Control**: Controlled JSON serialization depth
- **Resource Cleanup**: Proper cleanup of PowerShell objects
- **Error Recovery**: Graceful handling of memory-intensive operations

## Error Handling

### PowerShell Errors
- **Command Not Found**: Graceful handling of missing PowerShell cmdlets
- **Permission Errors**: Proper error reporting for insufficient permissions
- **VM State Errors**: Handling of VMs in unexpected states

### Database Errors
- **Connection Failures**: Retry logic for database connectivity issues
- **Constraint Violations**: Proper handling of unique constraint violations
- **Data Type Errors**: Validation of data types before database operations

### Network Errors
- **Guest Network Access**: Handling of network interface access failures
- **IP Address Collection**: Graceful handling of network information collection
- **Performance Metrics**: Error handling for resource metering failures

## Monitoring and Logging

### Debug Logging
- **Field Mapping**: Detailed logging of field mapping operations
- **Database Operations**: Logging of successful and failed database operations
- **Performance Metrics**: Logging of CPU and memory usage collection

### Error Logging
- **Structured Errors**: Consistent error message formatting
- **Context Information**: Error context without sensitive data exposure
- **Recovery Information**: Logging of recovery attempts and results

## Platform Support

### Windows Requirements
- **Hyper-V Role**: Requires Hyper-V role to be installed and enabled
- **PowerShell**: Requires PowerShell with Hyper-V cmdlets
- **Administrative Privileges**: Requires administrative access for VM operations

### Version Compatibility
- **Windows Server**: Supports Windows Server 2012 R2 and later
- **Windows Client**: Supports Windows 10/11 with Hyper-V feature
- **PowerShell Version**: Compatible with PowerShell 5.1 and later

## Usage Examples

### Basic Inventory Collection
```json
{
    "command": "hyperv_inventory_db"
}
```

### VM Control Operations
```json
{
    "command": "hyperv_start",
    "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789012\"}"
}
```

### Screenshot Capture
```json
{
    "command": "hyperv_screenshot",
    "parameters": "{\"vm_id\": \"12345678-1234-1234-1234-123456789012\"}"
}
```

### Database Retrieval
```json
{
    "command": "hyperv_get_vms"
}
```

## Troubleshooting

### Common Issues

#### Hyper-V Not Available
- **Symptom**: "Hyper-V is not available or enabled on this system"
- **Solution**: Install and enable Hyper-V role/feature

#### PowerShell Execution Errors
- **Symptom**: PowerShell command execution failures
- **Solution**: Verify PowerShell execution policy and administrative privileges

#### Database Connection Issues
- **Symptom**: Database update failures
- **Solution**: Verify JWT token validity and network connectivity

#### Screenshot Capture Failures
- **Symptom**: Screenshot capture errors
- **Solution**: Verify VM is running and has proper video configuration

### Debug Information
- **Logs**: Check application logs for detailed error information
- **Database**: Verify database schema and constraints
- **PowerShell**: Test PowerShell commands manually for validation 