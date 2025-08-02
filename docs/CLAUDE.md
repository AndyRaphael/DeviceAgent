# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Go-based RMM (Remote Monitoring and Management) device agent that connects to a Supabase backend. The agent registers devices, maintains heartbeat connections, and executes remote commands via WebSocket realtime connections.

## Architecture

### Core Components

- **main.go**: Entry point with WebSocket connection management, device registration, and command execution
- **app.go**: Application lifecycle management with graceful shutdown and reconnection logic
- **command.go**: Main command execution dispatcher (reduced from ~26k lines through refactoring)
- **config.go**: Supabase configuration and connection parameters
- **service.go**: Cross-platform service installation and management
- **device_assets.go**: Hardware and system information collection
- **hyperv.go**: Hyper-V virtual machine management functionality
- **hyperv_database.go**: Hyper-V database persistence and synchronization
- **screen_capture.go**: Screen capture functionality with platform-specific implementations

### Refactored Function Files

- **validation.go**: Input validation functions (validateVMID, validateUsername, etc.)
- **result.go**: CommandResult constructor functions and methods
- **system_info.go**: Basic system information functions (hostname, whoami, uptime, etc.)
- **storage.go**: Disk space and storage management functions

### Platform-Specific Files

- **service_windows.go**: Windows service implementation
- **service_unix.go**: Unix/Linux service implementation  
- **screen_capture_wts.go**: Windows Terminal Services screen capture
- **screen_capture_stub.go**: Stub implementation for unsupported platforms

### Documentation

- **docs/**: Comprehensive documentation directory
  - **docs/hyperv.md**: Complete Hyper-V management documentation

## Build and Development

### Building the Agent

```bash
# Build for current platform
go build -o deviceservice

# Cross-compile for different platforms (examples)
GOOS=windows GOARCH=amd64 go build -o build/windows-amd64/DeviceAgent.exe
GOOS=linux GOARCH=amd64 go build -o build/linux-amd64/deviceservice
GOOS=darwin GOARCH=amd64 go build -o build/darwin-amd64/deviceservice
```

### Running the Agent

```bash
# Run directly
go run .

# Available command line arguments:
./deviceservice run            # Run the application normally
./deviceservice service        # Run as service (handles Windows SCM)
./deviceservice capture-screen # Helper mode for screen capture
```

### Dependencies

The project uses standard Go modules with these key dependencies:
- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `github.com/google/uuid` - UUID generation
- `github.com/gorilla/websocket` - WebSocket client
- `golang.org/x/sys` - System calls
- `golang.org/x/image` - Image processing for screenshots

## Command System

The agent implements a comprehensive command execution system with:

- **Input validation**: Prevents injection attacks through parameter validation
- **Security controls**: Built-in safeguards for sensitive operations
- **Platform support**: Cross-platform command execution
- **Error handling**: Structured error reporting and logging

### Command Categories

#### System Commands
- System information collection
- Process management
- File operations
- Screenshot capture
- System shutdown/reboot

#### Hyper-V Commands
- **Inventory Management**: `hyperv_inventory`, `hyperv_inventory_db`, `hyperv_get_vms`, `hyperv_sync`
- **VM Control**: `hyperv_start`, `hyperv_pause`, `hyperv_reset`, `hyperv_turnoff`, `hyperv_shutdown`
- **VM Monitoring**: `hyperv_screenshot` with security validation

#### Hyper-V Data Collection
The Hyper-V system collects comprehensive VM information including:
- **Hardware Configuration**: Processor count, memory allocation, hard drives
- **Guest Operating System**: OS name, version, architecture, family
- **Network Information**: IP addresses, subnets for running VMs
- **Performance Metrics**: CPU and memory usage percentages
- **Security Features**: TPM, Secure Boot, Enhanced Session Transport
- **Backup & Replication**: Status, health, mode, frequency
- **Timestamps**: Creation time, last boot, last shutdown

## Security Features

- JWT-based authentication with Supabase
- Input validation for all command parameters
- UUID validation for VM IDs
- Safe character validation for usernames
- Delay parameter validation for system operations
- Structured logging without sensitive data exposure
- PowerShell input sanitization for Hyper-V operations
- Comprehensive VM ID validation and sanitization

## Device Management

- **Device Registration**: Automatic registration with hostname and system info
- **Asset Collection**: Hardware and OS information gathering
- **Heartbeat**: Periodic check-ins every 6 hours
- **Command Processing**: Real-time command execution via WebSocket
- **Reconnection**: Automatic reconnection with exponential backoff

## Database Integration

### Hyper-V Database Schema
The system maintains a comprehensive `hyperv_vms` table with:
- **Basic Information**: VM ID, name, state, status, health, uptime
- **Hardware Configuration**: Processor count, memory, hard drives, dynamic memory
- **Guest OS Details**: Operating system information and architecture
- **Network Information**: IP addresses and subnet data (JSONB)
- **Security Features**: TPM, Secure Boot, checkpoint settings
- **Performance Metrics**: CPU and memory usage percentages
- **Backup & Replication**: Comprehensive status tracking
- **Audit Trail**: First seen, last seen, last updated timestamps

### Database Operations
- **Upsert Logic**: Intelligent insert/update operations
- **Soft Delete**: Mark missing VMs as deleted
- **Error Handling**: Graceful handling of database failures
- **Batch Processing**: Efficient processing of multiple VMs

## Configuration

Core configuration is in `config.go` with Supabase connection details. The agent uses:
- Database schema: `public`
- Commands table: `commands`
- Devices table: `devices`
- Hyper-V VMs table: `hyperv_vms`
- WebSocket realtime channel for command delivery

## File Structure

```
├── main.go              # Main application entry point
├── app.go               # Application lifecycle management
├── command.go           # Main command execution dispatcher
├── config.go            # Configuration constants
├── service.go           # Service management
├── device_assets.go     # System information collection
├── hyperv.go            # Hyper-V management operations
├── hyperv_database.go   # Hyper-V database persistence
├── screen_capture*.go   # Screen capture implementations
├── service_*.go         # Platform-specific service code
├── validation.go        # Input validation functions
├── result.go            # CommandResult constructors
├── system_info.go       # Basic system information functions
├── storage.go           # Disk space management functions
├── docs/                # Documentation directory
│   └── hyperv.md       # Comprehensive Hyper-V documentation
├── build/               # Cross-compiled binaries
└── versioninfo.json     # Windows executable metadata
```

## Hyper-V Management

### Platform Support
- **Windows Only**: Hyper-V commands are Windows-specific
- **Requirements**: Hyper-V role installed and enabled
- **Privileges**: Administrative access required for VM operations
- **PowerShell**: Requires PowerShell with Hyper-V cmdlets

### Key Features
- **Comprehensive Inventory**: 29+ data fields per VM
- **Real-time Control**: Start, stop, pause, reset operations
- **Screenshot Capture**: Secure VM screen capture with validation
- **Database Persistence**: Full audit trail and history tracking
- **Performance Monitoring**: CPU and memory usage tracking
- **Security Validation**: Input sanitization and injection prevention

### Data Collection Capabilities
- **Hardware Information**: Processors, memory, storage devices
- **Guest OS Details**: Operating system and version information
- **Network Configuration**: IP addresses and network interfaces
- **Security Status**: TPM, Secure Boot, checkpoint settings
- **Performance Metrics**: Resource usage and utilization
- **Backup & Replication**: Status and configuration details

## Development Notes

- The project follows Go conventions with package-level functions
- Cross-platform compatibility is handled through build tags and separate implementations
- WebSocket connection includes Phoenix framework heartbeat protocol
- Command results use structured JSON with separate result/logs fields
- Device ID persistence uses platform-appropriate system directories
- Hyper-V functionality includes comprehensive error handling and security validation
- Database operations implement intelligent upsert logic with audit trails
- PowerShell integration uses enhanced scripts for comprehensive data collection