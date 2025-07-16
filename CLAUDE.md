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

# Run as service (platform-specific)
./deviceservice install  # Install service
./deviceservice start    # Start service
./deviceservice stop     # Stop service
./deviceservice remove   # Remove service
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

Key command types include:
- System information collection
- Process management
- File operations
- Screenshot capture
- Hyper-V VM management
- System shutdown/reboot

## Security Features

- JWT-based authentication with Supabase
- Input validation for all command parameters
- UUID validation for VM IDs
- Safe character validation for usernames
- Delay parameter validation for system operations
- Structured logging without sensitive data exposure

## Device Management

- **Device Registration**: Automatic registration with hostname and system info
- **Asset Collection**: Hardware and OS information gathering
- **Heartbeat**: Periodic check-ins every 6 hours
- **Command Processing**: Real-time command execution via WebSocket
- **Reconnection**: Automatic reconnection with exponential backoff

## Configuration

Core configuration is in `config.go` with Supabase connection details. The agent uses:
- Database schema: `public`
- Commands table: `commands`
- Devices table: `devices`
- WebSocket realtime channel for command delivery

## File Structure

```
├── main.go              # Main application entry point
├── app.go               # Application lifecycle management
├── command.go           # Main command execution dispatcher
├── config.go            # Configuration constants
├── service.go           # Service management
├── device_assets.go     # System information collection
├── hyperv.go            # Hyper-V management
├── screen_capture*.go   # Screen capture implementations
├── service_*.go         # Platform-specific service code
├── validation.go        # Input validation functions
├── result.go            # CommandResult constructors
├── system_info.go       # Basic system information functions
├── storage.go           # Disk space management functions
├── build/               # Cross-compiled binaries
└── versioninfo.json     # Windows executable metadata
```

## Development Notes

- The project follows Go conventions with package-level functions
- Cross-platform compatibility is handled through build tags and separate implementations
- WebSocket connection includes Phoenix framework heartbeat protocol
- Command results use structured JSON with separate result/logs fields
- Device ID persistence uses platform-appropriate system directories