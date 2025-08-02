# Installation and Service Management

## Overview

This document covers the installation, configuration, and service management of the RMM Device Agent across different platforms and deployment scenarios.

## Platform Support

### Windows
- **Service Installation**: Full Windows service support with automatic startup
- **Service Management**: Install, uninstall, start, stop, and configure
- **Failure Recovery**: Automatic restart on service failures
- **Event Logging**: Integration with Windows Event Logs

### Linux/macOS
- **Systemd Service**: Linux systemd service support
- **LaunchDaemon**: macOS LaunchDaemon support
- **Manual Installation**: Command-line installation and management

## Installation Methods

### Method 1: Manual Installation

#### Windows
```bash
# Download the latest release
# Extract to C:\Program Files\DeviceAgent\

# Install as Windows service (run as Administrator)
DeviceAgent.exe install

# Verify installation
Get-Service -Name "DeviceAgent"
```

#### Linux
```bash
# Download the latest release
sudo wget https://github.com/your-repo/releases/latest/download/deviceservice-linux-amd64 -O /usr/local/bin/deviceservice
sudo chmod +x /usr/local/bin/deviceservice

# Create systemd service file
sudo tee /etc/systemd/system/deviceagent.service > /dev/null <<EOF
[Unit]
Description=RMM Device Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/deviceservice service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable deviceagent
sudo systemctl start deviceagent
```

#### macOS
```bash
# Download the latest release
sudo curl -L https://github.com/your-repo/releases/latest/download/deviceservice-darwin-amd64 -o /usr/local/bin/deviceservice
sudo chmod +x /usr/local/bin/deviceservice

# Create LaunchDaemon plist
sudo tee /Library/LaunchDaemons/com.deviceagent.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.deviceagent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/deviceservice</string>
        <string>service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/deviceagent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/deviceagent.log</string>
</dict>
</plist>
EOF

# Load and start service
sudo launchctl load /Library/LaunchDaemons/com.deviceagent.plist
```

### Method 2: Automated Installation Script

#### Windows PowerShell Script
```powershell
# install-deviceagent.ps1
param(
    [string]$InstallPath = "C:\Program Files\DeviceAgent"
)

# Create installation directory
New-Item -ItemType Directory -Force -Path $InstallPath

# Download latest release
$latest = Invoke-RestMethod -Uri "https://api.github.com/repos/your-repo/releases/latest"
$asset = $latest.assets | Where-Object { $_.name -like "*windows-amd64*" }
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$InstallPath\DeviceAgent.exe"

# Install service
& "$InstallPath\DeviceAgent.exe" install

# Start service
Start-Service DeviceAgent

Write-Host "Device Agent installed successfully!"
```

#### Linux/macOS Shell Script
```bash
#!/bin/bash
# install-deviceagent.sh

set -e

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux-amd64"
    SERVICE_TYPE="systemd"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="darwin-amd64"
    SERVICE_TYPE="launchd"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

# Download and install
sudo curl -L "https://github.com/your-repo/releases/latest/download/deviceservice-$PLATFORM" -o /usr/local/bin/deviceservice
sudo chmod +x /usr/local/bin/deviceservice

# Install service based on platform
if [[ "$SERVICE_TYPE" == "systemd" ]]; then
    # Linux systemd installation
    sudo tee /etc/systemd/system/deviceagent.service > /dev/null <<EOF
[Unit]
Description=RMM Device Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/deviceservice service
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable deviceagent
    sudo systemctl start deviceagent

elif [[ "$SERVICE_TYPE" == "launchd" ]]; then
    # macOS LaunchDaemon installation
    sudo tee /Library/LaunchDaemons/com.deviceagent.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.deviceagent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/deviceservice</string>
        <string>service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/deviceagent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/deviceagent.log</string>
</dict>
</plist>
EOF

    sudo launchctl load /Library/LaunchDaemons/com.deviceagent.plist
fi

echo "Device Agent installed successfully!"
```

## Service Management

### Windows Service Management

#### Installation Commands
```powershell
# Install service (run as Administrator)
DeviceAgent.exe install

# Uninstall service
DeviceAgent.exe uninstall

# Check service status
Get-Service -Name "DeviceAgent"

# Start service manually
Start-Service DeviceAgent

# Stop service
Stop-Service DeviceAgent

# Set startup type
Set-Service DeviceAgent -StartupType Automatic
```

#### Service Configuration
```powershell
# Check service configuration
sc.exe qc DeviceAgent

# Check service dependencies
sc.exe qd DeviceAgent

# Check service failure actions
sc.exe qfailure DeviceAgent

# Set custom failure actions
sc.exe failure DeviceAgent reset=86400 actions=restart/60000/restart/60000/restart/60000
```

#### Troubleshooting Windows Service
```powershell
# Check service logs
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7000,7001,7009,7011} | Where-Object {$_.Message -like "*DeviceAgent*"}

# Check application logs
Get-WinEvent -FilterHashtable @{LogName='Application'; Source='DeviceAgent'}

# Test service manually
DeviceAgent.exe service

# Reinstall service
DeviceAgent.exe uninstall
DeviceAgent.exe install
```

### Linux Service Management

#### Systemd Commands
```bash
# Check service status
sudo systemctl status deviceagent

# Start service
sudo systemctl start deviceagent

# Stop service
sudo systemctl stop deviceagent

# Enable service (auto-start)
sudo systemctl enable deviceagent

# Disable service
sudo systemctl disable deviceagent

# Restart service
sudo systemctl restart deviceagent

# View service logs
sudo journalctl -u deviceagent -f
```

#### Troubleshooting Linux Service
```bash
# Check service configuration
sudo systemctl cat deviceagent

# Check service dependencies
sudo systemctl list-dependencies deviceagent

# Test service manually
sudo /usr/local/bin/deviceservice service

# Check for errors
sudo journalctl -u deviceagent --since "1 hour ago" | grep -i error
```

### macOS Service Management

#### LaunchDaemon Commands
```bash
# Check service status
sudo launchctl list | grep deviceagent

# Start service
sudo launchctl load /Library/LaunchDaemons/com.deviceagent.plist

# Stop service
sudo launchctl unload /Library/LaunchDaemons/com.deviceagent.plist

# Check service logs
sudo tail -f /var/log/deviceagent.log

# Test service manually
sudo /usr/local/bin/deviceservice service
```

#### Troubleshooting macOS Service
```bash
# Check LaunchDaemon configuration
sudo launchctl list | grep deviceagent

# Check service logs
sudo tail -f /var/log/deviceagent.log

# Reload LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/com.deviceagent.plist
sudo launchctl load /Library/LaunchDaemons/com.deviceagent.plist

# Check for errors in system logs
sudo log show --predicate 'process == "deviceservice"' --last 1h
```

## Configuration

### Environment Variables

The agent can be configured using environment variables:

```bash
# Supabase Configuration
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_API_KEY="your-api-key"
export SUPABASE_JWT_SECRET="your-jwt-secret"

# Device Configuration
export DEVICE_ID="custom-device-id"  # Optional, auto-generated if not set
export LOG_LEVEL="info"              # debug, info, warn, error
```

### Configuration Files

#### Windows Configuration
```powershell
# Create configuration directory
New-Item -ItemType Directory -Force -Path "C:\ProgramData\DeviceAgent"

# Create configuration file
@"
{
    "supabase_url": "https://your-project.supabase.co",
    "supabase_api_key": "your-api-key",
    "supabase_jwt_secret": "your-jwt-secret",
    "log_level": "info"
}
"@ | Out-File -FilePath "C:\ProgramData\DeviceAgent\config.json" -Encoding UTF8
```

#### Linux/macOS Configuration
```bash
# Create configuration directory
sudo mkdir -p /etc/deviceagent

# Create configuration file
sudo tee /etc/deviceagent/config.json > /dev/null <<EOF
{
    "supabase_url": "https://your-project.supabase.co",
    "supabase_api_key": "your-api-key",
    "supabase_jwt_secret": "your-jwt-secret",
    "log_level": "info"
}
EOF
```

## Troubleshooting

### Common Issues

#### 1. Service Not Starting After Reboot

**Windows:**
```powershell
# Check startup type
Get-Service DeviceAgent | Select-Object Name, StartType

# Check for dependencies
sc.exe qc DeviceAgent | findstr DEPENDENCIES

# Check event logs
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7000,7001,7009,7011} | Where-Object {$_.Message -like "*DeviceAgent*"}
```

**Linux:**
```bash
# Check service status
sudo systemctl status deviceagent

# Check service logs
sudo journalctl -u deviceagent --since "1 hour ago"

# Check for dependency issues
sudo systemctl list-dependencies deviceagent
```

**macOS:**
```bash
# Check LaunchDaemon status
sudo launchctl list | grep deviceagent

# Check service logs
sudo tail -f /var/log/deviceagent.log

# Check system logs
sudo log show --predicate 'process == "deviceservice"' --last 1h
```

#### 2. Service Failing to Start

**Common Causes:**
- **Missing Dependencies**: Network services not ready
- **Permission Issues**: Service account lacks required permissions
- **Path Issues**: Executable path incorrect
- **Configuration Errors**: Missing configuration files

**Solutions:**
```bash
# Test service manually
./deviceservice service

# Check file permissions
ls -la /usr/local/bin/deviceservice

# Check configuration
cat /etc/deviceagent/config.json

# Reinstall service
./deviceservice uninstall
./deviceservice install
```

#### 3. Connection Issues

**Check Network Connectivity:**
```bash
# Test Supabase connection
curl -I https://your-project.supabase.co

# Check DNS resolution
nslookup your-project.supabase.co

# Test WebSocket connection
curl -I -H "Upgrade: websocket" -H "Connection: Upgrade" https://your-project.supabase.co
```

**Check Authentication:**
```bash
# Verify JWT token generation
./deviceservice run

# Check API key validity
curl -H "apikey: your-api-key" https://your-project.supabase.co/rest/v1/
```

#### 4. Performance Issues

**Monitor Resource Usage:**
```bash
# Check CPU and memory usage
top -p $(pgrep deviceservice)

# Check disk I/O
iotop -p $(pgrep deviceservice)

# Check network connections
netstat -an | grep deviceservice
```

**Optimize Configuration:**
```json
{
    "log_level": "warn",
    "heartbeat_interval": 3600,
    "reconnection_delay": 30
}
```

## Security Considerations

### Service Account Security

#### Windows
```powershell
# Run service as Local System (default)
sc.exe config DeviceAgent obj=LocalSystem

# Run service as specific user (recommended for production)
sc.exe config DeviceAgent obj="DOMAIN\username" password="password"
```

#### Linux
```bash
# Create dedicated service user
sudo useradd -r -s /bin/false deviceagent

# Update service configuration
sudo sed -i 's/User=root/User=deviceagent/' /etc/systemd/system/deviceagent.service
sudo systemctl daemon-reload
```

#### macOS
```bash
# Create dedicated service user
sudo dscl . -create /Users/deviceagent
sudo dscl . -create /Users/deviceagent UserShell /bin/false
sudo dscl . -create /Users/deviceagent RealName "Device Agent Service"

# Update LaunchDaemon configuration
sudo sed -i 's/<key>UserName<\/key>/<key>UserName<\/key>\n    <string>deviceagent<\/string>/' /Library/LaunchDaemons/com.deviceagent.plist
```

### File Permissions

#### Windows
```powershell
# Set proper permissions on installation directory
icacls "C:\Program Files\DeviceAgent" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F"
icacls "C:\Program Files\DeviceAgent" /grant "BUILTIN\Administrators:(OI)(CI)F"
```

#### Linux
```bash
# Set proper permissions
sudo chown -R deviceagent:deviceagent /usr/local/bin/deviceservice
sudo chmod 755 /usr/local/bin/deviceservice
sudo chown -R deviceagent:deviceagent /etc/deviceagent
sudo chmod 600 /etc/deviceagent/config.json
```

#### macOS
```bash
# Set proper permissions
sudo chown deviceagent:staff /usr/local/bin/deviceservice
sudo chmod 755 /usr/local/bin/deviceservice
sudo chown -R deviceagent:staff /etc/deviceagent
sudo chmod 600 /etc/deviceagent/config.json
```

## Monitoring and Logging

### Log Locations

#### Windows
- **Application Logs**: Windows Event Log → Application
- **Service Logs**: Windows Event Log → System
- **Custom Logs**: `C:\ProgramData\DeviceAgent\logs\`

#### Linux
- **Systemd Logs**: `sudo journalctl -u deviceagent`
- **Custom Logs**: `/var/log/deviceagent.log`

#### macOS
- **LaunchDaemon Logs**: `/var/log/deviceagent.log`
- **System Logs**: Console.app or `sudo log show`

### Log Levels

```bash
# Set log level via environment variable
export LOG_LEVEL="debug"

# Set log level via configuration file
{
    "log_level": "info"
}
```

**Available Log Levels:**
- `debug`: Detailed debugging information
- `info`: General information messages
- `warn`: Warning messages
- `error`: Error messages only

### Monitoring Commands

```bash
# Check service status
systemctl status deviceagent  # Linux
launchctl list | grep deviceagent  # macOS
Get-Service DeviceAgent  # Windows

# Monitor logs in real-time
journalctl -u deviceagent -f  # Linux
tail -f /var/log/deviceagent.log  # macOS
Get-WinEvent -FilterHashtable @{LogName='Application'; Source='DeviceAgent'} -MaxEvents 10  # Windows

# Check resource usage
ps aux | grep deviceservice
top -p $(pgrep deviceservice)
```

## Uninstallation

### Windows
```powershell
# Stop service
Stop-Service DeviceAgent

# Uninstall service
DeviceAgent.exe uninstall

# Remove files
Remove-Item -Recurse -Force "C:\Program Files\DeviceAgent"
Remove-Item -Recurse -Force "C:\ProgramData\DeviceAgent"
```

### Linux
```bash
# Stop and disable service
sudo systemctl stop deviceagent
sudo systemctl disable deviceagent

# Remove service file
sudo rm /etc/systemd/system/deviceagent.service
sudo systemctl daemon-reload

# Remove executable
sudo rm /usr/local/bin/deviceservice

# Remove configuration
sudo rm -rf /etc/deviceagent
```

### macOS
```bash
# Stop service
sudo launchctl unload /Library/LaunchDaemons/com.deviceagent.plist

# Remove LaunchDaemon
sudo rm /Library/LaunchDaemons/com.deviceagent.plist

# Remove executable
sudo rm /usr/local/bin/deviceservice

# Remove configuration
sudo rm -rf /etc/deviceagent

# Remove logs
sudo rm /var/log/deviceagent.log
```

## Best Practices

### Installation
1. **Always run installation as Administrator/root**
2. **Verify the executable path is correct**
3. **Test the service manually before relying on auto-start**
4. **Use dedicated service accounts in production**
5. **Set appropriate file permissions**

### Configuration
1. **Use environment variables for sensitive data**
2. **Store configuration files securely**
3. **Rotate API keys regularly**
4. **Monitor service logs for errors**
5. **Set up alerts for service failures**

### Maintenance
1. **Regularly update the agent**
2. **Monitor resource usage**
3. **Review logs for issues**
4. **Test service recovery procedures**
5. **Backup configuration files**

### Security
1. **Use dedicated service accounts**
2. **Limit file permissions**
3. **Encrypt sensitive configuration**
4. **Monitor for unauthorized access**
5. **Keep the agent updated** 