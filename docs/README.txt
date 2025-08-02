RMM Device Agent v1.0.0
========================

This software is part of the Remote Monitoring and Management (RMM) system
provided by Spiffy Solutions Inc.

INSTALLATION:
=============
Windows:
- Run as Administrator
- Execute: go-agent.exe install
- Service will start automatically

Linux:
- sudo ./go-agent install
- Service will start automatically

macOS:
- sudo ./go-agent install
- Service will start automatically

SERVICE MANAGEMENT:
==================
Windows:
- Start: go-agent.exe start
- Stop: go-agent.exe stop
- Status: go-agent.exe status
- Uninstall: go-agent.exe uninstall

Linux/macOS:
- Start: sudo systemctl start go-agent
- Stop: sudo systemctl stop go-agent
- Status: sudo systemctl status go-agent
- Uninstall: sudo ./go-agent uninstall

CONFIGURATION:
==============
The agent connects automatically to the Spiffy Solutions RMM server.
No manual configuration required.

The agent will:
- Register the device with the RMM system
- Collect hardware and software inventory
- Monitor Hyper-V virtual machines (Windows)
- Execute remote commands as requested
- Maintain real-time connection for management

SUPPORT:
========
For technical support:
- Email: help@spiffyit.com
- Website: spiffyit.com
- Hours: Monday-Friday, 9AM-5PM EST

TROUBLESHOOTING:
================
1. Check if service is running
2. Verify network connectivity
3. Check firewall settings
4. Review application logs

LOG LOCATIONS:
==============
- Windows: C:\ProgramData\go-agent\logs\
- Linux: /var/log/go-agent/
- macOS: /var/log/go-agent/

Copyright (c) 2024 Spiffy Solutions Inc
All rights reserved. 