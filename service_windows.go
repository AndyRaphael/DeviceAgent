//go:build windows
// +build windows

package main

import (
	"context"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

func runAsService() {
	runAsWindowsService()
}

func runAsWindowsService() {
	// Check if we're running as a Windows service
	isWindowsService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine if we are running as service: %v", err)
	}

	if isWindowsService {
		// Running as actual Windows service
		err = svc.Run("DeviceAgent", &deviceService{})
		if err != nil {
			log.Fatalf("failed to run service: %v", err)
		}
	} else {
		// Running in console mode (for testing)
		runAsConsoleService()
	}
}

// deviceService implements the Windows service interface
type deviceService struct{}

func (s *deviceService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// Report that we're starting
	changes <- svc.Status{State: svc.StartPending}

	// Create context for the main application
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the main application in background
	go func() {
		log.Println("Starting device service...")
		runMainApplication(ctx)
	}()

	// Give the application a moment to initialize
	time.Sleep(2 * time.Second)

	// Report that we're running and ready
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Println("Service reported as running to Windows SCM")

	// Handle service control requests using range
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
			time.Sleep(100 * time.Millisecond)
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			log.Println("Service stop requested")
			changes <- svc.Status{State: svc.StopPending}
			cancel()                    // Cancel the main application context
			time.Sleep(2 * time.Second) // Give time for graceful shutdown
			return false, 0
		default:
			log.Printf("Unexpected service control request: %d", c.Cmd)
		}
	}

	// If we exit the range loop, it means the channel was closed
	log.Println("Service control channel closed")
	return false, 0
}
