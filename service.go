package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <command>\n", filepath.Base(os.Args[0]))
		fmt.Println("Commands:")
		fmt.Println("  run          - Run the application")
		fmt.Println("  service      - Run as service (handles Windows SCM)")
		fmt.Println("  capture-screen - Helper mode for screen capture")
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "run":
		// Run normally
		ctx := context.Background()
		runMainApplication(ctx)
		return
	case "service":
		// Run as service (platform-specific implementation)
		runAsService()
		return
	case "capture-screen":
		// Helper mode for screen capture
		handleScreenCaptureHelper()
		return
	default:
		log.Fatalf("Invalid command %s", cmd)
	}
}

func runAsConsoleService() {
	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start the application in a goroutine
	go func() {
		log.Println("Starting device service...")
		runMainApplication(ctx)
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)
	cancel()

	// Give the application time to shut down gracefully
	time.Sleep(2 * time.Second)
	log.Println("Service stopped gracefully")
}
