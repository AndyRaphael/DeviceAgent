package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

func runMainApplication(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Application panic: %v\n", r)
		}
	}()

	fmt.Println("🚀 Starting device client...")

	jwtToken := authenticateDevice()
	if jwtToken == "" {
		fmt.Println("❌ Failed to authenticate device")
		return
	}

	registerDevice(jwtToken)
	checkMissedCommands(jwtToken)

	// Start heartbeat loop in background
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Heartbeat loop panic: %v\n", r)
			}
		}()
		heartbeatLoop(ctx, jwtToken)
	}()

	// This will now respect the context and can be stopped gracefully
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Realtime connection panic: %v\n", r)
			}
		}()
		connectRealtime(ctx, jwtToken)
	}()

	// If we get here, it means connectRealtime returned (connection lost)
	// Add reconnection logic
	retryCount := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println("🛑 Application shutting down...")
			return
		default:
			retryCount++
			// Exponential backoff: 5s, 10s, 20s, then cap at 60s
			delay := 5 * time.Second
			if retryCount > 1 {
				delay = time.Duration(min(60, 5*retryCount)) * time.Second
			}

			fmt.Printf("🔄 Connection lost, reconnecting in %v... (attempt %d)\n", delay, retryCount)
			time.Sleep(delay)

			// Try to reconnect
			newToken := authenticateDevice()
			if newToken != "" {
				fmt.Println("🔄 Attempting to reconnect...")
				connectRealtime(ctx, newToken)
				// If we get here again, the connection was lost again
				fmt.Println("⚠️  Connection lost again...")
			} else {
				fmt.Println("❌ Failed to get new token for reconnection")
				// Reset retry count on auth failure and wait longer
				retryCount = 0
				time.Sleep(30 * time.Second)
			}
		}
	}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
