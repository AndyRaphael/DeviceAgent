package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// validateVMID validates that a VM ID is a proper UUID format
func validateVMID(vmID string) error {
	if vmID == "" {
		return errors.New("VM ID cannot be empty")
	}

	// UUID v4 format: 8-4-4-4-12 hexadecimal digits
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if !uuidRegex.MatchString(vmID) {
		return errors.New("invalid VM ID format - must be valid UUID")
	}

	return nil
}

// validateSessionID validates that a session ID is numeric and reasonable
func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return errors.New("session ID cannot be empty")
	}

	// Must be numeric
	sessionNum, err := strconv.Atoi(sessionID)
	if err != nil {
		return errors.New("session ID must be numeric")
	}

	// Reasonable range for session IDs (0-999)
	if sessionNum < 0 || sessionNum > 999 {
		return errors.New("session ID out of valid range (0-999)")
	}

	return nil
}

// validateUsername validates that a username contains only safe characters
func validateUsername(username string) error {
	if username == "" {
		return errors.New("username cannot be empty")
	}

	// Check length (reasonable username length)
	if len(username) > 100 {
		return errors.New("username too long (max 100 characters)")
	}

	// Only allow alphanumeric, dots, hyphens, underscores, and backslashes (for domain\user)
	validUsernameRegex := regexp.MustCompile(`^[a-zA-Z0-9._\\-]+$`)
	if !validUsernameRegex.MatchString(username) {
		return errors.New("username contains invalid characters")
	}

	return nil
}

// validateDelayParameter validates delay parameters for reboot/shutdown
func validateDelayParameter(delay string) error {
	if delay == "" {
		return errors.New("delay parameter cannot be empty")
	}

	delayNum, err := strconv.Atoi(delay)
	if err != nil {
		return errors.New("delay must be a number")
	}

	// Reasonable delay range: 0 to 24 hours (86400 seconds)
	if delayNum < 0 || delayNum > 86400 {
		return errors.New("delay out of valid range (0-86400 seconds)")
	}

	return nil
}

// validateGeneralParameter validates general string parameters to prevent injection
func validateGeneralParameter(paramName, paramValue string) error {
	if paramValue == "" {
		return nil // Empty is often okay for optional parameters
	}

	// Check for potentially dangerous characters that could be used for injection
	dangerousChars := []string{
		";", "|", "&", "$", "`", "$(", "${",
		"'", "\"", "<", ">", "*", "?", "[", "]",
		"\n", "\r", "\t",
	}

	for _, char := range dangerousChars {
		if strings.Contains(paramValue, char) {
			return fmt.Errorf("parameter '%s' contains potentially dangerous character: %s", paramName, char)
		}
	}

	// Check for non-printable characters
	for _, char := range paramValue {
		if !unicode.IsPrint(char) && !unicode.IsSpace(char) {
			return fmt.Errorf("parameter '%s' contains non-printable characters", paramName)
		}
	}

	return nil
}

// sanitizeForPowerShell escapes a string for safe use in PowerShell commands
func sanitizeForPowerShell(input string) string {
	// Replace single quotes with doubled single quotes (PowerShell escaping)
	sanitized := strings.ReplaceAll(input, "'", "''")
	return sanitized
}