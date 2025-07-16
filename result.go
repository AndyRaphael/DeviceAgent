package main

// NewSuccessResult creates a successful result with structured JSON data
func NewSuccessResult(data interface{}) CommandResult {
	return CommandResult{
		Result: data,
		Status: "success",
	}
}

// NewSuccessResultWithLogs creates a successful result with both data and logs
func NewSuccessResultWithLogs(data interface{}, logs string) CommandResult {
	return CommandResult{
		Result: data,
		Logs:   logs,
		Status: "success",
	}
}

// NewErrorResult creates an error result with logs only
func NewErrorResult(errorMsg string) CommandResult {
	return CommandResult{
		Logs:   errorMsg,
		Status: "error",
	}
}

// NewErrorResultWithDetails creates an error result with detailed logs
func NewErrorResultWithDetails(errorMsg, details string) CommandResult {
	logs := errorMsg
	if details != "" {
		logs += "\n\nDetails:\n" + details
	}
	return CommandResult{
		Logs:   logs,
		Status: "error",
	}
}

// AddLogs appends additional log information to existing logs
func (cr *CommandResult) AddLogs(additionalLogs string) {
	if cr.Logs == "" {
		cr.Logs = additionalLogs
	} else {
		cr.Logs += "\n" + additionalLogs
	}
}

// SetScreenshot adds screenshot data and updates the result with metadata
func (cr *CommandResult) SetScreenshot(base64Data string, metadata map[string]interface{}) {
	cr.ScreenshotData = base64Data
	if cr.Result == nil {
		cr.Result = make(map[string]interface{})
	}
	if resultMap, ok := cr.Result.(map[string]interface{}); ok {
		for key, value := range metadata {
			resultMap[key] = value
		}
	}
}