//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/image/draw"
	"golang.org/x/sys/windows"
)

// Windows API constants
const (
	SRCCOPY            = 0x00CC0020
	SM_CXSCREEN        = 0
	SM_CYSCREEN        = 1
	SM_XVIRTUALSCREEN  = 76
	SM_YVIRTUALSCREEN  = 77
	SM_CXVIRTUALSCREEN = 78
	SM_CYVIRTUALSCREEN = 79

	// DIB constants
	DIB_RGB_COLORS = 0
	BI_RGB         = 0

	// DPI Awareness constants
	PROCESS_DPI_UNAWARE           = 0
	PROCESS_SYSTEM_DPI_AWARE      = 1
	PROCESS_PER_MONITOR_DPI_AWARE = 2

	// Token and process constants
	TOKEN_DUPLICATE            = 0x0002
	TOKEN_ASSIGN_PRIMARY       = 0x0001
	TOKEN_QUERY                = 0x0008
	TOKEN_IMPERSONATE          = 0x0004
	TOKEN_ALL_ACCESS           = 0x001f01ff
	SecurityImpersonation      = 2
	TokenPrimary               = 1
	NORMAL_PRIORITY_CLASS      = 0x00000020
	CREATE_UNICODE_ENVIRONMENT = 0x00000400
	CREATE_NO_WINDOW           = 0x08000000
	INFINITE                   = 0xFFFFFFFF
	WAIT_OBJECT_0              = 0
	WAIT_TIMEOUT               = 0x00000102

	// Window show states
	SW_HIDE              = 0
	STARTF_USESHOWWINDOW = 0x00000001
)

// Windows API structures
type BITMAPINFOHEADER struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type BITMAPINFO struct {
	Header BITMAPINFOHEADER
	Colors [1]uint32
}

type STARTUPINFO struct {
	Cb            uint32
	_             *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             *uint8
	StdInput      uintptr
	StdOutput     uintptr
	StdError      uintptr
}

type PROCESS_INFORMATION struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}

// ScreenInfo holds screen dimension and DPI information
type ScreenInfo struct {
	virtualLeft   int
	virtualTop    int
	virtualWidth  int
	virtualHeight int
	dpiInfo       string
}

var (
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modgdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modwtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	moduserenv  = windows.NewLazySystemDLL("userenv.dll")
	modshcore   = windows.NewLazySystemDLL("shcore.dll")

	procGetSystemMetrics       = moduser32.NewProc("GetSystemMetrics")
	procGetSystemMetricsForDpi = moduser32.NewProc("GetSystemMetricsForDpi")
	procGetDpiForSystem        = moduser32.NewProc("GetDpiForSystem")
	procSetProcessDpiAwareness = modshcore.NewProc("SetProcessDpiAwareness")
	procGetDC                  = moduser32.NewProc("GetDC")
	procReleaseDC              = moduser32.NewProc("ReleaseDC")
	procCreateCompatibleDC     = modgdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = modgdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = modgdi32.NewProc("SelectObject")
	procBitBlt                 = modgdi32.NewProc("BitBlt")
	procDeleteDC               = modgdi32.NewProc("DeleteDC")
	procDeleteObject           = modgdi32.NewProc("DeleteObject")
	procGetDIBits              = modgdi32.NewProc("GetDIBits")
	procCreateDIBSection       = modgdi32.NewProc("CreateDIBSection")
	procGetPixel               = modgdi32.NewProc("GetPixel")
	procOpenDesktop            = moduser32.NewProc("OpenDesktopW")
	procSetThreadDesktop       = moduser32.NewProc("SetThreadDesktop")
	procCloseDesktop           = moduser32.NewProc("CloseDesktop")
	procStretchBlt             = modgdi32.NewProc("StretchBlt")

	// Session and process management
	procWTSQueryUserToken       = modwtsapi32.NewProc("WTSQueryUserToken")
	procCreateProcessAsUser     = modadvapi32.NewProc("CreateProcessAsUserW")
	procDuplicateTokenEx        = modadvapi32.NewProc("DuplicateTokenEx")
	procCreateEnvironmentBlock  = moduserenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock = moduserenv.NewProc("DestroyEnvironmentBlock")
	procCloseHandle             = modkernel32.NewProc("CloseHandle")
	procWaitForSingleObject     = modkernel32.NewProc("WaitForSingleObject")
	procGetForegroundWindow     = moduser32.NewProc("GetForegroundWindow")
	procGetDesktopWindow        = moduser32.NewProc("GetDesktopWindow")
	procGetShellWindow          = moduser32.NewProc("GetShellWindow")
	procGetWindowDC             = moduser32.NewProc("GetWindowDC")
	procEnumWindows             = moduser32.NewProc("EnumWindows")
	procGetWindowText           = moduser32.NewProc("GetWindowTextW")
	procIsWindowVisible         = moduser32.NewProc("IsWindowVisible")
	procCreateDC                = modgdi32.NewProc("CreateDCW")
	procGetBitmapBits           = modgdi32.NewProc("GetBitmapBits")
)

// captureScreen - Main entry point with WTS detection
func captureScreen(params map[string]interface{}) CommandResult {
	var logs []string
	logs = append(logs, "Screen capture command initiated")

	sessionID, hasSessionID := params["session_id"].(string)
	username, hasUsername := params["username"].(string)

	if !hasSessionID && !hasUsername {
		errorMsg := "Either session_id or username parameter is required"
		logs = append(logs, errorMsg)
		return createScreenCaptureError(errorMsg, logs)
	}

	// If username provided, find session ID
	if hasUsername && !hasSessionID {
		logs = append(logs, fmt.Sprintf("Looking up session ID for username: %s", username))
		sessionID = findSessionByUsername(username)
		if sessionID == "" {
			errorMsg := fmt.Sprintf("No session found for user: %s", username)
			logs = append(logs, errorMsg)
			return createScreenCaptureError(errorMsg, logs)
		}
		logs = append(logs, fmt.Sprintf("Found session ID: %s for username: %s", sessionID, username))
	}

	timestamp := time.Now().Format("20060102_150405")
	currentUser := os.Getenv("USERNAME")
	isSystemUser := isRunningAsSystem()

	logs = append(logs, fmt.Sprintf("Current user: %s, Is SYSTEM: %t, Target session: %s", currentUser, isSystemUser, sessionID))

	// Get session information to determine capture method
	sessionInfo, err := getSessionInfo(sessionID)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to get session info: %v", err)
		logs = append(logs, errorMsg)
		return createScreenCaptureError(errorMsg, logs)
	}

	logs = append(logs, fmt.Sprintf("Session type: %s, Session state: %s", sessionInfo.SessionType, sessionInfo.State))

	// Choose capture method based on session type and current context - PRESERVE EXISTING LOGIC
	var result CommandResult
	if sessionInfo.IsRDPSession() && isSystemUser {
		logs = append(logs, "Using WTS API approach for RDP session")
		result = captureScreenWTS(sessionID, timestamp, sessionInfo)
	} else if isSystemUser {
		logs = append(logs, "Using helper executable approach for console session from service")
		result = captureScreenViaHelper(sessionID, timestamp)
	} else {
		logs = append(logs, "Using direct capture approach")
		result = captureScreenDirect(sessionID, timestamp)
	}

	// SAFELY add our logs to existing result without breaking anything
	if result.Logs == "" {
		result.Logs = strings.Join(logs, "\n")
	} else {
		result.Logs = strings.Join(logs, "\n") + "\n\n" + result.Logs
	}

	return result
}

// handleScreenCaptureHelper - Cross-platform wrapper
func handleScreenCaptureHelper() {
	runScreenCaptureHelper()
}

// runScreenCaptureHelper runs the screen capture helper mode (restored functionality)
func runScreenCaptureHelper() {
	if len(os.Args) < 5 {
		fmt.Println("ERROR: Insufficient arguments")
		fmt.Println("Usage: deviceagent.exe capture-screen --session <sessionid> --output <filepath> [--wts-mode]")
		os.Exit(1)
	}

	var sessionID, outputPath string
	var wtsMode bool

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--session":
			if i+1 < len(os.Args) {
				sessionID = os.Args[i+1]
				i++
			}
		case "--output":
			if i+1 < len(os.Args) {
				outputPath = os.Args[i+1]
				i++
			}
		case "--wts-mode":
			wtsMode = true
		case "--debug":
			// Debug mode enabled (kept for compatibility)
		case "--verbose":
			// Verbose mode enabled (kept for compatibility)
		case "--switch-desktop":
			// Switch desktop enabled (kept for compatibility)
		}
	}

	if sessionID == "" || outputPath == "" {
		fmt.Println("ERROR: Missing required parameters")
		fmt.Println("Error: Both --session and --output parameters are required")
		os.Exit(1)
	}

	// Execute screen capture
	result := executeScreenCaptureHelper(sessionID, outputPath, wtsMode)
	if result != nil {
		fmt.Printf("Error: %v\n", result)
		os.Exit(1)
	}

	fmt.Println("Screen capture completed successfully")
}

// executeScreenCaptureHelper is called when running in helper mode with optimized capture
func executeScreenCaptureHelper(sessionID, outputPath string, wtsMode bool) error {

	fmt.Printf("Helper started - Session: %s, WTS: %t\n", sessionID, wtsMode)

	// Get virtual screen dimensions
	virtualLeft, _, _ := procGetSystemMetrics.Call(SM_XVIRTUALSCREEN)
	virtualTop, _, _ := procGetSystemMetrics.Call(SM_YVIRTUALSCREEN)
	virtualWidth, _, _ := procGetSystemMetrics.Call(SM_CXVIRTUALSCREEN)
	virtualHeight, _, _ := procGetSystemMetrics.Call(SM_CYVIRTUALSCREEN)

	// Enhanced desktop DC access with RDP-specific handling
	var hDesktopDC uintptr
	var dcMethod string
	var sourceWindow uintptr

	// For RDP sessions (WTS mode), skip window-based DCs and go straight to screen/display DCs
	if wtsMode {
		// Method 1: Try CreateDC("DISPLAY") first for RDP
		displayName, _ := windows.UTF16PtrFromString("DISPLAY")
		hDesktopDC, _, _ = procCreateDC.Call(
			uintptr(unsafe.Pointer(displayName)), 0, 0, 0,
		)
		if hDesktopDC != 0 {
			dcMethod = "CreateDC DISPLAY"
		}

		// Method 2: Fallback to GetDC(0) for RDP if CreateDC fails
		if hDesktopDC == 0 {
			hDesktopDC, _, _ = procGetDC.Call(0)
			if hDesktopDC != 0 {
				dcMethod = "Screen DC (RDP fallback)"
			}
		}
	} else {
		// For console sessions, try window-based methods first

		// Method 1: Try to get DC from foreground window first
		hForegroundWnd, _, _ := procGetForegroundWindow.Call()
		if hForegroundWnd != 0 {
			hDesktopDC, _, _ = procGetDC.Call(hForegroundWnd)
			if hDesktopDC != 0 {
				dcMethod = "Foreground Window DC"
				sourceWindow = hForegroundWnd
			} else {
				if hDesktopDC != 0 {
					procReleaseDC.Call(hForegroundWnd, hDesktopDC)
					hDesktopDC = 0
				}
			}
		}

		// Method 2: Try to get DC from desktop window
		if hDesktopDC == 0 {
			hDesktopWnd, _, _ := procGetDesktopWindow.Call()
			if hDesktopWnd != 0 {
				hDesktopDC, _, _ = procGetDC.Call(hDesktopWnd)
				if hDesktopDC != 0 {
					dcMethod = "Desktop Window DC"
					sourceWindow = hDesktopWnd
				} else {
					if hDesktopDC != 0 {
						procReleaseDC.Call(hDesktopWnd, hDesktopDC)
						hDesktopDC = 0
					}
				}
			}
		}

		// Method 3: Fallback to screen DC for console
		if hDesktopDC == 0 {
			hDesktopDC, _, _ = procGetDC.Call(0)
			if hDesktopDC != 0 {
				dcMethod = "Screen DC (console fallback)"
				sourceWindow = 0
			}
		}
	}

	if hDesktopDC == 0 {
		return fmt.Errorf("failed to get desktop DC")
	}

	// Set up proper cleanup based on method used
	defer func() {
		if dcMethod == "CreateDC DISPLAY" {
			procDeleteDC.Call(hDesktopDC)
		} else if dcMethod == "Foreground Window DC" && sourceWindow != 0 {
			procReleaseDC.Call(sourceWindow, hDesktopDC)
		} else if dcMethod == "Desktop Window DC" && sourceWindow != 0 {
			procReleaseDC.Call(sourceWindow, hDesktopDC)
		} else {
			procReleaseDC.Call(0, hDesktopDC)
		}
	}()

	// Test memory DC creation
	hMemoryDC, _, err := procCreateCompatibleDC.Call(hDesktopDC)
	if hMemoryDC == 0 {
		return fmt.Errorf("failed to create compatible DC: %v", err)
	}
	defer procDeleteDC.Call(hMemoryDC)

	// Calculate target dimensions based on monitor setup
	var targetWidth int
	if virtualWidth > virtualHeight*2 {
		// Multi-monitor setup (wide aspect ratio) - use higher resolution
		targetWidth = 1200
	} else {
		// Single monitor or stacked setup - use standard resolution
		targetWidth = 800
	}

	scaleFactorX := float64(virtualWidth) / float64(targetWidth)
	targetHeight := int(float64(virtualHeight) / scaleFactorX)

	hBitmap, _, err := procCreateCompatibleBitmap.Call(hDesktopDC, uintptr(targetWidth), uintptr(targetHeight))
	if hBitmap == 0 {
		return fmt.Errorf("failed to create compatible bitmap: %v", err)
	}
	defer procDeleteObject.Call(hBitmap)

	hOldBitmap, _, err := procSelectObject.Call(hMemoryDC, hBitmap)
	if hOldBitmap == 0 {
		return fmt.Errorf("failed to select bitmap: %v", err)
	}
	defer procSelectObject.Call(hMemoryDC, hOldBitmap)

	// Perform StretchBlt to scale full screen to target size
	result, _, err := procStretchBlt.Call(
		hMemoryDC, // Destination DC
		0, 0,      // Destination x,y
		uintptr(targetWidth), uintptr(targetHeight), // Destination width,height
		hDesktopDC,                                // Source DC
		uintptr(virtualLeft), uintptr(virtualTop), // Source x,y
		uintptr(virtualWidth), uintptr(virtualHeight), // Source width,height
		SRCCOPY, // Copy mode
	)

	if result == 0 {
		return fmt.Errorf("failed to capture and scale screen: %v", err)
	}

	// Check if user wants high quality mode
	highQuality := false
	for _, arg := range os.Args {
		if arg == "--high-quality" || arg == "--hq" {
			highQuality = true
			break
		}
	}

	var goImage image.Image
	var convertErr error

	if highQuality {
		goImage, convertErr = convertUsingScanlines(hMemoryDC, targetWidth, targetHeight, logCleanFunc)
	} else {
		goImage, convertErr = convertHBitmapToImageFastRDP(hBitmap, targetWidth, targetHeight, hMemoryDC, logCleanFunc)
	}

	if convertErr != nil {
		return fmt.Errorf("failed to convert bitmap: %v", convertErr)
	}

	// Encode final image
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, goImage, &jpeg.Options{Quality: 85})
	if err != nil {
		return fmt.Errorf("failed to encode JPEG: %v", err)
	}
	imageData := buf.Bytes()

	// Write output file
	err = os.WriteFile(outputPath, imageData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	fmt.Printf("Screenshot completed - %d bytes\n", len(imageData))
	return nil
}

// Simplified logging function for conversion methods
func logCleanFunc(message string) {
	// Only log critical errors and successes, skip verbose progress
	if strings.Contains(message, "ERROR") || strings.Contains(message, "SUCCESS") {
		fmt.Println(message)
	}
}

// Add this new fast conversion function specifically for RDP
func convertHBitmapToImageFastRDP(hBitmap uintptr, width, height int, hMemoryDC uintptr, logFunc func(string)) (image.Image, error) {
	// Method 1: Enhanced GetDIBits with proper format detection
	img, err := convertUsingGetDIBitsEnhanced(hBitmap, width, height, logFunc)
	if err == nil && hasImageContent(img, logFunc) {
		logFunc("SUCCESS: Enhanced GetDIBits method worked")
		return img, nil
	}

	// Method 2: Smart interpolation (every 2nd pixel)
	img, err = convertUsingSmartInterpolation(hMemoryDC, width, height, logFunc)
	if err == nil && hasImageContent(img, logFunc) {
		logFunc("SUCCESS: Smart interpolation worked")
		return img, nil
	}

	// Method 3: Fallback to GetBitmapBits with all formats
	return convertUsingGetBitmapBitsEnhanced(hBitmap, width, height, logFunc)
}

// Enhanced GetDIBits that should work better with RDP
func convertUsingGetDIBitsEnhanced(hBitmap uintptr, width, height int, logFunc func(string)) (image.Image, error) {
	// Get a DC for GetDIBits
	hScreenDC, _, _ := procGetDC.Call(0)
	if hScreenDC == 0 {
		return nil, fmt.Errorf("failed to get screen DC")
	}
	defer procReleaseDC.Call(0, hScreenDC)

	// Try 32-bit format first (most likely to work with RDP)
	bmi := BITMAPINFO{
		Header: BITMAPINFOHEADER{
			Size:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
			Width:       int32(width),
			Height:      -int32(height), // Negative for top-down
			Planes:      1,
			BitCount:    32,
			Compression: BI_RGB,
		},
	}

	imageSize := width * height * 4
	bitmapData := make([]byte, imageSize)

	// Second call to get actual bitmap data
	result, _, _ := procGetDIBits.Call(
		hScreenDC,
		hBitmap,
		0,
		uintptr(height),
		uintptr(unsafe.Pointer(&bitmapData[0])),
		uintptr(unsafe.Pointer(&bmi)),
		DIB_RGB_COLORS,
	)

	if result == 0 {
		// Try 24-bit format
		bmi.Header.BitCount = 24
		stride := ((width*3 + 3) / 4) * 4
		imageSize = stride * height
		bitmapData = make([]byte, imageSize)

		result, _, _ = procGetDIBits.Call(
			hScreenDC,
			hBitmap,
			0,
			uintptr(height),
			uintptr(unsafe.Pointer(&bitmapData[0])),
			uintptr(unsafe.Pointer(&bmi)),
			DIB_RGB_COLORS,
		)

		if result == 0 {
			return nil, fmt.Errorf("both 32-bit and 24-bit GetDIBits failed")
		}

		logFunc("SUCCESS: 24-bit GetDIBits worked")

		// Convert 24-bit BGR data
		img := image.NewRGBA(image.Rect(0, 0, width, height))
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				offset := y*stride + x*3
				if offset+2 < len(bitmapData) {
					b := bitmapData[offset]
					g := bitmapData[offset+1]
					r := bitmapData[offset+2]
					img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
				}
			}
		}
		return img, nil
	}

	logFunc("SUCCESS: 32-bit GetDIBits worked")

	// Convert 32-bit BGRA data
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offset := (y*width + x) * 4
			if offset+3 < len(bitmapData) {
				b := bitmapData[offset]
				g := bitmapData[offset+1]
				r := bitmapData[offset+2]
				a := bitmapData[offset+3]
				if a == 0 {
					a = 255
				}
				img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: a})
			}
		}
	}

	return img, nil
}

// Smart interpolation optimized for smaller target images
func convertUsingSmartInterpolation(hMemoryDC uintptr, width, height int, logFunc func(string)) (image.Image, error) {
	// For smaller images, sample every pixel for best quality
	// For larger images, use adaptive sampling
	var sampleStep int
	if width <= 1000 && height <= 600 {
		sampleStep = 1 // Sample every pixel for small images
	} else {
		sampleStep = 2 // Sample every 2nd pixel for larger images
	}

	samplesX := (width + sampleStep - 1) / sampleStep
	samplesY := (height + sampleStep - 1) / sampleStep

	// Create sample array
	samples := make([][]color.RGBA, samplesY)
	for i := range samples {
		samples[i] = make([]color.RGBA, samplesX)
	}

	// Sample the pixels
	for sy := 0; sy < samplesY; sy++ {
		for sx := 0; sx < samplesX; sx++ {
			x := sx * sampleStep
			y := sy * sampleStep

			if x < width && y < height {
				pixelColor, _, _ := procGetPixel.Call(hMemoryDC, uintptr(x), uintptr(y))
				r := uint8(pixelColor & 0xFF)
				g := uint8((pixelColor >> 8) & 0xFF)
				b := uint8((pixelColor >> 16) & 0xFF)

				samples[sy][sx] = color.RGBA{R: r, G: g, B: b, A: 255}
			}
		}
	}

	// Create full image
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Find surrounding sample points
			sx := x / sampleStep
			sy := y / sampleStep

			// Simple nearest neighbor
			if sx < samplesX && sy < samplesY {
				img.Set(x, y, samples[sy][sx])
			}
		}
	}

	logFunc("SUCCESS: Smart interpolation completed")
	return img, nil
}

// Enhanced GetBitmapBits with better format detection
func convertUsingGetBitmapBitsEnhanced(hBitmap uintptr, width, height int, logFunc func(string)) (image.Image, error) {
	// Try different bit depths
	formats := []struct {
		bitsPerPixel  int
		bytesPerPixel int
		name          string
	}{
		{32, 4, "32-bit BGRA"},
		{24, 3, "24-bit BGR"},
		{16, 2, "16-bit RGB"},
	}

	for _, format := range formats {
		bitmapSize := width * height * format.bytesPerPixel
		bitmapData := make([]byte, bitmapSize)

		bytesRead, _, _ := procGetBitmapBits.Call(
			hBitmap,
			uintptr(bitmapSize),
			uintptr(unsafe.Pointer(&bitmapData[0])),
		)

		if bytesRead == 0 {
			continue
		}

		// Convert based on format
		img := image.NewRGBA(image.Rect(0, 0, width, height))

		switch format.bitsPerPixel {
		case 32:
			// 32-bit BGRA format
			for y := 0; y < height; y++ {
				for x := 0; x < width; x++ {
					offset := (y*width + x) * 4
					if offset+3 < len(bitmapData) {
						b := bitmapData[offset]
						g := bitmapData[offset+1]
						r := bitmapData[offset+2]
						a := bitmapData[offset+3]
						if a == 0 {
							a = 255
						}
						img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: a})
					}
				}
			}

		case 24:
			// 24-bit BGR format
			stride := ((width*3 + 3) / 4) * 4 // 4-byte aligned
			for y := 0; y < height; y++ {
				for x := 0; x < width; x++ {
					offset := y*stride + x*3
					if offset+2 < len(bitmapData) {
						b := bitmapData[offset]
						g := bitmapData[offset+1]
						r := bitmapData[offset+2]
						img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
					}
				}
			}

		case 16:
			// 16-bit RGB format (5-6-5)
			for y := 0; y < height; y++ {
				for x := 0; x < width; x++ {
					offset := (y*width + x) * 2
					if offset+1 < len(bitmapData) {
						pixel := uint16(bitmapData[offset]) | (uint16(bitmapData[offset+1]) << 8)
						r := uint8((pixel & 0xF800) >> 8)
						g := uint8((pixel & 0x07E0) >> 3)
						b := uint8((pixel & 0x001F) << 3)
						img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
					}
				}
			}
		}

		// Test if this format produced good content
		if hasImageContent(img, logFunc) {
			logFunc("SUCCESS: " + format.name + " format produced valid image")
			return img, nil
		}
	}

	return nil, fmt.Errorf("all GetBitmapBits formats failed")
}

// Helper function to check if image has actual content
func hasImageContent(img image.Image, logFunc func(string)) bool {
	bounds := img.Bounds()
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		return false
	}

	// Check several points across the image
	checkPoints := [][2]int{
		{10, 10},
		{bounds.Dx() / 4, bounds.Dy() / 4},
		{bounds.Dx() / 2, bounds.Dy() / 2},
		{bounds.Dx() * 3 / 4, bounds.Dy() * 3 / 4},
		{bounds.Dx() - 10, bounds.Dy() - 10},
	}

	nonBlackPixels := 0
	nonWhitePixels := 0

	for _, point := range checkPoints {
		if point[0] < bounds.Dx() && point[1] < bounds.Dy() {
			r, g, b, _ := img.At(point[0], point[1]).RGBA()
			r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(b>>8)

			if r8 != 0 || g8 != 0 || b8 != 0 {
				nonBlackPixels++
			}
			if r8 != 255 || g8 != 255 || b8 != 255 {
				nonWhitePixels++
			}
		}
	}

	hasContent := nonBlackPixels > 0 && nonWhitePixels > 0

	return hasContent
}

// For very high quality, let's try a scanline approach
func convertUsingScanlines(hMemoryDC uintptr, width, height int, logFunc func(string)) (image.Image, error) {
	logFunc("Starting scanline conversion for maximum quality...")

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Process one line at a time for better performance
	for y := 0; y < height; y++ {
		// Sample this entire line
		for x := 0; x < width; x++ {
			pixelColor, _, _ := procGetPixel.Call(hMemoryDC, uintptr(x), uintptr(y))

			r := uint8(pixelColor & 0xFF)
			g := uint8((pixelColor >> 8) & 0xFF)
			b := uint8((pixelColor >> 16) & 0xFF)

			img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}

		// Progress every 5%
		if y%(height/20) == 0 {
			progress := (y * 100) / height
			logFunc(fmt.Sprintf("Scanline progress: %d%% (line %d/%d)", progress, y, height))
		}
	}

	logFunc("Scanline conversion complete")
	return img, nil
}

// isRunningAsSystem checks if the current process is running as SYSTEM
func isRunningAsSystem() bool {
	username := os.Getenv("USERNAME")
	usernameLower := strings.ToLower(username)

	return strings.Contains(usernameLower, "system") ||
		strings.HasSuffix(usernameLower, "$") ||
		strings.Contains(usernameLower, "local service") ||
		strings.Contains(usernameLower, "network service")
}

// captureScreenViaHelper launches helper executable in target session
func captureScreenViaHelper(sessionID, timestamp string) CommandResult {
	tempDir := "C:\\ProgramData\\DeviceAgent\\temp"
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to create temp directory: %v", err)},
			Error:  fmt.Sprintf("Failed to create temp directory: %v", err),
			Status: "error",
		}
	}

	outputPath := fmt.Sprintf("%s\\screenshot_%s_%s.jpg", tempDir, sessionID, timestamp)

	exePath, err := os.Executable()
	if err != nil {
		return CommandResult{
			Output: map[string]string{"error": fmt.Sprintf("Failed to get executable path: %v", err)},
			Error:  fmt.Sprintf("Failed to get executable path: %v", err),
			Status: "error",
		}
	}

	result := launchHelperInSession(exePath, sessionID, outputPath)
	if result.Status == "error" {
		return result
	}

	return waitForHelperAndReadResult(outputPath, sessionID, timestamp)
}

// captureScreenDirect performs direct screen capture (when running as user)
func captureScreenDirect(sessionID, timestamp string) CommandResult {
	return captureScreenNative(sessionID, timestamp)
}

// launchHelperInSession launches the helper executable in the specified session
func launchHelperInSession(exePath, sessionID, outputPath string) CommandResult {
	var diagnostics []string
	diagnostics = append(diagnostics, "=== LAUNCHING HELPER IN SESSION ===")
	diagnostics = append(diagnostics, fmt.Sprintf("Executable: %s", exePath))
	diagnostics = append(diagnostics, fmt.Sprintf("Session ID: %s", sessionID))
	diagnostics = append(diagnostics, fmt.Sprintf("Output path: %s", outputPath))

	sessionIDNum := uint32(0)
	if _, err := fmt.Sscanf(sessionID, "%d", &sessionIDNum); err != nil {
		diagnostics = append(diagnostics, fmt.Sprintf("Invalid session ID: %v", err))
		return createHelperFailureResult(diagnostics, "Invalid session ID")
	}

	var userToken uintptr
	result, _, err := procWTSQueryUserToken.Call(uintptr(sessionIDNum), uintptr(unsafe.Pointer(&userToken)))
	if result == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("WTSQueryUserToken failed: %v", err))
		return createHelperFailureResult(diagnostics, "Failed to get user token for session")
	}
	defer procCloseHandle.Call(userToken)
	diagnostics = append(diagnostics, "User token obtained successfully")

	var duplicatedToken uintptr
	result, _, err = procDuplicateTokenEx.Call(
		userToken,
		TOKEN_ALL_ACCESS,
		0,
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&duplicatedToken)),
	)
	if result == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("DuplicateTokenEx failed: %v", err))
		return createHelperFailureResult(diagnostics, "Failed to duplicate token")
	}
	defer procCloseHandle.Call(duplicatedToken)
	diagnostics = append(diagnostics, "Token duplicated successfully")

	var environment uintptr
	result, _, err = procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&environment)),
		duplicatedToken,
		0,
	)
	if result == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("CreateEnvironmentBlock failed: %v", err))
		environment = 0
	} else {
		defer procDestroyEnvironmentBlock.Call(environment)
		diagnostics = append(diagnostics, "Environment block created successfully")
	}

	commandLine := fmt.Sprintf(`"%s" capture-screen --session %s --output "%s"`, exePath, sessionID, outputPath)
	commandLinePtr, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		diagnostics = append(diagnostics, fmt.Sprintf("Failed to convert command line: %v", err))
		return createHelperFailureResult(diagnostics, "Failed to prepare command line")
	}
	diagnostics = append(diagnostics, fmt.Sprintf("Command line: %s", commandLine))

	desktop, _ := windows.UTF16PtrFromString("winsta0\\default")
	startupInfo := STARTUPINFO{
		Cb:         uint32(unsafe.Sizeof(STARTUPINFO{})),
		Desktop:    desktop,
		Flags:      STARTF_USESHOWWINDOW,
		ShowWindow: SW_HIDE,
	}

	var processInfo PROCESS_INFORMATION

	result, _, err = procCreateProcessAsUser.Call(
		duplicatedToken,
		0,
		uintptr(unsafe.Pointer(commandLinePtr)),
		0,
		0,
		0,
		NORMAL_PRIORITY_CLASS|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW,
		environment,
		0,
		uintptr(unsafe.Pointer(&startupInfo)),
		uintptr(unsafe.Pointer(&processInfo)),
	)

	if result == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("CreateProcessAsUser failed: %v", err))
		return createHelperFailureResult(diagnostics, "Failed to create process in user session")
	}

	diagnostics = append(diagnostics, fmt.Sprintf("Helper process created successfully (PID: %d)", processInfo.ProcessId))

	waitResult, _, _ := procWaitForSingleObject.Call(processInfo.Process, 30000)

	procCloseHandle.Call(processInfo.Process)
	procCloseHandle.Call(processInfo.Thread)

	switch waitResult {
	case WAIT_OBJECT_0:
		diagnostics = append(diagnostics, "Helper process completed successfully")
		return CommandResult{
			Output: map[string]interface{}{
				"success":     true,
				"session_id":  sessionID,
				"diagnostics": strings.Join(diagnostics, "\n"),
				"method":      "Helper Process Launch",
			},
			Error:  "",
			Status: "success",
		}
	case WAIT_TIMEOUT:
		diagnostics = append(diagnostics, "Helper process timed out")
		return createHelperFailureResult(diagnostics, "Helper process timed out")
	default:
		diagnostics = append(diagnostics, fmt.Sprintf("Wait failed with result: %d", waitResult))
		return createHelperFailureResult(diagnostics, "Failed to wait for helper process")
	}
}

// createHelperFailureResult creates a failure result for helper launching with enhanced logging
func createHelperFailureResult(diagnostics []string, errorMsg string) CommandResult {
	diagnosticsText := strings.Join(diagnostics, "\n")

	logs := []string{
		"Helper process launch failed",
		fmt.Sprintf("Error: %s", errorMsg),
		"",
		"Diagnostics:",
		diagnosticsText,
	}

	result := map[string]interface{}{
		"error":       errorMsg,
		"diagnostics": diagnosticsText,
		"method":      "Helper Process Launch",
		"success":     false,
	}

	return CommandResult{
		Result: result,
		Logs:   strings.Join(logs, "\n"),
		Status: "error",
	}
}

// waitForHelperAndReadResult waits for helper completion and reads the result with enhanced logging
func waitForHelperAndReadResult(outputPath, sessionID, timestamp string) CommandResult {
	var logs []string
	logs = append(logs, "Waiting for helper executable to complete")
	logs = append(logs, fmt.Sprintf("Monitoring output file: %s", outputPath))

	timeout := 30 * time.Second
	start := time.Now()

	for time.Since(start) < timeout {
		if _, err := os.Stat(outputPath); err == nil {
			logs = append(logs, "Output file detected, reading screenshot data")

			imageData, err := os.ReadFile(outputPath)
			if err != nil {
				errorMsg := fmt.Sprintf("Failed to read result file: %v", err)
				logs = append(logs, errorMsg)
				return createScreenCaptureError(errorMsg, logs)
			}

			os.Remove(outputPath)
			logs = append(logs, "Temporary file cleaned up")

			base64Image := base64.StdEncoding.EncodeToString(imageData)
			logs = append(logs, fmt.Sprintf("Successfully captured screenshot: %d bytes", len(imageData)))

			result := map[string]interface{}{
				"success":           true,
				"session_id":        sessionID,
				"image_size_bytes":  len(imageData),
				"image_base64_size": len(base64Image),
				"timestamp":         timestamp,
				"method":            "Helper Executable",
			}

			return CommandResult{
				Result:         result,
				Logs:           strings.Join(logs, "\n"),
				Status:         "success",
				ScreenshotData: base64Image,
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	errorMsg := "Helper executable timeout - no result file created"
	logs = append(logs, errorMsg)
	logs = append(logs, fmt.Sprintf("Waited %v for output file", timeout))
	return createScreenCaptureError(errorMsg, logs)
}

// captureScreenNative performs screen capture using pure Windows API calls
func captureScreenNative(sessionID, timestamp string) CommandResult {
	var diagnostics []string
	diagnostics = append(diagnostics, "=== NATIVE WINDOWS API SCREEN CAPTURE ===")
	diagnostics = append(diagnostics, fmt.Sprintf("Target session: %s", sessionID))
	diagnostics = append(diagnostics, fmt.Sprintf("Timestamp: %s", timestamp))

	setDPIAwareness(&diagnostics)
	screenInfo := getScreenDimensions(&diagnostics)

	virtualLeft := screenInfo.virtualLeft
	virtualTop := screenInfo.virtualTop
	virtualWidth := screenInfo.virtualWidth
	virtualHeight := screenInfo.virtualHeight

	diagnostics = append(diagnostics, fmt.Sprintf("Final screen dimensions: %dx%d at offset (%d,%d)",
		virtualWidth, virtualHeight, virtualLeft, virtualTop))

	hDesktopDC, _, err := procGetDC.Call(0)
	if hDesktopDC == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("Failed to get desktop DC: %v", err))
		return createFailureResult(diagnostics, "Failed to get desktop device context - Session 0 isolation")
	}
	defer procReleaseDC.Call(0, hDesktopDC)

	diagnostics = append(diagnostics, "Desktop DC obtained successfully")

	hMemoryDC, _, err := procCreateCompatibleDC.Call(hDesktopDC)
	if hMemoryDC == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("Failed to create compatible DC: %v", err))
		return createFailureResult(diagnostics, "Failed to create compatible device context")
	}
	defer procDeleteDC.Call(hMemoryDC)

	hBitmap, _, err := procCreateCompatibleBitmap.Call(hDesktopDC, uintptr(virtualWidth), uintptr(virtualHeight))
	if hBitmap == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("Failed to create compatible bitmap: %v", err))
		return createFailureResult(diagnostics, "Failed to create compatible bitmap")
	}
	defer procDeleteObject.Call(hBitmap)

	hOldBitmap, _, err := procSelectObject.Call(hMemoryDC, hBitmap)
	if hOldBitmap == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("Failed to select bitmap: %v", err))
		return createFailureResult(diagnostics, "Failed to select bitmap into device context")
	}
	defer procSelectObject.Call(hMemoryDC, hOldBitmap)

	result, _, err := procBitBlt.Call(
		hMemoryDC,
		0, 0,
		uintptr(virtualWidth), uintptr(virtualHeight),
		hDesktopDC,
		uintptr(virtualLeft), uintptr(virtualTop),
		SRCCOPY,
	)

	if result == 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("BitBlt failed: %v", err))
		return createFailureResult(diagnostics, "Failed to copy screen content - Session 0 isolation prevents desktop access")
	}

	diagnostics = append(diagnostics, "Screen content copied successfully")

	goImage, convertErr := convertHBitmapToImage(hBitmap, virtualWidth, virtualHeight)
	if convertErr != nil {
		diagnostics = append(diagnostics, fmt.Sprintf("Failed to convert bitmap to image: %v", convertErr))
		return createFailureResult(diagnostics, "Failed to convert bitmap to image")
	}

	resizedImage := resizeImage(goImage, 1000)
	diagnostics = append(diagnostics, fmt.Sprintf("Image resized to %dx%d",
		resizedImage.Bounds().Dx(), resizedImage.Bounds().Dy()))

	var buf bytes.Buffer
	err = jpeg.Encode(&buf, resizedImage, &jpeg.Options{Quality: 85})
	if err != nil {
		diagnostics = append(diagnostics, fmt.Sprintf("Failed to encode JPEG: %v", err))
		return createFailureResult(diagnostics, "Failed to encode image as JPEG")
	}

	imageData := buf.Bytes()
	base64Image := base64.StdEncoding.EncodeToString(imageData)

	return CommandResult{
		Output: map[string]interface{}{
			"success":             true,
			"session_id":          sessionID,
			"image_size_bytes":    len(imageData),
			"image_base64_size":   len(base64Image),
			"timestamp":           timestamp,
			"method":              "Native Windows API",
			"multi_monitor":       true,
			"diagnostics":         strings.Join(diagnostics, "\n"),
			"original_dimensions": fmt.Sprintf("%dx%d", virtualWidth, virtualHeight),
			"final_dimensions":    fmt.Sprintf("%dx%d", resizedImage.Bounds().Dx(), resizedImage.Bounds().Dy()),
			"format":              "JPEG",
			"quality":             85,
			"dpi_info":            screenInfo.dpiInfo,
		},
		Error:          "",
		Status:         "success",
		ScreenshotData: base64Image,
	}
}

// Enhanced convertHBitmapToImage that works with display driver bitmaps
func convertHBitmapToImage(hBitmap uintptr, width, height int) (image.Image, error) {
	// For display driver bitmaps, we need to use a different approach
	// Create a compatible DC and use it to read the bitmap data properly

	// Get screen DC for reference
	hScreenDC, _, _ := procGetDC.Call(0)
	if hScreenDC == 0 {
		return nil, fmt.Errorf("failed to get screen DC for conversion")
	}
	defer procReleaseDC.Call(0, hScreenDC)

	// Create a memory DC compatible with screen
	hMemDC, _, _ := procCreateCompatibleDC.Call(hScreenDC)
	if hMemDC == 0 {
		return nil, fmt.Errorf("failed to create compatible DC for conversion")
	}
	defer procDeleteDC.Call(hMemDC)

	// Create a DIB section that we can directly access
	var bmi BITMAPINFO
	bmi.Header = BITMAPINFOHEADER{
		Size:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
		Width:       int32(width),
		Height:      -int32(height), // Negative for top-down
		Planes:      1,
		BitCount:    32, // 32-bit RGBA
		Compression: BI_RGB,
	}

	var pBits uintptr
	hDIB, _, _ := procCreateDIBSection.Call(
		hScreenDC,
		uintptr(unsafe.Pointer(&bmi)),
		DIB_RGB_COLORS,
		uintptr(unsafe.Pointer(&pBits)),
		0,
		0,
	)

	if hDIB == 0 || pBits == 0 {
		return nil, fmt.Errorf("failed to create DIB section for conversion")
	}
	defer procDeleteObject.Call(hDIB)

	// Select DIB into memory DC
	hOldBitmap, _, _ := procSelectObject.Call(hMemDC, hDIB)
	defer procSelectObject.Call(hMemDC, hOldBitmap)

	// Create source DC and select our bitmap
	hSrcDC, _, _ := procCreateCompatibleDC.Call(hScreenDC)
	if hSrcDC == 0 {
		return nil, fmt.Errorf("failed to create source DC for conversion")
	}
	defer procDeleteDC.Call(hSrcDC)

	hOldSrcBitmap, _, _ := procSelectObject.Call(hSrcDC, hBitmap)
	defer procSelectObject.Call(hSrcDC, hOldSrcBitmap)

	// Copy from source bitmap to DIB section
	result, _, _ := procBitBlt.Call(
		hMemDC,
		0, 0,
		uintptr(width), uintptr(height),
		hSrcDC,
		0, 0,
		SRCCOPY,
	)

	if result == 0 {
		return nil, fmt.Errorf("failed to copy bitmap to DIB section")
	}

	// Now read the pixel data directly from DIB memory
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Calculate stride (bytes per row)
	stride := width * 4 // 32-bit = 4 bytes per pixel

	// Copy pixel data
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Calculate offset in the DIB bits
			offset := y*stride + x*4

			// Read BGRA values directly from DIB memory
			pixelPtr := unsafe.Pointer(pBits + uintptr(offset))
			b := *(*uint8)(pixelPtr)
			g := *(*uint8)(unsafe.Pointer(uintptr(pixelPtr) + 1))
			r := *(*uint8)(unsafe.Pointer(uintptr(pixelPtr) + 2))
			a := *(*uint8)(unsafe.Pointer(uintptr(pixelPtr) + 3))

			// Set pixel in Go image (convert BGRA to RGBA)
			if a == 0 {
				a = 255 // Assume opaque if alpha is 0
			}

			img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: a})
		}
	}

	return img, nil
}

// resizeImage resizes an image to the specified maximum width while maintaining aspect ratio
func resizeImage(src image.Image, maxWidth int) image.Image {
	bounds := src.Bounds()
	srcWidth := bounds.Dx()
	srcHeight := bounds.Dy()

	if srcWidth <= maxWidth {
		return src
	}

	ratio := float64(maxWidth) / float64(srcWidth)
	newWidth := maxWidth
	newHeight := int(float64(srcHeight) * ratio)

	dst := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)

	return dst
}

// setDPIAwareness sets the process to be DPI aware for accurate screen measurements
func setDPIAwareness(diagnostics *[]string) {
	result, _, err := procSetProcessDpiAwareness.Call(PROCESS_PER_MONITOR_DPI_AWARE)
	if result == 0 {
		*diagnostics = append(*diagnostics, "Successfully set DPI awareness to per-monitor")
	} else {
		*diagnostics = append(*diagnostics, fmt.Sprintf("SetProcessDpiAwareness failed: %v (this may be OK if already set)", err))
	}
}

// getScreenDimensions gets accurate screen dimensions accounting for DPI scaling
func getScreenDimensions(diagnostics *[]string) ScreenInfo {
	var info ScreenInfo

	systemDPI, _, _ := procGetDpiForSystem.Call()
	if systemDPI == 0 {
		systemDPI = 96
	}

	*diagnostics = append(*diagnostics, fmt.Sprintf("System DPI: %d", systemDPI))

	if procGetSystemMetricsForDpi.Find() == nil {
		*diagnostics = append(*diagnostics, "Using DPI-aware GetSystemMetricsForDpi")

		virtualLeft, _, _ := procGetSystemMetricsForDpi.Call(SM_XVIRTUALSCREEN, systemDPI)
		virtualTop, _, _ := procGetSystemMetricsForDpi.Call(SM_YVIRTUALSCREEN, systemDPI)
		virtualWidth, _, _ := procGetSystemMetricsForDpi.Call(SM_CXVIRTUALSCREEN, systemDPI)
		virtualHeight, _, _ := procGetSystemMetricsForDpi.Call(SM_CYVIRTUALSCREEN, systemDPI)

		info.virtualLeft = int(virtualLeft)
		info.virtualTop = int(virtualTop)
		info.virtualWidth = int(virtualWidth)
		info.virtualHeight = int(virtualHeight)
	} else {
		*diagnostics = append(*diagnostics, "GetSystemMetricsForDpi not available, using standard GetSystemMetrics")

		virtualLeft, _, _ := procGetSystemMetrics.Call(SM_XVIRTUALSCREEN)
		virtualTop, _, _ := procGetSystemMetrics.Call(SM_YVIRTUALSCREEN)
		virtualWidth, _, _ := procGetSystemMetrics.Call(SM_CXVIRTUALSCREEN)
		virtualHeight, _, _ := procGetSystemMetrics.Call(SM_CYVIRTUALSCREEN)

		info.virtualLeft = int(virtualLeft)
		info.virtualTop = int(virtualTop)
		info.virtualWidth = int(virtualWidth)
		info.virtualHeight = int(virtualHeight)
	}

	if info.virtualWidth == 0 || info.virtualHeight == 0 {
		*diagnostics = append(*diagnostics, "Virtual screen returned 0, falling back to primary screen")
		info.virtualLeft = 0
		info.virtualTop = 0

		if procGetSystemMetricsForDpi.Find() == nil {
			width, _, _ := procGetSystemMetricsForDpi.Call(SM_CXSCREEN, systemDPI)
			height, _, _ := procGetSystemMetricsForDpi.Call(SM_CYSCREEN, systemDPI)
			info.virtualWidth = int(width)
			info.virtualHeight = int(height)
		} else {
			width, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
			height, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
			info.virtualWidth = int(width)
			info.virtualHeight = int(height)
		}
	}

	scalingFactor := float64(systemDPI) / 96.0
	info.dpiInfo = fmt.Sprintf("DPI: %d, Scaling: %.1f%%", systemDPI, scalingFactor*100)

	*diagnostics = append(*diagnostics, info.dpiInfo)

	return info
}

// createFailureResult creates a standardized failure result with enhanced logging
func createFailureResult(diagnostics []string, errorMsg string) CommandResult {
	diagnosticsText := strings.Join(diagnostics, "\n")
	currentUser := os.Getenv("USERNAME")
	isSystemUser := isRunningAsSystem()

	logs := []string{
		"Native screen capture failed",
		fmt.Sprintf("Error: %s", errorMsg),
		"",
		fmt.Sprintf("Debug Info - Current user: %s, Is SYSTEM: %t", currentUser, isSystemUser),
		"",
		"Diagnostics:",
		diagnosticsText,
	}

	result := map[string]interface{}{
		"error":       errorMsg,
		"diagnostics": diagnosticsText,
		"method":      "Native Windows API",
		"debug_info":  fmt.Sprintf("Current user: %s, Is SYSTEM: %t", currentUser, isSystemUser),
		"success":     false,
	}

	return CommandResult{
		Result: result,
		Logs:   strings.Join(logs, "\n"),
		Status: "error",
	}
}

// createScreenCaptureSuccess creates a success result for screen capture with logs
func createScreenCaptureSuccess(sessionID, timestamp string, imageData string, metadata map[string]interface{}, logs []string) CommandResult {
	result := NewSuccessResult(metadata)
	result.ScreenshotData = imageData
	if len(logs) > 0 {
		result.Logs = strings.Join(logs, "\n")
	}
	return result
}

// createScreenCaptureError creates an error result for screen capture with logs
func createScreenCaptureError(errorMsg string, logs []string) CommandResult {
	if len(logs) > 0 {
		return NewErrorResultWithDetails(errorMsg, strings.Join(logs, "\n"))
	}
	return NewErrorResult(errorMsg)
}
