package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// PlatformStats represents statistics for a specific platform
type PlatformStats struct {
	OS           string                 `json:"os"`
	Architecture string                 `json:"architecture"`
	Hostname     string                 `json:"hostname"`
	Uptime       string                 `json:"uptime"`
	CPUInfo      map[string]interface{} `json:"cpu_info"`
	MemoryInfo   map[string]interface{} `json:"memory_info"`
	DiskInfo     map[string]interface{} `json:"disk_info"`
	NetworkInfo  map[string]interface{} `json:"network_info"`
	ProcessCount int                    `json:"process_count"`
}

// Windows-specific stats (existing CA functionality)
type TemplateStats struct {
	Issued  int `json:"issued"`
	Failed  int `json:"failed"`
	Revoked int `json:"revoked"`
}

type CAData struct {
	CA        string                    `json:"ca"`
	Templates map[string]*TemplateStats `json:"templates"`
}

type WindowsTelemetry struct {
	Timestamp time.Time     `json:"timestamp"`
	Platform  PlatformStats `json:"platform"`
	CAs       []CAData      `json:"cas"`
}

type Telemetry struct {
	Timestamp time.Time     `json:"timestamp"`
	Platform  PlatformStats `json:"platform"`
	Data      interface{}   `json:"data"`
}

// getPlatformStats returns platform-specific statistics
func getPlatformStats() (PlatformStats, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	stats := PlatformStats{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		Hostname:     hostname,
		CPUInfo:      make(map[string]interface{}),
		MemoryInfo:   make(map[string]interface{}),
		DiskInfo:     make(map[string]interface{}),
		NetworkInfo:  make(map[string]interface{}),
	}

	// Get uptime
	uptime, err := getUptime()
	if err == nil {
		stats.Uptime = uptime
	}

	// Get CPU info
	cpuInfo, err := getCPUInfo()
	if err == nil {
		stats.CPUInfo = cpuInfo
	}

	// Get memory info
	memInfo, err := getMemoryInfo()
	if err == nil {
		stats.MemoryInfo = memInfo
	}

	// Get disk info
	diskInfo, err := getDiskInfo()
	if err == nil {
		stats.DiskInfo = diskInfo
	}

	// Get network info
	netInfo, err := getNetworkInfo()
	if err == nil {
		stats.NetworkInfo = netInfo
	}

	// Get process count
	processCount, err := getProcessCount()
	if err == nil {
		stats.ProcessCount = processCount
	}

	return stats, nil
}

// getUptime returns system uptime
func getUptime() (string, error) {
	switch runtime.GOOS {
	case "windows":
		_, err := exec.Command("wmic", "os", "get", "LastBootUpTime", "/value").Output()
		if err != nil {
			return "", err
		}
		// Parse Windows uptime (simplified)
		return "Windows uptime available", nil
	case "linux":
		out, err := exec.Command("uptime", "-p").Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	case "darwin":
		out, err := exec.Command("uptime").Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	default:
		return "Unknown OS", nil
	}
}

// getCPUInfo returns CPU information
func getCPUInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})

	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors", "/value").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "linux":
		out, err := exec.Command("cat", "/proc/cpuinfo").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
		if err == nil {
			info["brand"] = strings.TrimSpace(string(out))
		}
		out2, err := exec.Command("sysctl", "-n", "hw.ncpu").Output()
		if err == nil {
			info["cores"] = strings.TrimSpace(string(out2))
		}
	}

	info["num_cpu"] = runtime.NumCPU()
	return info, nil
}

// getMemoryInfo returns memory information
func getMemoryInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})

	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("wmic", "computersystem", "get", "TotalPhysicalMemory", "/value").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "linux":
		out, err := exec.Command("cat", "/proc/meminfo").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			info["total_memory"] = strings.TrimSpace(string(out))
		}
	}

	return info, nil
}

// getDiskInfo returns disk information
func getDiskInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})

	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("wmic", "logicaldisk", "get", "Size,FreeSpace,DeviceID", "/value").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "linux":
		out, err := exec.Command("df", "-h").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "darwin":
		out, err := exec.Command("df", "-h").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	}

	return info, nil
}

// getNetworkInfo returns network information
func getNetworkInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})

	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("ipconfig").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "linux":
		out, err := exec.Command("ip", "addr").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	case "darwin":
		out, err := exec.Command("ifconfig").Output()
		if err == nil {
			info["raw_data"] = string(out)
		}
	}

	return info, nil
}

// getProcessCount returns the number of running processes
func getProcessCount() (int, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("tasklist", "/FO", "CSV").Output()
		if err != nil {
			return 0, err
		}
		lines := strings.Split(string(out), "\n")
		return len(lines) - 1, nil // Subtract header
	case "linux":
		out, err := exec.Command("ps", "-e", "--no-headers").Output()
		if err != nil {
			return 0, err
		}
		lines := strings.Split(string(out), "\n")
		count := 0
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		return count, nil
	case "darwin":
		out, err := exec.Command("ps", "-e", "--no-headers").Output()
		if err != nil {
			return 0, err
		}
		lines := strings.Split(string(out), "\n")
		count := 0
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		return count, nil
	default:
		return 0, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Windows-specific CA functions (existing code)
func discoverCAs() ([]string, error) {
	out, err := exec.Command("certutil", "-dump").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("certutil -dump failed: %v\n%s", err, out)
	}

	lines := strings.Split(string(out), "\n")
	var cas []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Config:") {
			// Extract the part after "Config:" and strip surrounding quotes if present
			cfg := strings.TrimPrefix(trimmed, "Config:")
			cfg = strings.TrimSpace(cfg)
			cfg = strings.Trim(cfg, `"`) // Remove quotes
			cas = append(cas, cfg)
		}
	}

	return cas, nil
}

func getTemplateStats(caConfig, disposition string) (map[string]int, error) {
	args := []string{
		"-config", caConfig,
		"-view",
		"-restrict", "Disposition=" + disposition,
		"-out", "CertificateTemplate",
	}
	out, err := exec.Command("certutil", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("certutil error: %v\n%s", err, out)
	}

	counts := make(map[string]int)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Certificate Template:") {
			// Extract only the value after "Certificate Template:"
			tmpl := strings.SplitN(line, "Certificate Template:", 2)[1]
			tmpl = strings.TrimSpace(tmpl)
			tmpl = strings.Trim(tmpl, `"`)           // remove quotes
			tmpl = strings.ReplaceAll(tmpl, `"`, "") // remove any lingering quotes inside
			counts[tmpl]++
		}
	}
	return counts, nil
}

// getWindowsCAData returns Windows CA data
func getWindowsCAData() ([]CAData, error) {
	cas, err := discoverCAs()
	if err != nil {
		return nil, err
	}

	dispositions := map[string]string{"20": "Issued", "30": "Failed", "21": "Revoked"}
	var result []CAData

	for _, ca := range cas {
		caData := CAData{CA: ca, Templates: make(map[string]*TemplateStats)}
		for code, label := range dispositions {
			stats, err := getTemplateStats(ca, code)
			if err != nil {
				log.Printf("Error getting stats for CA %s, disposition %s: %v", ca, label, err)
				continue
			}
			for tmpl, count := range stats {
				if _, exists := caData.Templates[tmpl]; !exists {
					caData.Templates[tmpl] = &TemplateStats{}
				}
				switch label {
				case "Issued":
					caData.Templates[tmpl].Issued = count
				case "Failed":
					caData.Templates[tmpl].Failed = count
				case "Revoked":
					caData.Templates[tmpl].Revoked = count
				}
			}
		}
		result = append(result, caData)
	}

	return result, nil
}

// getLinuxData returns Linux-specific data
func getLinuxData() (map[string]interface{}, error) {
	data := make(map[string]interface{})

	// Get system load
	if out, err := exec.Command("cat", "/proc/loadavg").Output(); err == nil {
		data["load_average"] = strings.TrimSpace(string(out))
	}

	// Get kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		data["kernel_version"] = strings.TrimSpace(string(out))
	}

	// Get distribution info
	if out, err := exec.Command("cat", "/etc/os-release").Output(); err == nil {
		data["distribution"] = strings.TrimSpace(string(out))
	}

	// Get running services
	if out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager").Output(); err == nil {
		data["running_services"] = strings.TrimSpace(string(out))
	}

	return data, nil
}

// getDarwinData returns macOS-specific data
func getDarwinData() (map[string]interface{}, error) {
	data := make(map[string]interface{})

	// Get macOS version
	if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		data["macos_version"] = strings.TrimSpace(string(out))
	}

	// Get system load
	if out, err := exec.Command("uptime").Output(); err == nil {
		data["uptime"] = strings.TrimSpace(string(out))
	}

	// Get running applications
	if out, err := exec.Command("ps", "aux").Output(); err == nil {
		data["running_processes"] = strings.TrimSpace(string(out))
	}

	return data, nil
}

func telemetryHandler(w http.ResponseWriter, r *http.Request) {
	// Get platform stats
	platformStats, err := getPlatformStats()
	if err != nil {
		log.Printf("Error getting platform stats: %v", err)
		platformStats = PlatformStats{
			OS:           runtime.GOOS,
			Architecture: runtime.GOARCH,
			Hostname:     "unknown",
		}
	}

	// Get platform-specific data
	var platformData interface{}

	switch runtime.GOOS {
	case "windows":
		caData, err := getWindowsCAData()
		if err != nil {
			log.Printf("Error getting Windows CA data: %v", err)
			platformData = map[string]string{"error": "Failed to get CA data"}
		} else {
			platformData = caData
		}
	case "linux":
		linuxData, err := getLinuxData()
		if err != nil {
			log.Printf("Error getting Linux data: %v", err)
			platformData = map[string]string{"error": "Failed to get Linux data"}
		} else {
			platformData = linuxData
		}
	case "darwin":
		darwinData, err := getDarwinData()
		if err != nil {
			log.Printf("Error getting macOS data: %v", err)
			platformData = map[string]string{"error": "Failed to get macOS data"}
		} else {
			platformData = darwinData
		}
	default:
		platformData = map[string]string{"message": "Unsupported operating system"}
	}

	result := Telemetry{
		Timestamp: time.Now(),
		Platform:  platformStats,
		Data:      platformData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	http.HandleFunc("/telemetry", telemetryHandler)
	fmt.Printf("Telemetry agent starting on http://localhost:8080/telemetry\n")
	fmt.Printf("Detected OS: %s, Architecture: %s\n", runtime.GOOS, runtime.GOARCH)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
