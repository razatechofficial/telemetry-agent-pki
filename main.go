package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type TemplateStats struct {
	Issued  int `json:"issued"`
	Failed  int `json:"failed"`
	Revoked int `json:"revoked"`
}

type CAData struct {
	CA        string                    `json:"ca"`
	Templates map[string]*TemplateStats `json:"templates"`
}

type Telemetry struct {
	Timestamp time.Time `json:"timestamp"`
	CAs       []CAData  `json:"cas"`
}

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
			// tmpl := strings.TrimSpace(strings.TrimPrefix(line, "Certificate Template:"))
			// tmpl := strings.TrimSpace(strings.SplitN(line, "Certificate Template:", 2)[1])
			// tmpl = strings.Trim(tmpl, `"`)
			// counts[tmpl]++

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

func telemetryHandler(w http.ResponseWriter, r *http.Request) {
	cas, err := discoverCAs()
	if err != nil {
		http.Error(w, "Failed to discover CAs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	dispositions := map[string]string{"20": "Issued", "30": "Failed", "21": "Revoked"}
	result := Telemetry{Timestamp: time.Now()}

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
		result.CAs = append(result.CAs, caData)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	http.HandleFunc("/telemetry", telemetryHandler)
	fmt.Println("Listening on http://localhost:8080/telemetry")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
