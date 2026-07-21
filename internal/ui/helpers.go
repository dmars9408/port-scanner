package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"portscanner/internal/scan"

	"github.com/charmbracelet/lipgloss"
)

//
// LOGGING
//

func saveLog(results []scan.PortScanResult) (string, error) {
	filename := fmt.Sprintf("scan_%d.log", time.Now().Unix())

	f, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("cannot create log file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	if _, err := fmt.Fprintf(w, "[%s] Scan results\n", time.Now().Format(time.RFC3339)); err != nil {
		return "", fmt.Errorf("cannot write log header: %w", err)
	}

	for _, r := range results {
		if _, err := fmt.Fprintf(w, "%s %d/%s %s %s\n",
			r.Timestamp.Format(time.RFC3339),
			r.Port,
			strings.ToUpper(r.Protocol),
			strings.ToUpper(r.Status),
			r.ResponseTime.String(),
		); err != nil {
			return "", fmt.Errorf("cannot write log entry: %w", err)
		}
	}

	if err := w.Flush(); err != nil {
		return "", fmt.Errorf("cannot flush log buffer: %w", err)
	}

	return filename, nil
}

//
// METRICS
//

func countOpen(results []scan.PortScanResult) int {
	n := 0
	for _, r := range results {
		if strings.EqualFold(r.Status, "OPEN") {
			n++
		}
	}
	return n
}

func countClosed(results []scan.PortScanResult) int {
	n := 0
	for _, r := range results {
		if strings.EqualFold(r.Status, "CLOSED") {
			n++
		}
	}
	return n
}

func totalRealTime(results []scan.PortScanResult) time.Duration {
	if len(results) == 0 {
		return 0
	}

	min := results[0].Timestamp
	max := results[0].Timestamp

	for _, r := range results {
		if r.Timestamp.Before(min) {
			min = r.Timestamp
		}
		if r.Timestamp.After(max) {
			max = r.Timestamp
		}
	}

	return max.Sub(min)
}

func totalAccumulatedTime(results []scan.PortScanResult) time.Duration {
	var sum time.Duration
	for _, r := range results {
		sum += r.ResponseTime
	}
	return sum
}

//
// SERVICE, CATEGORY, EXPLOITS
//

func detectService(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "TELNET",
		53:   "DNS",
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB",
		3306: "MYSQL",
	}

	if s, ok := services[port]; ok {
		return s
	}
	return "UNKNOWN"
}

func serviceCategory(service string) string {
	switch service {
	case "HTTP", "HTTPS":
		return "WEB"
	case "SSH", "TELNET":
		return "INFRA"
	case "MYSQL":
		return "DATABASE"
	case "FTP", "SMB":
		return "LEGACY"
	default:
		return "UNKNOWN"
	}
}

func exploitKnown(port int) string {
	switch port {
	case 21:
		return "FTP exploits (bruteforce, cleartext credentials)"
	case 22:
		return "SSH bruteforce / misconfigurations"
	case 23:
		return "TELNET exploits (cleartext, RCE)"
	case 445:
		return "SMB exploits (EternalBlue, WannaCry)"
	case 3306:
		return "MySQL exploits (weak auth, RCE)"
	default:
		return "No common exploits"
	}
}

//
// RISK LEVEL + EXPLANATION + BAR
//

func riskLevel(port int, status string, response time.Duration) string {
	status = strings.ToUpper(status)

	if status != "OPEN" {
		return "LOW"
	}

	if response > 2*time.Second {
		return "LOW (Honeypot suspected)"
	}

	service := detectService(port)
	category := serviceCategory(service)

	switch category {
	case "LEGACY":
		return "CRITICAL"
	case "INFRA", "DATABASE":
		return "HIGH"
	case "WEB":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func riskExplanation(port int, status string, response time.Duration) string {
	level := riskLevel(port, status, response)
	service := detectService(port)
	category := serviceCategory(service)
	exploit := exploitKnown(port)

	switch {
	case strings.HasPrefix(level, "CRITICAL"):
		return fmt.Sprintf("%s exposed (%s). Known exploits: %s",
			service, category, exploit)
	case strings.HasPrefix(level, "HIGH"):
		return fmt.Sprintf("%s service exposed (%s). Potential exploits: %s",
			service, category, exploit)
	case strings.HasPrefix(level, "MEDIUM"):
		return fmt.Sprintf("%s service exposed. Common web vulnerabilities may apply.",
			service)
	case strings.Contains(level, "Honeypot"):
		return "Slow response suggests honeypot or tarpitting behavior."
	default:
		return "Closed or non-sensitive service."
	}
}

func riskBar(level string) string {
	level = strings.ToUpper(level)

	var filled int
	switch {
	case strings.HasPrefix(level, "CRITICAL"):
		filled = 10
	case strings.HasPrefix(level, "HIGH"):
		filled = 7
	case strings.HasPrefix(level, "MEDIUM"):
		filled = 5
	default:
		filled = 2
	}

	empty := 10 - filled
	return fmt.Sprintf("[%s%s]",
		strings.Repeat("■", filled),
		strings.Repeat("□", empty),
	)
}

//
// COLORS
//

func riskColor(level string) lipgloss.Color {
	level = strings.ToUpper(level)

	switch {
	case strings.HasPrefix(level, "CRITICAL"):
		return lipgloss.Color("#FF0000")
	case strings.HasPrefix(level, "HIGH"):
		return lipgloss.Color("#FF4500")
	case strings.HasPrefix(level, "MEDIUM"):
		return lipgloss.Color("#FFA500")
	default:
		return lipgloss.Color("#00FF00")
	}
}

func pad(s string, width int) string {
	visible := lipgloss.Width(s)
	if visible < width {
		return s + strings.Repeat(" ", width-visible)
	}
	return s
}
