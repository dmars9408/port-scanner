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

func totalRealTime(m Model) time.Duration {
	if m.StartTime.IsZero() {
		return 0
	}
	return time.Since(m.StartTime)
}

//
// SERVICE, CATEGORY, EXPLOITS
//

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
