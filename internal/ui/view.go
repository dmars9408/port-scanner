package ui

import (
	"fmt"
	"portscanner/internal/scan"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// --- Vista principal ---
func (m Model) View() string {
	switch m.Screen {
	case ScreenForm:
		return formView(m)
	case ScreenScanning:
		return scanningView(m)
	case ScreenResults:
		return resultsSummaryView(m)
	case ScreenSSH:
		return sshView(m)
	}
	return ""
}

// --- Vista de formulario ---
func formView(m Model) string {
	errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555"))

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#01FF70")).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#85144b")).
		Padding(0, 2)

	return lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render("PortScanner Go v1.0"),
		"",
		"Host:",
		m.HostInput.View(),
		"",
		"Press Tab to select ports",
		"",
		"Ports:",
		m.PortsInput.View(),
		"",
		errorStyle.Render(m.ValidationError),
		"",
		"Press Enter to start scanning",
	)
}

// --- Vista de escaneo ---
func scanningView(m Model) string {
	return lipgloss.JoinVertical(lipgloss.Left,
		"Scanning "+m.Host+"...",
		"",
		fmt.Sprintf("Current port: %d", m.CurrentPort),
		"",
		m.Progress.View(),
		"",
		fmt.Sprintf("%d/%d ports scanned", m.ScannedCount, len(m.Ports)),
	)
}

// --- Vista de resultados (tabla simple) ---
func resultsView(m Model) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%-7s %-8s %-8s %-6s\n", "PORT", "PROTOCOL", "STATUS", "TIME")

	for _, r := range m.Results {
		fmt.Fprintf(&b, "%-7d %-8s %-8s %-6s\n",
			r.Port,
			strings.ToUpper(r.Protocol),
			strings.ToUpper(r.Status),
			r.ResponseTime.String())
	}

	var openCount, closedCount int
	for _, r := range m.Results {
		if r.Status == "open" {
			openCount++
		} else {
			closedCount++
		}
	}

	fmt.Fprintf(&b, "\nTOTAL: %d, OPEN: %d, CLOSED: %d\n", len(m.Results), openCount, closedCount)

	if len(m.Results) > 0 {
		startTime := m.Results[0].Timestamp
		endTime := m.Results[len(m.Results)-1].Timestamp
		total := endTime.Sub(startTime)
		fmt.Fprintf(&b, "Total scan time: %s\n", total.String())
	}

	return b.String()
}

func resultsSummaryView(m Model) string {
	return m.Viewport.View()
}

// --- Estilos base tabla ---
func resultsSummaryContent(m Model) string {

	var left strings.Builder

	left.WriteString(TitleStyle.Render("Scan Summary"))
	left.WriteString("\n")

	fmt.Fprintf(&left, "%s %s\n", LabelStyle.Render("Host:"), ValueStyle.Render(m.Host))
	fmt.Fprintf(&left, "%s %d\n", LabelStyle.Render("Total ports:"), len(m.Results))
	fmt.Fprintf(&left, "%s %d\n", LabelStyle.Render("Open:"), scan.CountOpen(m.Results))
	fmt.Fprintf(&left, "%s %d\n", LabelStyle.Render("Closed:"), scan.CountClosed(m.Results))
	fmt.Fprintf(&left, "%s %s\n", LabelStyle.Render("Real time:"), totalRealTime(m))
	fmt.Fprintf(&left, "%s %s\n", LabelStyle.Render("Sum time:"), scan.TotalAccumulatedTime(m.Results))

	leftBox := BoxStyle.Render(left.String())

	var right strings.Builder

	right.WriteString(TitleStyle.Render("Actions"))
	right.WriteString("\n")
	right.WriteString("  R - Run another scan\n")
	right.WriteString("  S - Save log\n")
	right.WriteString("  Q - Quit\n")

	if m.SelectedHost.HasSSH {
		right.WriteString("  I - Start SSH session\n")
	}

	if m.LogMessages != "" {
		right.WriteString("\n")
		right.WriteString(LogStyle.Render(m.LogMessages))
		right.WriteString("\n")
	}

	rightBox := BoxStyle.Render(right.String())

	gap := lipgloss.NewStyle().Width(25).Render("")
	topRow := lipgloss.JoinHorizontal(lipgloss.Top, leftBox, gap, rightBox)

	var table strings.Builder

	table.WriteString(TitleStyle.Render("SCAN RESULTS"))
	table.WriteString("\n")

	fmt.Fprintf(&table,
		"%s\n",
		HeaderStyle.Render(fmt.Sprintf(
			"%-6s %-8s %-10s %-12s %-15s %-12s %-8s %-45s",
			"PORT", "PROTO", "STATUS", "SERVICE", "PRODUCT", "CATEGORY", "RISK", "INFO",
		)),
	)

	for _, r := range m.Results {
		status := strings.ToUpper(r.Status)
		protocol := strings.ToUpper(r.Protocol)
		service := scan.DetectService(r.Port)
		product := scan.DetectServiceFromBanner(r.Banner)
		category := scan.ServiceCategory(service)
		level := scan.RiskLevel(r.Port, status, r.ResponseTime)
		explanation := scan.RiskExplanation(r.Port, status, r.ResponseTime)

		var statusColored string

		switch status {
		case "OPEN":
			statusColored = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true).Render(status)
		case "CLOSED":
			statusColored = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true).Render(status)
		case "TIMEOUT":
			statusColored = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFF00")).Bold(true).Render(status)
		case "DNS_ERROR":
			statusColored = lipgloss.NewStyle().Foreground(lipgloss.Color("#00AFFF")).Bold(true).Render(status)
		case "REFUSED":
			statusColored = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8800")).Bold(true).Render(status)
		case "UNREACHABLE":
			statusColored = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA")).Bold(true).Render(status)
		default:
			statusColored = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Render(status)
		}

		riskColored := lipgloss.NewStyle().Foreground(riskColor(level)).Bold(true).Render(level)

		fmt.Fprintf(&table, "%s %s %s %s %s %s %s %s\n",
			pad(fmt.Sprintf("%d", r.Port), 6),
			pad(protocol, 8),
			pad(statusColored, 10),
			pad(service, 12),
			pad(product, 15),
			pad(category, 12),
			pad(riskColored, 8),
			pad(explanation, 45),
		)
	}

	bottomBox := BoxStyle.Render(table.String())

	return lipgloss.JoinVertical(lipgloss.Top, topRow, bottomBox)
}

// --- Vista SSH corregida ---
func sshView(m Model) string {
	var b strings.Builder

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00AFFF"))
	b.WriteString(title.Render("SSH Session"))
	b.WriteString("\n\n")

	// Mostrar contenido del viewport (comandos + output)
	b.WriteString(m.Viewport.View())
	b.WriteString("\n\n")

	// Mostrar errores
	if m.SSHError != "" {
		errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555"))
		b.WriteString(errStyle.Render(m.SSHError))
		b.WriteString("\n\n")
	}

	// Mostrar output
	if m.SSHOutput != "" {
		outStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA"))
		b.WriteString(outStyle.Render(m.SSHOutput))
		b.WriteString("\n\n")
	}

	// Input SIEMPRE visible
	b.WriteString("> ")
	b.WriteString(m.SSHInput.View())

	return b.String()
}
