package scan

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type BubbleResultMsg struct {
	Result PortScanResult
}

func ScanPortsAsync(host string, ports []int) tea.Cmd {
	return tea.Batch(
		// Generamos un comando por cada puerto
		funcsForPorts(host, ports)...,
	)
}

// Esta función crea un slice de comandos, uno por cada puerto
func funcsForPorts(host string, ports []int) []tea.Cmd {
	cmds := make([]tea.Cmd, len(ports))
	for i, port := range ports {
		cmds[i] = func() tea.Msg {
			result := ScanPort(host, port, 500*time.Millisecond)
			return BubbleResultMsg{Result: result}
		}
	}
	return cmds
}
