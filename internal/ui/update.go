package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"portscanner/internal/scan" // <-- ajusta el import si tu módulo tiene otro nombre
)

type ScanProgressMessage struct {
	Port int
}

func InitialModel() Model {
	host := textinput.New()
	host.Placeholder = "example.com or x.x.x.x"
	host.Focus()
	host.Width = 30

	ports := textinput.New()
	ports.Placeholder = "80,443,1-100"
	ports.Width = 30
	p := progress.New(progress.WithDefaultScaledGradient())
	return Model{
		Screen:       ScreenForm,
		HostInput:    host,
		PortsInput:   ports,
		Progress:     p,
		ScannedCount: 0,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {

		case "up":
			if m.Screen == ScreenResults {
				m.Viewport.ScrollUp(1)
			}
		case "down":
			if m.Screen == ScreenResults {
				m.Viewport.ScrollDown(1)
			}
		case "pgup":
			if m.Screen == ScreenResults {
				m.Viewport.ScrollUp(10)
			}
		case "pgdown":
			if m.Screen == ScreenResults {
				m.Viewport.ScrollDown(10)
			}

		case "tab":
			if m.HostInput.Focused() {
				m.HostInput.Blur()
				m.PortsInput.Focus()
			} else {
				m.PortsInput.Blur()
				m.HostInput.Focus()
			}
			return m, nil
		case "enter":
			if m.Screen == ScreenForm {
				return validateForm(m)
			}
		case "esc":
			return m, tea.Quit

		case "r":
			if m.Screen == ScreenResults {
				m.Results = nil
				m.ScannedCount = 0
				m.Screen = ScreenForm
				return m, nil
			}

		case "s":
			if m.Screen == ScreenResults {
				filename, err := saveLog(m.Results)
				if err != nil {
					m.LogMessages = fmt.Sprintf("Error saving log: %v", err)
				} else {
					m.LogMessages = fmt.Sprintf("Log saved to %s", filename)
				}
				return m, nil
			}

		case "q":
			if m.Screen == ScreenResults {
				return m, tea.Quit
			}

		}
	case tea.MouseMsg: //no esta funcionando
		if m.Screen == ScreenResults {
			var cmd tea.Cmd
			m.Viewport, cmd = m.Viewport.Update(msg)
			switch msg.Button {
			case tea.MouseButtonWheelUp:
				m.Viewport.ScrollUp(3)
			case tea.MouseButtonWheelDown:
				m.Viewport.ScrollDown(3)
			}
			return m, cmd
		}

	case scan.BubbleResultMsg: // CAMBIO
		// Aquí recibes un resultado real
		result := msg.Result

		// Aquí guardas resultados en tu modelo (lo añadimos)
		m.Results = append(m.Results, result)

		// Actualizar contador
		m.ScannedCount++

		// Calcular porcentaje
		percent := float64(m.ScannedCount) / float64(len(m.Ports))

		// Actualizar barra
		cmd := m.Progress.SetPercent(percent)

		// Cuando ya tengas todos los resultados, cambias de pantalla
		if len(m.Results) == len(m.Ports) {
			sort.Slice(m.Results, func(i, j int) bool {
				return m.Results[i].Port < m.Results[j].Port
			})

			m.Screen = ScreenResults

			m.Viewport = viewport.New(100, 30)
			m.Viewport.YPosition = 0
			m.Viewport.SetContent(resultsSummaryContent(m))
		}

		return m, cmd

	case ScanProgressMessage:
		m.CurrentPort = msg.Port
		return m, nil

	}

	var cmd tea.Cmd
	m.HostInput, _ = m.HostInput.Update(msg)
	m.PortsInput, _ = m.PortsInput.Update(msg)

	return m, cmd
}

func validateForm(m Model) (tea.Model, tea.Cmd) {
	host := strings.TrimSpace(m.HostInput.Value())
	portsRaw := strings.TrimSpace(m.PortsInput.Value())

	if host == "" {
		m.ValidationError = "Host cannot be empty"
		return m, nil
	}

	ports, err := scan.ParsePorts(portsRaw)
	if err != nil {
		m.ValidationError = err.Error()
		return m, nil
	}

	m.ValidationError = ""
	m.Screen = ScreenScanning
	m.Host = host
	m.Ports = ports

	return m, scan.ScanPortsAsync(host, ports)
}
