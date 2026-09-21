package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"portscanner/internal/scan"
)

type SSHConnectMsg struct {
	Client *scan.SSHClient
	System scan.RemoteSystem
	Err    string
}

type SSHRunMsg struct {
	Output string
	Err    string
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

	sshInput := textinput.New()
	sshInput.Placeholder = "Enter SSH command or number"
	sshInput.Width = 50
	sshInput.CharLimit = 200

	return Model{
		Screen:       ScreenForm,
		HostInput:    host,
		PortsInput:   ports,
		Progress:     p,
		ScannedCount: 0,
		SSHInput:     sshInput,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	switch msg := msg.(type) {

	case tea.KeyMsg:
		// Si estamos en la vista SSH, manejamos las teclas 'b' y 'q' para volver o cerrar sesión
		if m.Screen == ScreenSSH {
			switch msg.String() {

			case "b", "B":
				// Volver a la vista de resultados
				m.Screen = ScreenResults
				m.SSHManualMode = false
				m.SSHAwaitingParam = false
				m.SSHPendingCommand = nil
				m.SSHError = ""
				return m, nil

			case "q", "Q":
				// Cerrar sesión SSH y volver al summary
				if m.SSHClient == nil {
					m.SSHError = "SSH client not initialized."
					return m, nil
				}

				m.SSHClient.Close()
				m.SSHClient = nil
				m.SSHCommands = nil
				m.SSHActive = false
				m.SSHAwaitingParam = false
				m.SSHUser = ""
				m.SSHPassword = ""
				m.Screen = ScreenResults
				return m, nil

			}
		}

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

		case "i", "I":
			if m.SelectedHost.HasSSH {
				m.Screen = ScreenSSH
				m.SSHAwaitingParam = true
				m.SSHInput.Placeholder = "SSH Username"
				m.SSHInput.Focus()
				return m, nil
			}

		}

		// SSH LOGIN FLOW (username + password)
		if m.Screen == ScreenSSH && m.SSHAwaitingParam && !m.SSHActive {
			m.SSHInput, _ = m.SSHInput.Update(msg)

			if msg.String() == "enter" {

				// 1) Usuario
				if m.SSHUser == "" {
					m.SSHUser = m.SSHInput.Value()
					m.SSHInput.SetValue("")
					m.SSHInput.Placeholder = "SSH Password"
					m.SSHInput.EchoMode = textinput.EchoPassword // 🔒 oculta caracteres
					m.Viewport.SetContent("SSH Login\n\nEnter password:")
					return m, nil
				}

				// 2) Contraseña
				if m.SSHPassword == "" {
					m.SSHPassword = m.SSHInput.Value()
					m.SSHAwaitingParam = false
					m.SSHInput.EchoMode = textinput.EchoNormal // 🔓 restaura modo texto
					m.Viewport.SetContent("Connecting to SSH server...")
					return m, startSSHSessionCmd(
						m.SelectedHost.IP,
						m.SelectedHost.SSHPort,
						m.SSHUser,
						m.SSHPassword,
						m.SelectedHost.SSHBanner,
					)
				}

			}

			return m, nil
		}

		// SSH esperando parámetro
		if m.SSHActive && m.SSHAwaitingParam {
			m.SSHInput, _ = m.SSHInput.Update(msg)

			if msg.String() == "enter" {
				param := m.SSHInput.Value()
				m.SSHInput.SetValue("")

				finalCmd := fmt.Sprintf(m.SSHPendingCommand.Template, param)

				m.SSHAwaitingParam = false
				m.SSHInput.Blur()
				m.SSHPendingCommand = nil

				return m, runSSHCommandCmd(m.SSHClient, finalCmd)
			}

			return m, nil
		}

		// SSH modo manual
		if m.SSHActive && m.SSHManualMode {
			m.SSHInput, _ = m.SSHInput.Update(msg)

			if msg.String() == "enter" {
				cmd := m.SSHInput.Value()
				m.SSHInput.SetValue("")
				return m, runSSHCommandCmd(m.SSHClient, cmd)
			}

			return m, nil
		}

		// SSH modo automático con selector numérico
		if m.SSHActive && !m.SSHManualMode {
			m.SSHInput, _ = m.SSHInput.Update(msg)

			if msg.String() == "enter" {
				raw := strings.TrimSpace(m.SSHInput.Value())
				m.SSHInput.SetValue("")

				num, err := strconv.Atoi(raw)
				if err != nil {
					m.SSHOutput = fmt.Sprintf("Invalid command: %s\n", raw)
					return m, nil
				}

				cmd, exists := m.SSHCommands[num]
				if !exists {
					m.SSHOutput = fmt.Sprintf("Command %d not available.\n", num)
					return m, nil
				}

				if cmd.NeedsInput {
					m.SSHAwaitingParam = true
					m.SSHPendingCommand = &cmd
					m.SSHOutput = cmd.InputPrompt + "\n"
					return m, nil
				}

				return m, runSSHCommandCmd(m.SSHClient, cmd.Template)
			}

			return m, nil
		}

	case tea.MouseMsg:
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

	case scan.BubbleResultMsg:
		result := msg.Result
		m.Results = append(m.Results, result)
		m.ScannedCount++

		percent := float64(m.ScannedCount) / float64(len(m.Ports))
		cmd := m.Progress.SetPercent(percent)

		if result.Status == "open" && strings.Contains(strings.ToLower(result.Service), "ssh") {
			m.SelectedHost = scan.HostResult{
				IP:        m.Host,
				SSHPort:   result.Port,
				SSHBanner: result.Banner,
				HasSSH:    true,
			}
		}

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

	case scan.ScanProgressMessage:
		m.CurrentPort = msg.Port
		return m, nil

	case SSHConnectMsg:
		if msg.Err != "" {
			m.SSHError = msg.Err
			return m, nil
		}

		m.SSHClient = msg.Client
		m.SSHSystem = msg.System
		m.SSHCommands = scan.CommandsForSystem(msg.System)
		m.SSHActive = true
		m.SSHAwaitingParam = false
		m.SSHInput.Blur()
		m.SSHError = ""
		m.SSHOutput = ""

		// Vista SSH inicial
		var content strings.Builder
		content.WriteString("SSH Session Established\n\n")

		// Mostrar comandos disponibles
		content.WriteString("Available commands:\n")
		for num, cmd := range m.SSHCommands {
			content.WriteString(fmt.Sprintf("  %d) %s\n", num, cmd.InputPrompt))
		}

		// Mostrar instrucciones de navegación
		content.WriteString("\n[B] Back to results   |   [Q] Quit SSH\n")

		m.Viewport.SetContent(content.String())

		if msg.System == scan.SystemUnknown {
			m.SSHManualMode = true
			m.SSHOutput = "Remote system not recognized.\nManual mode enabled.\n"
		} else {
			m.SSHManualMode = false
		}

		return m, nil

	case SSHRunMsg:
		if msg.Err != "" {
			m.SSHError = msg.Err
		} else {
			m.SSHOutput = msg.Output
			m.SSHError = ""
		}
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
	m.Host = host
	m.Ports = ports
	m.StartTime = time.Now()
	m.Screen = ScreenScanning

	return m, scan.ScanPortsAsync(host, ports)
}

func startSSHSessionCmd(host string, port int, user, pass, banner string) tea.Cmd {
	return func() tea.Msg {
		client, err := scan.ConnectSSH(host, port, user, pass, 3*time.Second)
		if err != nil {
			return SSHConnectMsg{Err: err.Error()}
		}

		system := client.DetectRemoteSystem(banner)

		return SSHConnectMsg{
			Client: client,
			System: system,
		}
	}
}

func runSSHCommandCmd(client *scan.SSHClient, cmd string) tea.Cmd {
	return func() tea.Msg {
		out, err := client.Run(cmd)
		if err != nil {
			return SSHRunMsg{Err: err.Error()}
		}
		return SSHRunMsg{Output: out}
	}
}
