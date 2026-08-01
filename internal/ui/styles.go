package ui

import "github.com/charmbracelet/lipgloss"

// --- Estilos globales para la interfaz ---

var TitleStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#00AFFF")).
	PaddingBottom(1)

var BoxStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.Color("#555555")).
	Padding(1, 2)

var LabelStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#AAAAAA"))

var ValueStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#FFFFFF"))

var LogStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#00FF00")).
	Bold(true)

var HeaderStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#00AFFF"))
