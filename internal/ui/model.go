package ui

import (
	"portscanner/internal/scan"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
)

type ScreenType int

const (
	ScreenForm ScreenType = iota
	ScreenScanning
	ScreenResults
)

type Model struct {
	Screen          ScreenType
	HostInput       textinput.Model
	PortsInput      textinput.Model
	ValidationError string

	Host  string
	Ports []int

	Results []scan.PortScanResult

	Progress     progress.Model
	ScannedCount int

	CurrentPort int

	LogMessages string

	Viewport viewport.Model
}
