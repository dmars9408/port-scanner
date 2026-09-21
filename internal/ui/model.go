package ui

import (
	"portscanner/internal/scan"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
)

type ScreenType int

const (
	ScreenForm ScreenType = iota
	ScreenScanning
	ScreenResults
	ScreenSSH
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

	Viewport  viewport.Model
	StartTime time.Time

	SSHClient         *scan.SSHClient
	SSHSystem         scan.RemoteSystem
	SSHOutput         string
	SSHError          string
	SSHActive         bool
	SSHUser           string
	SSHPassword       string
	SSHManualMode     bool
	SSHInput          textinput.Model
	SSHAwaitingParam  bool
	SSHCommands       map[int]scan.SecurityCommand
	SSHPendingCommand *scan.SecurityCommand

	SelectedHost scan.HostResult
}
