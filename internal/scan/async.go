package scan

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

/*
async.go permite escanear los puertos de manera asíncrona, o sea, sin bloquear
la interfaz BubbleTea.
BubbleTea es un framework de terminal basado en el patrón de diseño
Model-View-Controller, que funciona como un sistema de comandos y mensajes.
Este archhivo async.go crea esos comandos.
*/

type BubbleResultMsg struct {
	Result PortScanResult
}

type ScanProgressMessage struct {
	Port int
}

func ScanPortsAsync(host string, ports []int) tea.Cmd {
	var cmds []tea.Cmd

	for _, port := range ports {
		p := port
		cmds = append(cmds,
			func() tea.Msg {
				//Primero avisamos qué puerto se está escaneando
				return ScanProgressMessage{Port: p}
			},
			func() tea.Msg {
				//Luego enviamos el resultado real
				result := ScanPort(host, p, 500*time.Millisecond)
				return BubbleResultMsg{Result: result}
			},
		)
	}

	return tea.Batch(cmds...)
}

// Esta función crea un slice de comandos, uno por cada puerto
func funcsForPorts(host string, ports []int) []tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(ports)*2) // dos comandos por puerto

	for _, port := range ports {
		p := port

		//Primero: mensaje de progreso
		cmds = append(cmds, func() tea.Msg {
			return ScanProgressMessage{Port: p}
		})

		//Segundo: resultado del escaneo
		cmds = append(cmds, func() tea.Msg {
			result := ScanPort(host, p, 500*time.Millisecond)
			return BubbleResultMsg{Result: result}
		})
	}

	return cmds
}
