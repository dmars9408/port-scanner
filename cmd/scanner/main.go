package main

import (
	"log"
	"portscanner/internal/ui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	p := tea.NewProgram(
		ui.InitialModel(),
		tea.WithMouseCellMotion(), // habilita soporte de ratón
	)

	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
