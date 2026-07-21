package scan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func ParsePorts(input string) ([]int, error) {
	parts := strings.Split(input, ",")
	var ports []int
	cleandouble := make(map[int]bool) // para evitar duplicados

	for _, part := range parts { // rango
		part = strings.TrimSpace(part)
		//rango -
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			startInput := strings.TrimSpace(bounds[0]) // inicio
			endInput := strings.TrimSpace(bounds[1])   // fin

			start, err := strconv.Atoi(startInput) // convierte a int
			if err != nil {                        // si hay error
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			end, err := strconv.Atoi(endInput)
			if err != nil {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("port range out of bounds: %s", part)
			}
			for i := start; i <= end; i++ { // recorre el rango
				if !cleandouble[i] { // si no esta en el map
					ports = append(ports, i) // agrega al slice
					cleandouble[i] = true    // agrega al map
				}
			}
		} else { // sin rango
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			if !cleandouble[port] {
				ports = append(ports, port)
				cleandouble[port] = true
			}
		}
	}
	sort.Ints(ports)
	return ports, nil
}
