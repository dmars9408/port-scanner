package main

import (
	"flag"
	"fmt"
	"os"
	"portscanner/internal/scan"
	"strconv"
	"strings"
	"time"
)

const (
	Cyan    = "\033[36m"
	Green   = "\033[32m"
	Red     = "\033[31m"
	Yellow  = "\033[33m"
	Magenta = "\033[35m"
	Reset   = "\033[0m"
)

func animateBanner() {
	banner := "=== PortScanner Go v1.0 ==="
	fmt.Print("\033[H") //mover cursor a la primera linea

	for i := 0; i < 20; i++ {
		fmt.Print("\033[K") //borrar linea
		fmt.Printf("%s%s%s%s", Cyan, strings.Repeat(" ", i), banner, Reset)
		time.Sleep(40 * time.Millisecond)
	}
	fmt.Print("\033[s")
}

func fixBanner() {
	fmt.Print("\033[H") // ir a la primera línea
	fmt.Print("\033[K") // borrar línea
	fmt.Println(Cyan + "=== PortScanner Go v1.0 ===" + Reset)

	// Guardar posición del cursor justo debajo del banner
	fmt.Print("\033[s")
}

func updateBanner(text string) {
	fmt.Print("\033[u") // restaurar posición guardada
	fmt.Print("\033[H") // ir a la primera línea
	fmt.Print("\033[K") // borrar línea
	fmt.Println(Cyan + text + Reset)
	fmt.Print("\033[s") // guardar posición de nuevo
}

func main() {
	host := flag.String("host", "", "Host name or ip address")
	ports := flag.String("ports", "", "Ports to scan separated by commas")
	timeout := flag.Duration("timeout", 2*time.Second, "Timeout for each port scan")
	maxConcurrency := flag.Int("max-concurrency", 100, "Max number of goroutines to use for scanning")
	flag.Parse()

	//animar banner
	animateBanner()
	fixBanner()

	//modo interactivo si no se pasan flags
	if flag.NFlag() == 0 {
		//updateBanner("Guide mode — please enter scan parameters ▸")
		fmt.Println(Cyan + "=== PortScanner Go v1.0 ===" + Reset)
		fmt.Println("Guide mode — please enter scan parameters ▸")

		var hostInput string
		var portsInput string

		fmt.Print("Enter hostname or ip address: ")
		fmt.Scanln(&hostInput)

		fmt.Print("Enter ports to scan separated by commas: ")
		fmt.Scanln(&portsInput)
		//sobreescribimos los flags
		*host = hostInput
		*ports = portsInput
	}

	//validaciones
	if *host == "" {
		fmt.Println("Missing hostname or ip address")
		os.Exit(1)
	}
	if *ports == "" {
		fmt.Println("Missing ports to scan")
		os.Exit(1)
	}
	split := strings.Split(*ports, ",")
	var portsInt []int
	for _, port := range split {
		portlist := strings.TrimSpace(port)
		portInt, err := strconv.Atoi(portlist)
		if err != nil {
			fmt.Println("Invalid port:", portlist)
			os.Exit(1)
		}
		if portInt < 1 || portInt > 65535 {
			fmt.Println("Invalid port:", portInt)
			os.Exit(1)
		}

		portsInt = append(portsInt, portInt)
	}
	//escaneo
	updateBanner("Scanning ports...")
	results := scan.ScanPorts(*host, portsInt, *timeout, *maxConcurrency)
	fmt.Printf("%-7s %-8s %-10s %-10s %-s\n", "PORT", "PROTO", "STATUS", "TIME", "ERROR")
	fmt.Println(strings.Repeat("-", 55))

	//imprimir resultados
	updateBanner("Scan completed!")
	for _, r := range results {
		errMsg := "-"
		if r.Error != "" {
			errMsg = r.Error
		}
		//status color
		statusColor := r.Status
		switch strings.ToLower(r.Status) {
		case "open":
			statusColor = Green + r.Status + Reset
		case "closed":
			statusColor = Red + r.Status + Reset
		case "filtered":
			statusColor = Yellow + r.Status + Reset
		case "timedout":
			statusColor = Yellow + r.Status + Reset
		case "error":
			statusColor = Magenta + r.Status + Reset
		default:
			statusColor = Cyan + r.Status + Reset
		}

		fmt.Printf(
			"%-7d %-8s %-10s %-10s %-s\n",
			r.Port,
			r.Protocol,
			statusColor,
			r.ResponseTime.String(),
			errMsg,
		)
	}

}
