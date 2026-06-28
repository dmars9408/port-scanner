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

func main() {
	host := flag.String("host", "", "Host name or ip address")
	ports := flag.String("ports", "", "Ports to scan separated by commas")
	timeout := flag.Duration("timeout", 2*time.Second, "Timeout for each port scan")
	maxConcurrency := flag.Int("max-concurrency", 100, "Max number of goroutines to use for scanning")
	flag.Parse()

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
	results := scan.ScanPorts(*host, portsInt, *timeout, *maxConcurrency)
	fmt.Printf("%-7s %-8s %-10s %-10s %-s\n", "PORT", "PROTO", "STATUS", "TIME", "ERROR")
	fmt.Println(strings.Repeat("-", 50))

	for _, r := range results {
		errMsg := "-"
		if r.Error != "" {
			errMsg = r.Error
		}

		fmt.Printf(
			"%-7d %-8s %-10s %-10s %-s\n",
			r.Port,
			r.Protocol,
			r.Status,
			r.ResponseTime.String(),
			errMsg,
		)
	}

}
