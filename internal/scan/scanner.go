package scan

import (
	"fmt"
	"net"
<<<<<<< HEAD
=======
	"strings"
>>>>>>> feature/bubbletea-ui
	"sync"
	"time"
)

// struct para devolver la informacion del escaneo de puertos
type PortScanResult struct {
	Port         int
	Status       string
	Error        string
	Protocol     string
	ResponseTime time.Duration
	Timestamp    time.Time
}

// funcion para leer un solo puerto
func ScanPort(host string, port int, timeout time.Duration) PortScanResult {
<<<<<<< HEAD
	start := time.Now()                                      //inicio del escaneo
	addrs := net.JoinHostPort(host, fmt.Sprintf("%d", port)) //con el net.JoinHostPort permitimos procesar tanto IPv4 como IPv6
	//intentamos establecer conexion con timeout
	/*version no optima
	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addrs)
	if err == nil {
		conn.Close()
		return PortScanResult{Port: port, Status: "open", Protocol: "tcp", ResponseTime: time.Since(start), Timestamp: time.Now()}
	} else {
		return PortScanResult{Port: port, Status: "closed", Error: err.Error(), Protocol: "tcp", ResponseTime: time.Since(start), Timestamp: time.Now()}
	}
	*/
	/*version optimizada, se define una sola vez #ResponseTime y #Timestamp para evitar redundancia y posibles errores
	en un mismo escaneo, ademas tenemos un solo #return evitando la casi redundancia del caso anterior*/
	reply := PortScanResult{
		Port:         port,
		Protocol:     "tcp",
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
	}
	if conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addrs); err == nil {
		conn.Close()
		reply.Status = "open"
	} else {
		reply.Status = "closed"
		reply.Error = err.Error()
	}
	return reply

=======
	start := time.Now()
	addrs := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	reply := PortScanResult{
		Port:      port,
		Protocol:  "tcp",
		Timestamp: time.Now(),
	}

	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addrs)
	reply.ResponseTime = time.Since(start)

	if err == nil {
		conn.Close()
		reply.Status = "open"
		return reply
	}

	// --- Clasificación profesional de errores ---
	msg := err.Error()

	switch {
	case strings.Contains(msg, "no such host"):
		reply.Status = "dns_error"
		reply.Error = fmt.Sprintf("DNS error: cannot resolve host '%s'", host)

	case strings.Contains(msg, "i/o timeout"):
		reply.Status = "timeout"
		reply.Error = fmt.Sprintf("Timeout: host '%s' did not respond", host)

	case strings.Contains(msg, "connection refused"):
		reply.Status = "refused"
		reply.Error = fmt.Sprintf("Connection refused on port %d", port)

	case strings.Contains(msg, "network is unreachable"):
		reply.Status = "unreachable"
		reply.Error = "Network unreachable: check your connection"

	default:
		reply.Status = "closed"
		reply.Error = fmt.Sprintf("Port %d closed (%s)", port, msg)
	}

	return reply
>>>>>>> feature/bubbletea-ui
}

// funcion para escanear todos los puertos
func ScanPorts(host string, ports []int, timeout time.Duration, maxConcurrency int) []PortScanResult {
	results := make(chan PortScanResult)             //canal para devolver los resultados
	semaphore := make(chan struct{}, maxConcurrency) //sincronizacion
	wg := sync.WaitGroup{}                           //sincronizacion
	//escaneo de puertos
	for _, port := range ports {
		wg.Add(1)               //aumenta el contador
		semaphore <- struct{}{} //sincronizacion
		go func(port int) {
			defer wg.Done()                          //decrementa el contador
			defer func() { <-semaphore }()           //sincronizacion
			results <- ScanPort(host, port, timeout) //devuelve el escaneo
		}(port) //llamada a la funcion
	}
	go func() {
		wg.Wait()      //espera a que todos los goroutines terminen
		close(results) //cierra el canal
	}()
	var scanResults []PortScanResult
	for result := range results {
		scanResults = append(scanResults, result)
	}
	return scanResults
}
