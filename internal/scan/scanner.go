package scan

import (
	"fmt"
	"net"
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
