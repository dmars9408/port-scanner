package scan

import (
	"math/rand"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type BubbleResultMsg struct {
	Result PortScanResult
}

type ScanProgressMessage struct {
	Port int
}

// ScanDoneMsg avisa a Bubble Tea que todos los puertos terminaron de escanearse.
type ScanDoneMsg struct{}

// StartScanSession lanza el worker pool en segundo plano y devuelve un tea.Cmd
// que escucha los resultados conforme se producen sin saturar el sistema.
func StartScanSession(host string, ports []int, concurrency int, timeout time.Duration) (tea.Cmd, chan tea.Msg) {
	msgChan := make(chan tea.Msg, 500) // Buffer para absorber ráfagas hacia la UI

	go func() {
		defer close(msgChan)

		// 1. Creamos una copia local y aleatorizamos el orden de los puertos
		shuffled := make([]int, len(ports))
		copy(shuffled, ports)

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		r.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		// 2. Llenamos el canal con los puertos desordenados
		jobs := make(chan int, len(shuffled))
		for _, p := range shuffled {
			jobs <- p
		}
		close(jobs)

		var wg sync.WaitGroup
		// Limitamos la concurrencia al número indicado (por ej. 100 o 200)
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for port := range jobs {
					// 1. Notificar progreso a la UI
					msgChan <- ScanProgressMessage{Port: port}

					// 2. Realizar escaneo real
					res := ScanPort(host, port, timeout)

					// 3. Entregar resultado a la UI
					msgChan <- BubbleResultMsg{Result: res}
				}
			}()
		}

		wg.Wait()
		// Enviamos señal de finalización
		msgChan <- ScanDoneMsg{}
	}()

	return WaitForScanMsg(msgChan), msgChan
}

// WaitForScanMsg lee el siguiente mensaje disponible en el canal de escaneo.
// Este es el patrón estándar de Bubble Tea para escuchar canales asíncronos continuos.
func WaitForScanMsg(msgChan chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-msgChan
		if !ok {
			return nil
		}
		return msg
	}
}
