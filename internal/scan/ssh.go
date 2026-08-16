package scan

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type RemoteSystem int

const (
	SystemUnknown RemoteSystem = iota
	SystemLinux
	SystemBSD
	SystemWindows
	SystemCisco
	SystemHuawei
	SystemJuniper
	SystemFortinet
	SystemPaloAlto
	SystemMikroTik
)

type SSHClient struct {
	Client *ssh.Client
	System RemoteSystem
	Banner string
	Host   string
	Port   int
}

func ConnectSSH(host string, port int, user, password string, timeout time.Duration) (*SSHClient, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	return &SSHClient{
		Client: client,
		System: SystemUnknown,
		Host:   host,
		Port:   port,
	}, nil
}

func (s *SSHClient) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}

func (s *SSHClient) Run(cmd string) (string, error) {
	session, err := s.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

func DetectSystemFromBanner(banner string) RemoteSystem {
	b := strings.ToLower(banner)

	switch {
	case strings.Contains(b, "openssh"):
		return SystemLinux // se refina luego con comandos
	case strings.Contains(b, "cisco"):
		return SystemCisco
	case strings.Contains(b, "huawei"):
		return SystemHuawei
	case strings.Contains(b, "juniper"):
		return SystemJuniper
	case strings.Contains(b, "fortios"):
		return SystemFortinet
	case strings.Contains(b, "pan-os"):
		return SystemPaloAlto
	case strings.Contains(b, "mikrotik"):
		return SystemMikroTik
	default:
		return SystemUnknown
	}
}

func (s *SSHClient) DetectSystemByCommands() RemoteSystem {

	// Linux / BSD
	if out, err := s.Run("uname -s"); err == nil {
		o := strings.ToLower(out)
		switch {
		case strings.Contains(o, "linux"):
			return SystemLinux
		case strings.Contains(o, "freebsd"), strings.Contains(o, "openbsd"), strings.Contains(o, "netbsd"):
			return SystemBSD
		}
	}

	// Cisco / Juniper
	if out, err := s.Run("show version"); err == nil {
		o := strings.ToLower(out)
		switch {
		case strings.Contains(o, "cisco ios"), strings.Contains(o, "nx-os"):
			return SystemCisco
		case strings.Contains(o, "juniper"), strings.Contains(o, "junos"):
			return SystemJuniper
		}
	}

	// Huawei
	if out, err := s.Run("display version"); err == nil {
		o := strings.ToLower(out)
		if strings.Contains(o, "huawei") {
			return SystemHuawei
		}
	}

	// Fortinet
	if out, err := s.Run("get system status"); err == nil {
		o := strings.ToLower(out)
		if strings.Contains(o, "fortios") {
			return SystemFortinet
		}
	}

	// Palo Alto
	if out, err := s.Run("show system info"); err == nil {
		o := strings.ToLower(out)
		if strings.Contains(o, "pan-os") {
			return SystemPaloAlto
		}
	}

	// MikroTik
	if out, err := s.Run("/system resource print"); err == nil {
		o := strings.ToLower(out)
		if strings.Contains(o, "routeros") || strings.Contains(o, "mikrotik") {
			return SystemMikroTik
		}
	}

	return SystemUnknown
}

func (s *SSHClient) DetectRemoteSystem(banner string) RemoteSystem {
	// 1) Intento por banner
	sys := DetectSystemFromBanner(banner)
	if sys != SystemUnknown {
		return sys
	}

	// 2) Intento por comandos seguros
	sys = s.DetectSystemByCommands()
	return sys
}

func CommandsForSystem(sys RemoteSystem) []string {
	switch sys {

	case SystemLinux:
		return []string{
			"uname -a",
			"hostnamectl",
			"df -h",
			"free -m",
			"uptime",
			"ps aux",
			"ss -tulnp",
		}

	case SystemBSD:
		return []string{
			"uname -a",
			"df -h",
			"top -b",
			"sockstat -4",
		}

	case SystemWindows:
		return []string{
			"systeminfo",
			"tasklist",
			"netstat -ano",
		}

	case SystemCisco:
		return []string{
			"show version",
			"show running-config",
			"show ip interface brief",
			"show processes cpu",
		}

	case SystemHuawei:
		return []string{
			"display version",
			"display current-configuration",
			"display interface brief",
		}

	case SystemJuniper:
		return []string{
			"show version",
			"show configuration",
			"show interfaces terse",
		}

	case SystemFortinet:
		return []string{
			"get system status",
			"get system performance top",
			"diagnose sys top",
		}

	case SystemPaloAlto:
		return []string{
			"show system info",
			"show running resource-monitor",
			"show session all",
		}

	case SystemMikroTik:
		return []string{
			"/system resource print",
			"/interface print",
			"/ip address print",
		}

	default: // SystemUnknown
		return []string{
			"help",
			"?",
		}
	}
}
