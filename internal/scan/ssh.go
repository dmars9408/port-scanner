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

type SecurityCommand struct {
	Label       string
	Template    string
	NeedsInput  bool
	InputPrompt string
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
	case strings.Contains(b, "mikrotik"), strings.Contains(b, "routeros"):
		return SystemMikroTik
	}

	return SystemUnknown
}

func (s *SSHClient) DetectSystemByCommands() RemoteSystem {

	// Windows
	if out, err := s.Run("ver"); err == nil {
		o := strings.ToLower(out)
		if strings.Contains(o, "microsoft") {
			return SystemWindows
		}
	}

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
	// 1) Intento por banner (solo sistemas con banners confiables)
	sys := DetectSystemFromBanner(banner)
	if sys != SystemUnknown {
		return sys
	}

	// 2) Detección real por comandos
	return s.DetectSystemByCommands()
}

func CommandsForSystem(sys RemoteSystem) map[int]SecurityCommand {
	switch sys {

	// --- LINUX ---
	case SystemLinux:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "System info", Template: "uname -a"}
		cmds[2] = SecurityCommand{Label: "Hostname info", Template: "hostnamectl"}
		cmds[3] = SecurityCommand{Label: "Disk usage", Template: "df -h"}
		cmds[4] = SecurityCommand{Label: "Memory usage", Template: "free -m"}
		cmds[5] = SecurityCommand{Label: "Process list", Template: "ps aux"}
		cmds[6] = SecurityCommand{Label: "Listening ports", Template: "ss -tulnp"}
		cmds[7] = SecurityCommand{Label: "Network interfaces", Template: "ip addr show"}
		cmds[8] = SecurityCommand{Label: "Routing table", Template: "ip route show"}
		cmds[9] = SecurityCommand{Label: "Firewall rules (iptables)", Template: "sudo iptables -L -n -v"}
		cmds[10] = SecurityCommand{Label: "System logs", Template: "journalctl -xe"}
		cmds[11] = SecurityCommand{Label: "Auth failures", Template: "grep -i 'fail' /var/log/auth.log"}
		cmds[12] = SecurityCommand{Label: "Last logins", Template: "last -a"}
		cmds[13] = SecurityCommand{Label: "Cron jobs", Template: "crontab -l"}

		cmds[20] = SecurityCommand{
			Label:       "Stop service",
			Template:    "sudo systemctl stop %s",
			NeedsInput:  true,
			InputPrompt: "Service name:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port (iptables)",
			Template:    "sudo iptables -A INPUT -p tcp --dport %s -j DROP",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Shutdown interface",
			Template:    "sudo ip link set %s down",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		cmds[60] = SecurityCommand{
			Label:       "Kill process",
			Template:    "kill %s",
			NeedsInput:  true,
			InputPrompt: "PID:",
		}

		return cmds

	// --- BSD ---
	case SystemBSD:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "System info", Template: "uname -a"}
		cmds[2] = SecurityCommand{Label: "Disk usage", Template: "df -h"}
		cmds[3] = SecurityCommand{Label: "Process monitor", Template: "top -b"}
		cmds[4] = SecurityCommand{Label: "Socket info", Template: "sockstat -4"}
		cmds[5] = SecurityCommand{Label: "PF rules", Template: "pfctl -sr"}
		cmds[6] = SecurityCommand{Label: "PF stats", Template: "pfctl -si"}

		cmds[20] = SecurityCommand{
			Label:       "Kill process",
			Template:    "kill %s",
			NeedsInput:  true,
			InputPrompt: "PID:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port (PF)",
			Template:    "echo 'block in proto tcp from any to any port %s' >> /etc/pf.conf ; pfctl -f /etc/pf.conf",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Shutdown interface",
			Template:    "ifconfig %s down",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		return cmds

	// --- WINDOWS ---
	case SystemWindows:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "System info", Template: "systeminfo"}
		cmds[2] = SecurityCommand{Label: "Process list", Template: "tasklist"}
		cmds[3] = SecurityCommand{Label: "Network ports", Template: "netstat -ano"}
		cmds[4] = SecurityCommand{Label: "Adapters", Template: "Get-NetAdapter"}
		cmds[5] = SecurityCommand{Label: "Firewall rules", Template: "Get-NetFirewallRule"}

		cmds[20] = SecurityCommand{
			Label:       "Stop service",
			Template:    "Stop-Service -Name %s",
			NeedsInput:  true,
			InputPrompt: "Service:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port",
			Template:    "New-NetFirewallRule -DisplayName 'Block %s' -Direction Inbound -LocalPort %s -Protocol TCP -Action Block",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Disable interface",
			Template:    "Disable-NetAdapter -Name %s -Confirm:$false",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		return cmds

	// --- CISCO ---
	case SystemCisco:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "Version info", Template: "show version"}
		cmds[2] = SecurityCommand{Label: "Running config", Template: "show running-config"}
		cmds[3] = SecurityCommand{Label: "Interfaces brief", Template: "show ip interface brief"}
		cmds[4] = SecurityCommand{Label: "VLANs", Template: "show vlan"}
		cmds[5] = SecurityCommand{Label: "ACLs", Template: "show access-lists"}

		cmds[20] = SecurityCommand{
			Label:       "Shutdown interface",
			Template:    "configure terminal ; interface %s ; shutdown",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port (ACL)",
			Template:    "configure terminal ; ip access-list extended BLOCK ; deny tcp any any eq %s ; exit",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Assign VLAN",
			Template:    "configure terminal ; interface %s ; switchport access vlan %s",
			NeedsInput:  true,
			InputPrompt: "VLAN ID:",
		}

		return cmds

	// --- HUAWEI ---
	case SystemHuawei:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "Version info", Template: "display version"}
		cmds[2] = SecurityCommand{Label: "Current config", Template: "display current-configuration"}
		cmds[3] = SecurityCommand{Label: "Interfaces brief", Template: "display interface brief"}
		cmds[4] = SecurityCommand{Label: "VLANs", Template: "display vlan"}
		cmds[5] = SecurityCommand{Label: "ACLs", Template: "display acl all"}

		cmds[20] = SecurityCommand{
			Label:       "Shutdown interface",
			Template:    "system-view ; interface %s ; shutdown",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port (ACL)",
			Template:    "system-view ; acl 3000 ; rule 5 deny tcp destination-port %s",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Assign VLAN",
			Template:    "system-view ; interface %s ; port link-type access ; port default vlan %s",
			NeedsInput:  true,
			InputPrompt: "VLAN ID:",
		}

		return cmds

	// --- JUNIPER ---
	case SystemJuniper:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "Version info", Template: "show version"}
		cmds[2] = SecurityCommand{Label: "Configuration", Template: "show configuration"}
		cmds[3] = SecurityCommand{Label: "Interfaces terse", Template: "show interfaces terse"}
		cmds[4] = SecurityCommand{Label: "VLANs", Template: "show vlans"}
		cmds[5] = SecurityCommand{Label: "Firewall filters", Template: "show firewall"}

		cmds[20] = SecurityCommand{
			Label:       "Shutdown interface",
			Template:    "configure ; set interfaces %s disable ; commit",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port (filter)",
			Template:    "configure ; set firewall family inet filter BLOCK term 1 from destination-port %s ; set firewall family inet filter BLOCK term 1 then discard ; commit",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Assign VLAN",
			Template:    "configure ; set interfaces %s unit 0 family ethernet-switching vlan members %s ; commit",
			NeedsInput:  true,
			InputPrompt: "VLAN ID:",
		}

		return cmds

	// --- FORTINET ---
	case SystemFortinet:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "System status", Template: "get system status"}
		cmds[2] = SecurityCommand{Label: "Performance top", Template: "get system performance top"}
		cmds[3] = SecurityCommand{Label: "Firewall policies", Template: "show firewall policy"}
		cmds[4] = SecurityCommand{Label: "Interfaces", Template: "show system interface"}
		cmds[5] = SecurityCommand{Label: "VLANs", Template: "show system vlan"}

		cmds[20] = SecurityCommand{
			Label:       "Disable interface",
			Template:    "config system interface ; edit %s ; set status down ; end",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port",
			Template:    "config firewall service custom ; edit Block_%s ; set tcp-portrange %s ; next ; end",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Assign VLAN",
			Template:    "config system interface ; edit %s ; set vlanid %s ; end",
			NeedsInput:  true,
			InputPrompt: "VLAN ID:",
		}

		return cmds

	// --- MIKROTIK ---
	case SystemMikroTik:
		cmds := make(map[int]SecurityCommand)

		cmds[1] = SecurityCommand{Label: "System resources", Template: "/system resource print"}
		cmds[2] = SecurityCommand{Label: "Interfaces", Template: "/interface print"}
		cmds[3] = SecurityCommand{Label: "IP addresses", Template: "/ip address print"}
		cmds[4] = SecurityCommand{Label: "Firewall rules", Template: "/ip firewall filter print"}
		cmds[5] = SecurityCommand{Label: "VLANs", Template: "/interface vlan print"}

		cmds[20] = SecurityCommand{
			Label:       "Disable interface",
			Template:    "/interface disable %s",
			NeedsInput:  true,
			InputPrompt: "Interface:",
		}

		cmds[30] = SecurityCommand{
			Label:       "Block port",
			Template:    "/ip firewall filter add chain=input protocol=tcp dst-port=%s action=drop",
			NeedsInput:  true,
			InputPrompt: "Port:",
		}

		cmds[40] = SecurityCommand{
			Label:       "Create VLAN",
			Template:    "/interface vlan add vlan-id=%s interface=ether1 name=vlan%s",
			NeedsInput:  true,
			InputPrompt: "VLAN ID:",
		}

		return cmds

	// --- DEFAULT ---
	default:
		return map[int]SecurityCommand{}
	}
}
