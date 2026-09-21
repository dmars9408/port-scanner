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

func CommandsForSystem(sys RemoteSystem) map[int]SecurityCommand {
	switch sys {

	// linux
	case SystemLinux:
		return map[int]SecurityCommand{
			// --- Diagnóstico equivalente ---
			1:  {Label: "System info", Template: "uname -a"},
			2:  {Label: "Hostname info", Template: "hostnamectl"},
			3:  {Label: "Disk usage", Template: "df -h"},
			4:  {Label: "Memory usage", Template: "free -m"},
			5:  {Label: "Process list", Template: "ps aux"},
			6:  {Label: "Listening ports", Template: "ss -tulnp"},
			7:  {Label: "Network interfaces", Template: "ip addr show"},
			8:  {Label: "Routing table", Template: "ip route show"},
			9:  {Label: "Firewall rules (iptables)", Template: "iptables -L -n -v"},
			10: {Label: "System logs", Template: "journalctl -xe"},
			11: {Label: "Auth failures", Template: "grep -i 'fail' /var/log/auth.log"},
			12: {Label: "Last logins", Template: "last -a"},
			13: {Label: "Cron jobs", Template: "crontab -l"},

			// --- Gestión de servicios ---
			20: {
				Label:       "Stop service",
				Template:    "sudo systemctl stop %s",
				NeedsInput:  true,
				InputPrompt: "Nombre del servicio:",
			},

			// --- Gestión de puertos ---
			30: {
				Label:       "Block port (iptables)",
				Template:    "sudo iptables -A INPUT -p tcp --dport %s -j DROP",
				NeedsInput:  true,
				InputPrompt: "Puerto a bloquear:",
			},

			// --- Gestión de interfaces ---
			40: {
				Label:       "Shutdown interface",
				Template:    "sudo ip link set %s down",
				NeedsInput:  true,
				InputPrompt: "Nombre de la interfaz:",
			},

			// --- Gestión de VLANs ---
			50: {
				Label:       "Create VLAN",
				Template:    "sudo ip link add link eth0 name eth0.%s type vlan id %s",
				NeedsInput:  true,
				InputPrompt: "ID de VLAN:",
			},

			// --- Gestión de procesos ---
			60: {
				Label:       "Kill process",
				Template:    "kill %s",
				NeedsInput:  true,
				InputPrompt: "PID:",
			},
		}

	//bsd
	case SystemBSD:
		return map[int]SecurityCommand{
			1: {Label: "System info", Template: "uname -a"},
			2: {Label: "Disk usage", Template: "df -h"},
			3: {Label: "Process monitor", Template: "top -b"},
			4: {Label: "Socket info", Template: "sockstat -4"},
			5: {Label: "PF rules", Template: "pfctl -sr"},
			6: {Label: "PF stats", Template: "pfctl -si"},

			20: {
				Label:       "Kill process",
				Template:    "kill %s",
				NeedsInput:  true,
				InputPrompt: "PID:",
			},

			30: {
				Label:       "Block port (PF)",
				Template:    "echo 'block in proto tcp from any to any port %s' >> /etc/pf.conf ; pfctl -f /etc/pf.conf",
				NeedsInput:  true,
				InputPrompt: "Puerto:",
			},

			40: {
				Label:       "Shutdown interface",
				Template:    "ifconfig %s down",
				NeedsInput:  true,
				InputPrompt: "Interfaz:",
			},
		}

	//windows
	case SystemWindows:
		return map[int]SecurityCommand{
			1: {Label: "System info", Template: "systeminfo"},
			2: {Label: "Process list", Template: "tasklist"},
			3: {Label: "Network ports", Template: "netstat -ano"},
			4: {Label: "Adapters", Template: "Get-NetAdapter"},
			5: {Label: "Firewall rules", Template: "Get-NetFirewallRule"},

			20: {
				Label:       "Stop service",
				Template:    "Stop-Service -Name %s",
				NeedsInput:  true,
				InputPrompt: "Servicio:",
			},

			30: {
				Label:       "Block port",
				Template:    "New-NetFirewallRule -DisplayName 'Block %s' -Direction Inbound -LocalPort %s -Protocol TCP -Action Block",
				NeedsInput:  true,
				InputPrompt: "Puerto:",
			},

			40: {
				Label:       "Disable interface",
				Template:    "Disable-NetAdapter -Name %s -Confirm:$false",
				NeedsInput:  true,
				InputPrompt: "Interfaz:",
			},

			50: {
				Label:       "Create VLAN (Hyper-V)",
				Template:    "Add-VMNetworkAdapter -VMName 'VM1' -SwitchName 'vSwitch' ; Set-VMNetworkAdapterVlan -VMName 'VM1' -Access -VlanId %s",
				NeedsInput:  true,
				InputPrompt: "ID de VLAN:",
			},
		}

	// cisco ios/nx-os
	case SystemCisco:
		return map[int]SecurityCommand{
			1: {Label: "Version info", Template: "show version"},
			2: {Label: "Running config", Template: "show running-config"},
			3: {Label: "Interfaces brief", Template: "show ip interface brief"},
			4: {Label: "VLANs", Template: "show vlan"},
			5: {Label: "ACLs", Template: "show access-lists"},

			20: {
				Label:       "Shutdown interface",
				Template:    "configure terminal ; interface %s ; shutdown",
				NeedsInput:  true,
				InputPrompt: "Interfaz (ej: GigabitEthernet0/1):",
			},

			30: {
				Label:       "Block port (ACL)",
				Template:    "configure terminal ; ip access-list extended BLOCK ; deny tcp any any eq %s ; exit",
				NeedsInput:  true,
				InputPrompt: "Puerto:",
			},

			40: {
				Label:       "Assign VLAN",
				Template:    "configure terminal ; interface %s ; switchport access vlan %s",
				NeedsInput:  true,
				InputPrompt: "VLAN ID:",
			},
		}

	//huawei vrp
	case SystemHuawei:
		return map[int]SecurityCommand{
			1: {Label: "Version info", Template: "display version"},
			2: {Label: "Current config", Template: "display current-configuration"},
			3: {Label: "Interfaces brief", Template: "display interface brief"},
			4: {Label: "VLANs", Template: "display vlan"},
			5: {Label: "ACLs", Template: "display acl all"},

			20: {
				Label:       "Shutdown interface",
				Template:    "system-view ; interface %s ; shutdown",
				NeedsInput:  true,
				InputPrompt: "Interfaz:",
			},

			30: {
				Label:       "Block port (ACL)",
				Template:    "system-view ; acl 3000 ; rule 5 deny tcp destination-port %s",
				NeedsInput:  true,
				InputPrompt: "Puerto:",
			},

			40: {
				Label:       "Assign VLAN",
				Template:    "system-view ; interface %s ; port link-type access ; port default vlan %s",
				NeedsInput:  true,
				InputPrompt: "VLAN ID:",
			},
		}

	//juniper junos
	case SystemJuniper:
		return map[int]SecurityCommand{
			1: {Label: "Version info", Template: "show version"},
			2: {Label: "Configuration", Template: "show configuration"},
			3: {Label: "Interfaces terse", Template: "show interfaces terse"},
			4: {Label: "VLANs", Template: "show vlans"},
			5: {Label: "Firewall filters", Template: "show firewall"},

			20: {
				Label:       "Shutdown interface",
				Template:    "configure ; set interfaces %s disable ; commit",
				NeedsInput:  true,
				InputPrompt: "Interfaz:",
			},

			30: {
				Label:       "Block port (filter)",
				Template:    "configure ; set firewall family inet filter BLOCK term 1 from destination-port %s ; set firewall family inet filter BLOCK term 1 then discard ; commit",
				NeedsInput:  true,
				InputPrompt: "Puerto:",
			},

			40: {
				Label:       "Assign VLAN",
				Template:    "configure ; set interfaces %s unit 0 family ethernet-switching vlan members %s ; commit",
				NeedsInput:  true,
				InputPrompt: "VLAN ID:",
			},
		}

	//fortinet fortios
	case SystemFortinet:
		return map[int]SecurityCommand{
			1: {Label: "System status", Template: "get system status"},
			2: {Label: "Performance top", Template: "get system performance top"},
			3: {Label: "Firewall policies", Template: "show firewall policy"},
			4: {Label: "Interfaces", Template: "show system interface"},
			5: {Label: "VLANs", Template: "show system vlan"},

			20: {
				Label:       "Disable interface",
				Template:    "config system interface ; edit %s ; set status down ; end",
				NeedsInput:  true,
				InputPrompt: "Interfaz:",
			},

			30: {
				Label:       "Block port",
				Template:    "config firewall service custom ; edit Block_%s ; set tcp-portrange %s ; next ; end",
				NeedsInput:  true,
				InputPrompt: "Puerto:",
			},

			40: {
				Label:       "Assign VLAN",
				Template:    "config system interface ; edit %s ; set vlanid %s ; end",
				NeedsInput:  true,
				InputPrompt: "VLAN ID:",
			},
		}

	// mikrotik routeros
	case SystemMikroTik:
		return map[int]SecurityCommand{
			1: {Label: "System resources", Template: "/system resource print"},
			2: {Label: "Interfaces", Template: "/interface print"},
			3: {Label: "IP addresses", Template: "/ip address print"},
			4: {Label: "Firewall rules", Template: "/ip firewall filter print"},
			5: {Label: "VLANs", Template: "/interface vlan print"},

			20: {
				Label:       "Disable interface",
				Template:    "/interface disable %s",
				NeedsInput:  true,
				InputPrompt: "Interfaz:",
			},

			30: {
				Label:       "Block port",
				Template:    "/ip firewall filter add chain=input protocol=tcp dst-port=%s action=drop",
				NeedsInput:  true,
				InputPrompt: "Puerto:",
			},

			40: {
				Label:       "Create VLAN",
				Template:    "/interface vlan add vlan-id=%s interface=ether1 name=vlan%s",
				NeedsInput:  true,
				InputPrompt: "VLAN ID:",
			},
		}

	// unknown system
	default:
		return map[int]SecurityCommand{}
	}
}
