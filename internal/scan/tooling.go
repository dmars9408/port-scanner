package scan

import (
	"fmt"
	"strings"
	"time"
)

func CountOpen(results []PortScanResult) int {
	n := 0
	for _, r := range results {
		if strings.EqualFold(r.Status, "OPEN") {
			n++
		}
	}
	return n
}

func CountClosed(results []PortScanResult) int {
	n := 0
	for _, r := range results {
		if strings.EqualFold(r.Status, "CLOSED") {
			n++
		}
	}
	return n
}

func DetectService(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "TELNET"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 69:
		return "TFTP"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 111:
		return "RPC"
	case 123:
		return "NTP"
	case 135:
		return "MSRPC"
	case 137, 138, 139:
		return "SMB"
	case 143:
		return "IMAP"
	case 161:
		return "SNMP"
	case 389:
		return "LDAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 500:
		return "IPSEC"
	case 514:
		return "SYSLOG"
	case 587:
		return "SMTP"
	case 631:
		return "IPP"
	case 873:
		return "RSYNC"
	case 902:
		return "VMWARE"
	case 912:
		return "VMWARE"
	case 1433:
		return "MSSQL"
	case 1521:
		return "ORACLE"
	case 1883:
		return "MQTT"
	case 1900:
		return "SSDP"
	case 2049:
		return "NFS"
	case 2375:
		return "DOCKER"
	case 2379, 2380:
		return "ETCD"
	case 3306:
		return "MYSQL"
	case 3389:
		return "RDP"
	case 4369:
		return "ERLANG"
	case 5000:
		return "UPNP"
	case 5432:
		return "POSTGRES"
	case 5672:
		return "AMQP"
	case 5900:
		return "VNC"
	case 5985, 5986:
		return "WINRM"
	case 6379:
		return "REDIS"
	case 7001, 7002:
		return "KAFKA"
	case 7474:
		return "NEO4J"
	case 8000, 8001, 8002:
		return "HTTP"
	case 8080, 8081, 8082:
		return "HTTP"
	case 8161:
		return "ACTIVEMQ"
	case 8443:
		return "HTTPS"
	case 9000:
		return "MINIO"
	case 9092:
		return "KAFKA"
	case 9200:
		return "ELASTICSEARCH"
	case 9300:
		return "ELASTICSEARCH"
	case 11211:
		return "MEMCACHED"
	default:
		return "UNKNOWN"
	}
}

func ServiceCategory(service string) string {
	switch service {
	case "HTTP", "HTTPS":
		return "WEB"

	case "SSH", "TELNET":
		return "INFRA"

	case "MYSQL", "POSTGRES", "MONGODB", "REDIS", "MARIADB":
		return "DATABASE"

	case "FTP", "SMB":
		return "LEGACY"

	case "LDAP", "SNMP", "VNC":
		return "INFRA"

	case "RDP":
		return "REMOTE"

	case "MQTT", "AMQP", "RABBITMQ", "KAFKA":
		return "MESSAGE"

	case "PROXY":
		return "PROXY"

	case "VPN":
		return "VPN"

	default:
		return "UNKNOWN"
	}
}

func ExploitKnown(port int) string {
	switch port {
	case 21:
		return "Anonymous login, weak auth"
	case 22:
		return "Weak SSH keys, outdated OpenSSH"
	case 23:
		return "Plaintext auth"
	case 25:
		return "Open relay"
	case 53:
		return "DNS amplification"
	case 80, 443:
		return "Common web vulns"
	case 110, 143:
		return "Plaintext auth"
	case 161:
		return "Public community string"
	case 389:
		return "Anonymous bind"
	case 445:
		return "SMB exploits"
	case 3306:
		return "Weak DB auth"
	case 3389:
		return "RDP brute force"
	case 5432:
		return "Weak DB auth"
	case 5672:
		return "Open AMQP"
	case 5900:
		return "Unauth VNC"
	case 6379:
		return "Unauth Redis"
	case 9200:
		return "Open Elasticsearch"
	case 11211:
		return "Open Memcached"
	default:
		return "None known"
	}
}

//
// RISK LEVEL + EXPLANATION + BAR
//

func RiskLevel(port int, status string, response time.Duration) string {
	status = strings.ToUpper(status)
	if status != "OPEN" {
		return "LOW"
	}

	if response > 2*time.Second {
		return "LOW (Honeypot suspected)"
	}

	service := DetectService(port)
	category := ServiceCategory(service)

	switch category {
	case "LEGACY":
		return "CRITICAL"

	case "DATABASE":
		return "HIGH"

	case "INFRA":
		return "HIGH"

	case "REMOTE":
		return "HIGH"

	case "MESSAGE":
		return "HIGH"

	case "PROXY":
		return "MEDIUM"

	case "VPN":
		return "MEDIUM"

	case "WEB":
		return "MEDIUM"

	default:
		return "LOW"
	}
}

func RiskExplanation(port int, status string, response time.Duration) string {
	level := RiskLevel(port, status, response)
	service := DetectService(port)
	category := ServiceCategory(service)
	exploit := ExploitKnown(port)

	switch {
	case strings.HasPrefix(level, "CRITICAL"):
		return fmt.Sprintf("%s exposed (%s). Known exploits: %s",
			service, category, exploit)

	case strings.HasPrefix(level, "HIGH"):
		return fmt.Sprintf("%s service exposed (%s). Potential exploits: %s",
			service, category, exploit)

	case strings.HasPrefix(level, "MEDIUM"):
		return fmt.Sprintf("%s service exposed. Common vulnerabilities may apply.",
			service)

	case strings.Contains(level, "Honeypot"):
		return "Slow response suggests honeypot or tarpitting behavior."

	default:
		return "Closed or non-sensitive service."
	}
}

func TotalAccumulatedTime(results []PortScanResult) time.Duration {
	var sum time.Duration
	for _, r := range results {
		sum += r.ResponseTime
	}
	return sum
}

func DetectServiceFromBanner(banner string) string {
	b := strings.ToLower(banner)

	switch {
	// WEB SERVERS
	case strings.Contains(b, "apache"):
		return "HTTP (Apache)"
	case strings.Contains(b, "nginx"):
		return "HTTP (Nginx)"
	case strings.Contains(b, "iis"):
		return "HTTP (IIS)"
	case strings.Contains(b, "caddy"):
		return "HTTP (Caddy)"
	case strings.Contains(b, "jetty"):
		return "HTTP (Jetty)"
	case strings.Contains(b, "tomcat"):
		return "HTTP (Tomcat)"
	case strings.Contains(b, "gunicorn"):
		return "HTTP (Gunicorn)"
	case strings.Contains(b, "uvicorn"):
		return "HTTP (Uvicorn)"
	case strings.Contains(b, "express"):
		return "HTTP (Express)"
	case strings.Contains(b, "php"):
		return "HTTP (PHP)"

	// SSH
	case strings.Contains(b, "openssh"):
		return "SSH (OpenSSH)"
	case strings.Contains(b, "dropbear"):
		return "SSH (Dropbear)"

	// FTP
	case strings.Contains(b, "vsftpd"):
		return "FTP (vsftpd)"
	case strings.Contains(b, "proftpd"):
		return "FTP (ProFTPD)"

	// MAIL
	case strings.Contains(b, "postfix"):
		return "SMTP (Postfix)"
	case strings.Contains(b, "exim"):
		return "SMTP (Exim)"
	case strings.Contains(b, "sendmail"):
		return "SMTP (Sendmail)"

	// DATABASES
	case strings.Contains(b, "mysql"):
		return "MySQL"
	case strings.Contains(b, "mariadb"):
		return "MariaDB"
	case strings.Contains(b, "postgres"):
		return "PostgreSQL"
	case strings.Contains(b, "mongodb"):
		return "MongoDB"
	case strings.Contains(b, "redis"):
		return "Redis"
	case strings.Contains(b, "couchdb"):
		return "CouchDB"
	case strings.Contains(b, "elasticsearch"):
		return "Elasticsearch"

	// WINDOWS SERVICES
	case strings.Contains(b, "msrpc"):
		return "MSRPC"
	case strings.Contains(b, "smb"):
		return "SMB"
	case strings.Contains(b, "ms-wbt"):
		return "RDP"

	// VPN
	case strings.Contains(b, "openvpn"):
		return "OpenVPN"
	case strings.Contains(b, "wireguard"):
		return "WireGuard"

	// MESSAGING
	case strings.Contains(b, "mqtt"):
		return "MQTT"
	case strings.Contains(b, "rabbitmq"):
		return "RabbitMQ"
	case strings.Contains(b, "kafka"):
		return "Kafka"

	// PROXY
	case strings.Contains(b, "squid"):
		return "Proxy (Squid)"
	case strings.Contains(b, "haproxy"):
		return "Proxy (HAProxy)"
	case strings.Contains(b, "traefik"):
		return "Proxy (Traefik)"

	// OTHER
	case strings.Contains(b, "ldap"):
		return "LDAP"
	case strings.Contains(b, "snmp"):
		return "SNMP"
	case strings.Contains(b, "rtsp"):
		return "RTSP"
	case strings.Contains(b, "sip"):
		return "SIP"
	case strings.Contains(b, "vnc"):
		return "VNC"
	}

	return "Unknown"
}
