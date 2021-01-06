package l9synscan

import "github.com/google/gopacket/layers"

type L9SynScanResult struct {
	Hosts []string
	Ports []layers.TCPPort
}

func (result *L9SynScanResult) AddHost(host string) bool {
	if result.HasHost(host) {
		return false
	}
	result.Hosts = append(result.Hosts, host)
	return true
}

func (result *L9SynScanResult) AddPort(port layers.TCPPort) bool {
	if result.HasPort(port) {
		return false
	}
	result.Ports = append(result.Ports, port)
	return true
}

func (result *L9SynScanResult) HasHost(host string) bool {
	for _, hostname := range result.Hosts {
		if host == hostname {
			return true
		}
	}
	return false
}

func (result *L9SynScanResult) HasPort(port layers.TCPPort) bool {
	for _, scannedPort := range result.Ports {
		if port == scannedPort {
			return true
		}
	}
	return false
}
