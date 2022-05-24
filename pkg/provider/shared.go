package provider

import (
	"fmt"
	"net"
)

func getTraefikIP(traefikHost string) (net.IP, error) {
	ip := net.ParseIP(traefikHost)
	if ip != nil {
		return ip, nil
	}

	// The port is required by ResolveTCPAddr, but it's not used.
	addr, err := net.ResolveTCPAddr("tcp", traefikHost+":1234")
	if err != nil {
		return nil, fmt.Errorf("resolve TCP address: %w", err)
	}

	return addr.IP, nil
}
