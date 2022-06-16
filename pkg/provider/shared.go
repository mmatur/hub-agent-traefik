/*
Copyright (C) 2022 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

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
