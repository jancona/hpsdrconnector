// Copyright 2020 James P. Ancona

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package radio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	protocol1           = 0
	protocol2           = 1
	protocol1PortSuffix = ":1024"
)

const (
	oldDeviceMetis      = 0
	oldDeviceHermes     = 1
	oldDeviceGriffin    = 2
	oldDeviceAngelia    = 4
	oldDeviceOrion      = 5
	oldDeviceHermesLite = 6
	oldDeviceOrion2     = 10
)

const (
	deviceUnknown = -1
	deviceMetis   = iota
	deviceHermes
	deviceHermes2
	deviceAngelia
	deviceOrion
	deviceOrion2
	deviceHermesLite
)

// Device is a discovered network SDR
type Device struct {
	Protocol           int
	Device             int
	Name               string
	SoftwareVersion    byte
	Status             byte
	SupportedReceivers int
	ADCs               int
	Network            struct {
		MacAddress       net.HardwareAddr
		Address          *net.UDPAddr
		InterfaceAddress *net.IPNet
		InterfaceName    string
	}
}

// DiscoverDevices finds SDR devices on the network
func DiscoverDevices() ([]Device, error) {
	devices := make([]Device, 0)
	ifl, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("Unable to get network interfaces: %w", err)
	}
	for _, ifa := range ifl {
		addrs, err := ifa.Addrs()
		if err != nil {
			return nil, fmt.Errorf("Unable to get network interface addresses: %w", err)
		}
		if len(addrs) > 0 {
			if (ifa.Flags & net.FlagUp) == net.FlagUp {
				devices, err = discoverProtocol1(ifa, addrs, devices)
				if err != nil {
					log.Printf("[DEBUG] Failure doing discovery on interface %v: %v", ifa.Name, err)
				}
			}
		}
	}
	return devices, nil
}

func discoverProtocol1(ifa net.Interface, addrs []net.Addr, devices []Device) ([]Device, error) {
	log.Printf("[DEBUG] discoverProtocol1: looking for HPSDR devices on %s\n", ifa.Name)
	for _, a := range addrs {
		ip, ipn, err := net.ParseCIDR(a.String())
		if err != nil {
			return devices, fmt.Errorf("Unable to parse CIDR for address %v: %w", a, err)
		}
		log.Printf("[DEBUG] discoverProtocol1: ip: %v, ipn: %v, ipn.Mask: %v\n", ip, ipn, ipn.Mask)
		var a string
		ip = ip.To4()
		if ip != nil {
			a = ip.String() + protocol1PortSuffix
			// } else if ip.To16() != nil {
			// 	a = "[" + ip.String() + "]" + protocol1PortSuffix
			// }
			addr, err := net.ResolveUDPAddr("udp", a)
			if err != nil {
				return devices, fmt.Errorf("Unable to resolve UDP address for address %v: %w", a, err)
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				log.Println(err)
				continue
			}
			defer conn.Close()
			log.Print("[DEBUG] discoverProtocol1: Got connection", conn)
			found := make(chan Device)
			go discoverReceive(conn, found, ip, ipn, ifa.Name)
			// send discovery packet
			frame := makeFrame(0xEF, 0xFE, 0x02)
			// According to
			// https://github.com/TAPR/OpenHPSDR-Firmware/blob/master/Protocol%201/Documentation/Metis-%20How%20it%20works_V1.33.pdf
			// we should just use 255.255.255.255
			// Other software varies in practice, and Quisk does both.
			// Either seems to work for the PiSDR and HL2.
			// bc, err := lastAddr(ipn)
			// if err != nil {
			// 	return devices, fmt.Errorf("Unable to determine broadcast address for network %v: %w", ipn, err)
			// }
			// bca, err := net.ResolveUDPAddr("udp", bc.String()+protocol1PortSuffix)
			bca, err := net.ResolveUDPAddr("udp", "255.255.255.255"+protocol1PortSuffix)
			if err != nil {
				log.Printf("[DEBUG] discoverProtocol1: Unable to resolve UDP address: %v", err)
			} else {
				_, err = conn.WriteToUDP(frame, bca)
				if err != nil {
					log.Printf("[DEBUG] discoverProtocol1: Error sending discovery packet: %v", err)
				}
			}

			for device := range found {
				log.Printf("[DEBUG] found: %v", device)
				devices = append(devices, device)
			}
		}
	}
	return devices, nil
}

// Calculate broadcast address
// from https://stackoverflow.com/questions/36166791/how-to-get-broadcast-address-of-ipv4-net-ipnet
func lastAddr(n *net.IPNet) (net.IP, error) { // works when the n is a prefix, otherwise...
	if n.IP.To4() == nil {
		return net.IP{}, errors.New("does not support IPv6 addresses")
	}
	ip := make(net.IP, len(n.IP.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(n.IP.To4())|^binary.BigEndian.Uint32(net.IP(n.Mask).To4()))
	return ip, nil
}
func discoverReceive(
	conn *net.UDPConn,
	found chan Device,
	address net.IP,
	interfaceAddress *net.IPNet,
	interfaceName string) {
	log.Print("[DEBUG] discoverReceive: starting")
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		// Receiving a message
		buffer := make([]byte, 2048)
		l, rmAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				break
			} else {
				log.Printf("[DEBUG] discoverReceive: error reading from UDP: %v", err)
				break
			}
		}
		log.Print("[DEBUG] discoverReceive: >>>Discovery packet received from: " + rmAddr.String())
		log.Printf("[DEBUG] discoverReceive: buffer:\n%#v", buffer[:l])
		var device Device
		if buffer[0] == 0xEF && buffer[1] == 0xFE {
			status := buffer[2]
			if status == 2 || status == 3 {
				device.Protocol = protocol1
				switch buffer[10] {
				case oldDeviceMetis:
					device.Device = deviceMetis
					device.Name = "Metis"
					device.SupportedReceivers = 5
					device.ADCs = 1
					break
				case oldDeviceHermes:
					device.Device = deviceHermes
					device.Name = "Hermes"
					device.SupportedReceivers = 5
					device.ADCs = 1
					break
				case oldDeviceAngelia:
					device.Device = deviceAngelia
					device.Name = "Angelia"
					device.SupportedReceivers = 7
					device.ADCs = 2
					break
				case oldDeviceOrion:
					device.Device = deviceOrion
					device.Name = "Orion"
					device.SupportedReceivers = 7
					device.ADCs = 2
					break
				case oldDeviceHermesLite:
					device.Device = deviceHermesLite
					device.Name = "Hermes Lite"
					device.SupportedReceivers = 7
					device.ADCs = 1
					break
				case oldDeviceOrion2:
					device.Device = deviceOrion2
					device.Name = "Orion 2"
					device.SupportedReceivers = 7
					device.ADCs = 2
					break
				default:
					device.Device = deviceUnknown
					device.Name = "Unknown"
					device.SupportedReceivers = 7
					device.ADCs = 1
					break
				}
				device.SoftwareVersion = buffer[9] & 0xFF
				device.Network.MacAddress = net.HardwareAddr(buffer[3:9])
				device.Status = status
				device.Network.Address = rmAddr
				device.Network.InterfaceAddress = interfaceAddress
				device.Network.InterfaceName = interfaceName
				log.Printf("[DEBUG] discoverReceive: found device:\n%#v", device)
				found <- device
			}
		}

	}
	close(found)
	log.Print("[DEBUG] discoverReceive: complete")
}

func makeFrame(prefix ...byte) []byte {
	frame := make([]byte, 63)
	i := 0
	for _, b := range prefix {
		frame[i] = b
		i++
	}
	for i < len(frame) {
		frame[i] = 0x00
		i++
	}
	return frame
}
