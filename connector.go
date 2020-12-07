// +build !windows

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

package main // "github.com/jancona/hpsdrconnector"

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/logutils"
	"github.com/jancona/hpsdr"
	"github.com/jancona/hpsdr/protocol1"
)

const bufferSize = 2048

var (
	iqPort      *uint   = flag.Uint("port", 4590, "IQ listen port")
	frequency   *uint   = flag.Uint("frequency", 7100000, "Tune to specified frequency in Hz")
	sampleRate  *uint   = flag.Uint("samplerate", 96000, "Use the specified samplerate: one of 48000, 96000, 192000, 384000")
	lnaGain     *uint   = flag.Uint("gain", 20, "LNA gain between 0 (-12dB) and 60 (48dB)")
	controlPort *uint   = flag.Uint("control", 4591, "control socket port (default 4591)")
	radioIP     *string = flag.String("radio", "", "IP address of radio (default use first radio discovered)")
	isDebug     *bool   = flag.Bool("debug", false, "Emit debug log messages on stdout")
	isServer    *bool   = flag.Bool("server", false, "Run as the server process")
	serverPort  *uint   = flag.Uint("serverPort", 7300, "Server port for this radio")
)

func init() {
	flag.UintVar(iqPort, "p", 4590, "IQ listen port")
	flag.UintVar(frequency, "f", 7100000, "Tune to specified frequency in Hz")
	flag.UintVar(sampleRate, "s", 96000, "Use the specified samplerate: one of 48000, 96000, 192000, 384000")
	flag.UintVar(lnaGain, "g", 20, "LNA gain between 0 (-12dB) and 60 (48dB)")
	flag.UintVar(controlPort, "c", 4591, "control socket port (default 4591)")
	flag.StringVar(radioIP, "r", "", "IP address of radio (default use first radio discovered)")
	flag.BoolVar(isDebug, "d", false, "Emit debug log messages on stdout")
}

func main() {
	flag.Parse()
	minLogLevel := "INFO"
	if *isDebug {
		minLogLevel = "DEBUG"
	}

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "ERROR"},
		MinLevel: logutils.LogLevel(minLogLevel),
		Writer:   os.Stdout,
	}
	log.SetOutput(filter)
	log.Print("[DEBUG] Debug is on")

	serverConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", *serverPort))
	if *isServer {
		if err != nil {
			// Run as a server
			runAsServer()
			os.Exit(0)
		} else {
			log.Fatalf("Attempting to start a server on port %d, but one is already running", *serverPort)
		}
	} else {
		runAsClient(serverConn, err)
	}
}

func runAsClient(serverConn net.Conn, err error) {
	if err != nil {
		log.Printf("[DEBUG] No server running, starting one on port %d", *serverPort)
		// No server running, so start one
		args := []string{
			"--server",
			"--serverPort", strconv.FormatUint(uint64(*serverPort), 10),
			"--port", strconv.FormatUint(uint64(*iqPort), 10),
			"--frequency", strconv.FormatUint(uint64(*frequency), 10),
			"--samplerate", strconv.FormatUint(uint64(*sampleRate), 10),
			"--gain", strconv.FormatUint(uint64(*lnaGain), 10),
			"--control", strconv.FormatUint(uint64(*controlPort), 10),
		}
		if *radioIP != "" {
			args = append(args, "--radio", *radioIP)
		}
		if *isDebug {
			args = append(args, "--debug")
		}
		log.Printf("[DEBUG] Server args: %v", args)
		cmd := exec.Command("hpsdrconnector", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Start()
		if err != nil {
			log.Fatalf("Unable to launch hpsdrconnector server: %v", err)
		}
		for i := 0; i < 5; i++ {
			serverConn, err = net.Dial("tcp", fmt.Sprintf("localhost:%d", *serverPort))
			if err != nil {
				log.Printf("Failed to connect to hpsdrconnector server: %v", err)
			}
			if serverConn != nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			log.Fatalf("Unable to connect to hpsdrconnector server: %v", err)
		}
	} else {
		// Send start_receiver command to server
		cmd := fmt.Sprintf("new_receiver:%d:%d:%d", *iqPort, *controlPort, *frequency)
		_, err = serverConn.Write([]byte(cmd))
		if err != nil {
			log.Fatalf("Error sending command '%s' to server: %v", cmd, err)
		}
	}
	// Run until we're terminated then tell server to close receiver
	// wait for a close signal then clean up
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan struct{})
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		log.Print("Received an interrupt, stopping...")
		// Send close_receiver command to server
		cmd := fmt.Sprintf("close_receiver:%d", *controlPort)
		_, err = serverConn.Write([]byte(cmd))
		if err != nil {
			log.Fatalf("Error sending command '%s' to server: %v", cmd, err)
		}
		close(cleanupDone)
	}()
	<-cleanupDone
}

// Server represents the radio server
type Server struct {
	radio         hpsdr.Radio
	receiverMutex sync.Mutex
	receivers     map[uint]hpsdr.Receiver
}

func runAsServer() {
	log.Printf("[DEBUG] Server starting on port %d", *serverPort)
	server := Server{
		receivers: map[uint]hpsdr.Receiver{},
	}

	switch *sampleRate {
	case 48000:
	case 96000:
	case 192000:
	case 384000:
	default:
		log.Fatalf("Invalid sample rate %d. Must be one of 48000, 96000, 192000, 384000", *sampleRate)
	}

	if *lnaGain > 60 {
		log.Fatalf("Invalid LNA gain %d. Must be between 0 and 60", *lnaGain)
	}

	var addr *net.UDPAddr
	var err error
	if *radioIP != "" {
		a := *radioIP + ":1024"
		addr, err = net.ResolveUDPAddr("udp", a)
		if err != nil {
			log.Fatalf("Error resolving receiver address %s: %v", a, err)
		}
	} else {
		devices, err := hpsdr.DiscoverDevices()
		if err != nil {
			log.Printf("[ERROR] Error discovering devices: %v", err)
		}
		log.Printf("[DEBUG] main: devices: %#v", devices)
		if len(devices) == 0 {
			log.Fatal("No devices detected. Exiting.")
		}
		addr = devices[0].Network.Address
	}
	server.radio = protocol1.NewRadio(addr)
	server.radio.SetSampleRate(*sampleRate)
	server.radio.SetTXFrequency(*frequency)
	server.radio.SetLNAGain(*lnaGain)

	done := make(chan struct{})
	log.Printf("[INFO] Listening on server port %d", *serverPort)
	config := newReuseAddrListenConfig()
	serverListener, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", *serverPort))
	if err != nil {
		log.Fatalf("Error listening on server port %d: %v", *serverPort, err)
	}
	go func() {
		for receiverCount := 1; receiverCount > 0; {
			log.Printf("[DEBUG] Calling Accept on server port %d", *serverPort)
			serverConn, err := serverListener.Accept()
			if err != nil {
				log.Fatalf("Error accepting connection on server port %d: %v", *serverPort, err)
			}
			log.Printf("[DEBUG] Opened connection on server port %d", *serverPort)
			buf := make([]byte, 128)
			for run := true; run; {
				cnt, err := serverConn.Read(buf)
				if err != nil {
					log.Printf("[DEBUG] Error reading server socket: %v", err)
					run = false
					break
				}
				if cnt <= 0 {
					run = false
					break
				}
				cmd := strings.Trim(string(buf[:cnt]), "\x00\r\n ")
				log.Printf("[DEBUG] Received server command '%s'", cmd)
				tok := strings.Split(cmd, ":")
				log.Printf("[DEBUG] len(tok)=%d", len(tok))
				switch tok[0] {
				case "new_receiver":
					if len(tok) != 4 {
						log.Printf("[DEBUG] Ignoring bad new_receiver command: %s", cmd)
					}
					iqPort, err := strconv.ParseUint(tok[1], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] Ignoring bad IQ port value in server command '%s': %v", cmd, err)
					}
					controlPort, err := strconv.ParseUint(tok[2], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] Ignoring bad control port value in server command '%s': %v", cmd, err)
					}
					frequency, err := strconv.ParseUint(tok[3], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] Ignoring bad frequency value in server command '%s': %v", cmd, err)
					}
					server.addReceiver(uint(iqPort), uint(controlPort), uint(frequency))
				case "close_receiver":
					if len(tok) != 2 {
						log.Printf("[DEBUG] Ignoring bad new_receiver command: %s", cmd)
					}
					controlPort, err := strconv.ParseUint(tok[1], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] Ignoring bad control port value in server command '%s': %v", cmd, err)
					}
					receiverCount = server.closeReceiver(uint(controlPort))
				default:
					log.Printf("[DEBUG] Ignoring unsupported server command: %s", cmd)
				}
			}
		}
		// receiverCount is zero, so we're done
		close(done)
	}()
	server.addReceiver(*iqPort, *controlPort, *frequency)

	log.Printf("[INFO] Starting radio on %s", addr.String())
	err = server.radio.Start()
	if err != nil {
		log.Fatalf("Error starting radio %v: %v", server.radio, err)
	}
	go server.sendTransmitSamples()
	<-done
	server.radio.Close()
}

func (s *Server) closeReceiver(controlPort uint) int {
	s.receiverMutex.Lock()
	defer s.receiverMutex.Unlock()
	delete(s.receivers, controlPort)
	return len(s.receivers)
}

func newReuseAddrListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(descriptor uintptr) {
				syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
}

func (s *Server) addReceiver(iqPort uint, controlPort uint, frequency uint) {
	distributor := NewDistributor()

	s.receiverMutex.Lock()
	rec := s.radio.AddReceiver(distributor.Distribute)
	s.receivers[controlPort] = rec
	defer s.receiverMutex.Unlock()

	rec.SetFrequency(frequency)
	var controlConn, iqConn net.Conn

	log.Printf("[INFO] Listening on control port %d", controlPort)
	config := newReuseAddrListenConfig()
	controlListener, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", controlPort))
	if err != nil {
		log.Fatalf("Error listening on control port %d: %v", controlPort, err)
	}
	go func() {
		for {
			log.Printf("[DEBUG] Calling Accept on control port %d", controlPort)
			controlConn, err = controlListener.Accept()
			if err != nil {
				// TODO: How should we handle this?
				log.Fatalf("Error accepting connection on control port %d: %v", controlPort, err)
			}
			log.Printf("[DEBUG] Opened connection on control port %d", controlPort)
			buf := make([]byte, 128)
			for run := true; run; {
				cnt, err := controlConn.Read(buf)
				if err != nil {
					log.Printf("[DEBUG] Error reading control socket: %v", err)
					run = false
					break
				}
				if cnt <= 0 {
					run = false
					break
				}
				cmd := strings.Trim(string(buf[:cnt]), "\x00\r\n ")
				log.Printf("[DEBUG] Received command '%s'", cmd)
				tok := strings.Split(cmd, ":")
				log.Printf("[DEBUG] len(tok)=%d", len(tok))
				// if len(tok) != 2 {
				// 	log.Printf("[DEBUG] Ignoring invalid command '%s'", cmd)
				// 	continue
				// }
				switch tok[0] {
				case "samp_rate":
					sr, err := strconv.ParseUint(tok[1], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] Ignoring bad sample rate value in control command '%s': %v", cmd, err)
					}
					*sampleRate = uint(sr)
					s.radio.SetSampleRate(*sampleRate)
				case "center_freq":
					f, err := strconv.ParseUint(tok[1], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] Ignoring bad center frequency value in control command '%s': %v", cmd, err)
					}
					frequency = uint(f)
					s.radio.SetTXFrequency(frequency)
					rec.SetFrequency(frequency)
					if frequency >= 3000000 {
						// Turn on high pass filter
						s.radio.SetOCOut(0b1000000)
					} else {
						s.radio.SetOCOut(0)
					}
				case "rf_gain":
					val := strings.ToLower(tok[1])
					if val == "auto" || val == "none" {
						*lnaGain = 20
					} else {
						gain, err := strconv.ParseUint(val, 10, 64)
						if err != nil {
							log.Printf("[DEBUG] Ignoring bad gain value in control command '%s': %v", cmd, err)
						}
						*lnaGain = uint(gain)
					}
					s.radio.SetLNAGain(*lnaGain)
				// case "new_receiver":
				// 	if len(tok) != 4 {
				// 		log.Printf("[DEBUG] Ignoring bad new_receiver command: %s", cmd)
				// 	}
				// 	iqPort, err := strconv.ParseUint(tok[1], 10, 64)
				// 	if err != nil {
				// 		log.Printf("[DEBUG] Ignoring bad IQ port value in control command '%s': %v", cmd, err)
				// 	}
				// 	controlPort, err := strconv.ParseUint(tok[2], 10, 64)
				// 	if err != nil {
				// 		log.Printf("[DEBUG] Ignoring bad control port value in control command '%s': %v", cmd, err)
				// 	}
				// 	frequency, err := strconv.ParseUint(tok[3], 10, 64)
				// 	if err != nil {
				// 		log.Printf("[DEBUG] Ignoring bad frequency value in control command '%s': %v", cmd, err)
				// 	}
				// 	addReceiver(r, uint(iqPort), uint(controlPort), uint(frequency))
				default:
					log.Printf("[DEBUG] Ignoring unsupported control command: %s", cmd)
				}
			}
		}
	}()

	log.Printf("[INFO] Listening on IQ port %d", iqPort)
	config = newReuseAddrListenConfig()
	iqListener, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", iqPort))
	if err != nil {
		log.Fatalf("Error listening on port %d: %v", iqPort, err)
	}
	go func() {
		for {
			log.Printf("[DEBUG] Calling Accept on IQ port %d", iqPort)
			iqConn, err = iqListener.Accept()
			if err != nil {
				log.Fatalf("Error accepting connection on port %d: %v", iqPort, err)
			}
			log.Printf("[DEBUG] Opened connection on IQ port %d", iqPort)
			go func(conn net.Conn) {
				sampleChan := distributor.Listen()
				defer distributor.Close(sampleChan)
				defer func() {
					log.Printf("[DEBUG] Closing IQ socket on port %d", iqPort)
					err = conn.Close()
					if err != nil {
						log.Printf("[DEBUG] Error closing IQ socket on port %d: %v", iqPort, err)
					}
				}()
				var samples []hpsdr.ReceiveSample
				for run := true; run; {
					samples, run = <-sampleChan
					if run {
						buf := make([]byte, len(samples)*8)
						for i, sample := range samples {
							binary.LittleEndian.PutUint32(buf[i*8:], math.Float32bits(sample.QFloat()))
							binary.LittleEndian.PutUint32(buf[i*8+4:], math.Float32bits(sample.IFloat()))
						}
						_, err := conn.Write(buf)
						if err != nil {
							log.Printf("[DEBUG] Error writing to IQ port %d: %v", iqPort, err)
							run = false
						}
					}
				}
			}(iqConn)
		}
	}()
}

func (s *Server) sendTransmitSamples() {
	ts := make([]hpsdr.TransmitSample, s.radio.TransmitSamplesPerMessage())
	for {
		// Send empty transmit samples to pass config changes and keep watchdog timer happy
		s.radio.SendSamples(ts)
		time.Sleep(time.Second / time.Duration(48000/s.radio.TransmitSamplesPerMessage()))
	}
}

// Distributor distributes received samples to one or more IQ goroutines
type Distributor struct {
	sync.RWMutex
	listeners map[chan []hpsdr.ReceiveSample]bool
}

// NewDistributor constructs a distributor
func NewDistributor() Distributor {
	return Distributor{
		listeners: map[chan []hpsdr.ReceiveSample]bool{},
	}
}

// Listen returms a channel for a listening goroutine to receive samples
func (d *Distributor) Listen() chan []hpsdr.ReceiveSample {
	c := make(chan []hpsdr.ReceiveSample, *sampleRate) // one second buffer
	d.Lock()
	d.listeners[c] = true
	d.Unlock()
	log.Printf("[DEBUG] Added listener %v", c)
	return c
}

// Close closes a channel when a goroutine is done
func (d *Distributor) Close(c chan []hpsdr.ReceiveSample) {
	log.Printf("[DEBUG] Removing listener %v", c)
	d.Lock()
	delete(d.listeners, c)
	d.Unlock()
	close(c)
	log.Printf("[DEBUG] Removed listener %v", c)
}

// Distribute receives samples from a radio and distributes them to listening goroutines
func (d *Distributor) Distribute(samples []hpsdr.ReceiveSample) {
	// log.Printf("[DEBUG] Got samples %#v", samples)
	d.RLock()
	for l := range d.listeners {
		select {
		case l <- samples:
			// fmt.Println("sent message")
		default:
			// Drop unsent samples on the floor
		}
	}
	d.RUnlock()
}
