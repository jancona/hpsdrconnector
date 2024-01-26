//go:build !windows

// Copyright 2020, 2021 James P. Ancona

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
	"bufio"
	"context"
	"encoding/binary"
	"errors"
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

var (
	iqPortArg      *uint   = flag.Uint("port", 4590, "IQ listen port")
	frequencyArg   *uint   = flag.Uint("frequency", 7100000, "Tune to specified frequency in Hz")
	sampleRateArg  *uint   = flag.Uint("samplerate", 96000, "Use the specified samplerate: one of 48000, 96000, 192000, 384000")
	lnaGainArg     *uint   = flag.Uint("gain", 20, "LNA gain between 0 (-12dB) and 60 (48dB)")
	controlPortArg *uint   = flag.Uint("control", 4591, "control socket port (default 4591)")
	radioIPArg     *string = flag.String("radio", "", "IP address of radio (default use first radio discovered)")
	isDebugArg     *bool   = flag.Bool("debug", false, "Emit debug log messages on stdout")
	isServerArg    *bool   = flag.Bool("server", false, "Run as the server process")
	serverPortArg  *uint   = flag.Uint("serverPort", 7300, "Server port for this radio")
	serverLogArg   *string = flag.String("serverLog", "", "Device/file for server log (default stdout)")
)

func init() {
	flag.UintVar(iqPortArg, "p", 4590, "IQ listen port")
	flag.UintVar(frequencyArg, "f", 7100000, "Tune to specified frequency in Hz")
	flag.UintVar(sampleRateArg, "s", 96000, "Use the specified samplerate: one of 48000, 96000, 192000, 384000")
	flag.UintVar(lnaGainArg, "g", 20, "LNA gain between 0 (-12dB) and 60 (48dB)")
	flag.UintVar(controlPortArg, "c", 4591, "control socket port (default 4591)")
	flag.StringVar(radioIPArg, "r", "", "IP address of radio (default use first radio discovered)")
	flag.BoolVar(isDebugArg, "d", false, "Emit debug log messages on stdout")
}

func main() {
	var err error

	flag.Parse()
	minLogLevel := "INFO"
	if *isDebugArg {
		minLogLevel = "DEBUG"
	}
	logWriter := os.Stdout
	if *serverLogArg != "" {
		logWriter, err = os.OpenFile(*serverLogArg, os.O_WRONLY|os.O_CREATE|os.O_SYNC, 0644)
		if err != nil {
			log.Fatalf("client: Error opening server output, exiting: %v", err)
		}
	}

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "ERROR"},
		MinLevel: logutils.LogLevel(minLogLevel),
		Writer:   logWriter,
	}
	log.SetOutput(filter)
	log.Print("[DEBUG] Debug is on")

	serverConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", *serverPortArg))
	if *isServerArg {
		if err != nil {
			// Run as a server
			runAsServer()
			os.Exit(0)
		} else {
			log.Fatalf("Attempting to start a server on port %d, but one is already running", *serverPortArg)
		}
	} else {
		runAsClient(serverConn, err)
	}
}

func runAsClient(serverConn net.Conn, err error) {
	if err != nil {
		log.Printf("[DEBUG] client: No server running, starting one on port %d", *serverPortArg)
		// No server running, so start one
		args := []string{
			"--server",
			"--serverPort", strconv.FormatUint(uint64(*serverPortArg), 10),
			"--samplerate", strconv.FormatUint(uint64(*sampleRateArg), 10),
			"--gain", strconv.FormatUint(uint64(*lnaGainArg), 10),
		}
		if *radioIPArg != "" {
			args = append(args, "--radio", *radioIPArg)
		}
		if *isDebugArg {
			args = append(args, "--debug")
		}
		log.Printf("[DEBUG] client: Server args: %v", args)
		cmd := exec.Command("hpsdrconnector", args...)
		cmd.SysProcAttr =
			&syscall.SysProcAttr{
				// Start server in its own process group so it survives the death of the client
				Setpgid: true,
				Pgid:    0,
			}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			log.Fatalf("client: Unable to launch hpsdrconnector server, exiting: %v", err)
		}
		for i := 0; i < 10; i++ {
			serverConn, err = net.Dial("tcp", fmt.Sprintf("localhost:%d", *serverPortArg))
			if err != nil {
				log.Printf("client: Failed to connect to hpsdrconnector server, exiting: %v", err)
			}
			if serverConn != nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			log.Fatalf("client: Unable to connect to hpsdrconnector server, exiting: %v", err)
		}
	}
	// We should now have a server to talk to
	cmd := fmt.Sprintf("new_receiver:%d:%d:%d", *iqPortArg, *controlPortArg, *frequencyArg)
	log.Printf("[DEBUG] client: Sending command '%s' to server", cmd)
	_, err = serverConn.Write([]byte(cmd))
	if err != nil {
		log.Fatalf("client: Error sending command '%s' to server, exiting: %v", cmd, err)
	}
	// Run until we're terminated then tell server to close receiver
	log.Print("[DEBUG] client: Waiting for close signal")
	// wait for a close signal then clean up
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan struct{})
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		log.Print("client: Received an interrupt, stopping...")
		// Send close_receiver command to server
		cmd := fmt.Sprintf("close_receiver:%d", *controlPortArg)
		_, err = serverConn.Write([]byte(cmd))
		if err != nil {
			log.Fatalf("client: Error sending command '%s' to server, exiting: %v", cmd, err)
		}
		close(cleanupDone)
	}()
	<-cleanupDone
}

func runAsServer() {
	log.Printf("[DEBUG] server(%d): Starting", *serverPortArg)

	switch *sampleRateArg {
	case 48000:
	case 96000:
	case 192000:
	case 384000:
	default:
		log.Fatalf("Invalid sample rate %d. Must be one of 48000, 96000, 192000, 384000", *sampleRateArg)
	}

	if *lnaGainArg > 60 {
		log.Fatalf("Invalid LNA gain %d. Must be between 0 and 60", *lnaGainArg)
	}

	device, err := discoverDevice(*radioIPArg)
	if err != nil {
		log.Fatalf("Error discovering device, exiting: %v", err)
	}

	server := &Server{
		port:          *serverPortArg,
		receivers:     map[uint]hpsdr.Receiver{},
		stopReceivers: map[uint]chan struct{}{},
	}

	server.radio = protocol1.NewRadio(device)
	server.radio.SetSampleRate(*sampleRateArg)
	server.radio.SetTXFrequency(*frequencyArg)
	server.radio.SetLNAGain(*lnaGainArg)

	done := make(chan struct{})
	log.Printf("[INFO] server(%d): Listening to radio on %v", server.port, device.Network.Address.String())
	config := newReuseAddrListenConfig()
	l, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", server.port))
	if err != nil {
		log.Fatalf("Error listening on server port %d: %v", server.port, err)
	}
	serverListener, ok := l.(*net.TCPListener)
	if !ok {
		log.Fatalf("serverListener on port %d is not a TCPListener", server.port)
	}
	go server.handleServerListener(serverListener, done)
	log.Printf("[INFO] server(%d): Starting %s radio with up to %d receivers on %s", server.port, device.Name, device.SupportedReceivers, device.Network.Address.String())
	err = server.radio.Start()
	if err != nil {
		log.Fatalf("Error starting radio %s: %v", device.Name, err)
	}
	go server.sendTransmitSamples()
	<-done
	log.Printf("[INFO] server(%d): Exiting...", server.port)
	server.radio.Close()
	log.Printf("[INFO] server(%d): Done", server.port)
}

func discoverDevice(radioIP string) (*hpsdr.Device, error) {
	var device *hpsdr.Device
	var err error
	if radioIP != "" {
		device, err = hpsdr.DiscoverDevice(radioIP)
		if err != nil {
			return nil, fmt.Errorf("error locating device at %s: %v", radioIP, err)
		}
		if device == nil {
			return nil, fmt.Errorf("no device found at %s", radioIP)
		}
	} else {
		devices, err := hpsdr.DiscoverDevices()
		if err != nil {
			log.Printf("[ERROR] Error discovering devices: %v", err)
		}
		log.Printf("[DEBUG] main: devices: %#v", devices)
		if len(devices) == 0 {
			return nil, errors.New("no devices detected")
		}
		device = devices[0]
	}
	return device, nil
}

// Server represents the radio server
type Server struct {
	port          uint
	radio         hpsdr.Radio
	receiverMutex sync.RWMutex
	receivers     map[uint]hpsdr.Receiver
	stopReceivers map[uint]chan struct{}
}

func (s *Server) handleServerListener(serverListener *net.TCPListener, done chan struct{}) {
	log.Printf("[DEBUG] server(%d): handleServerListener starting", s.port)
	timeoutCount := 0
	for {
		err := serverListener.SetDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			log.Printf("[DEBUG] server(%d): serverListener.SetDeadline error: %v", s.port, err)
		}
		// log.Printf("[DEBUG] server(%d): Calling Accept", s.port)
		serverConn, err := serverListener.Accept()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if s.receiverCount() == 0 {
				timeoutCount++
				log.Printf("[DEBUG] server(%d): serverListener.Accept() timeout with no receivers, timeoutCount=%d", s.port, timeoutCount)
				if timeoutCount > 1 {
					// we waited at least 10 seconds with no receivers added, so exit
					log.Printf("[DEBUG] server(%d): serverListener.Accept() timeout with no receivers, exiting...", s.port)
					break
				}
			} else {
				timeoutCount = 0
			}
			continue
		} else if err != nil {
			log.Fatalf("server(%d): Error accepting connection on server port: %v", s.port, err)
		}
		log.Printf("[DEBUG] server(%d): Opened connection on server port", s.port)
		go s.handleServerConn(serverConn)
	}
	log.Printf("[DEBUG] server(%d): All receivers closed for more than 10s, so exiting", s.port)
	close(done)
}

func (s *Server) handleServerConn(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 128)
	for run := true; run; {
		cnt, err := c.Read(buf)
		if err != nil {
			log.Printf("[DEBUG] server(%d): Error reading server socket: %v", s.port, err)
			run = false
			break
		}
		if cnt <= 0 {
			log.Printf("[DEBUG] server(%d): c.Read() count=%d, closing", s.port, cnt)
			run = false
			break
		}
		cmd := strings.Trim(string(buf[:cnt]), "\x00\r\n ")
		log.Printf("[DEBUG] server(%d): Received server command '%s'", s.port, cmd)
		tok := strings.Split(cmd, ":")
		switch tok[0] {
		case "new_receiver":
			if len(tok) != 4 {
				log.Printf("[DEBUG] server(%d): Ignoring bad new_receiver command: %s", s.port, cmd)
				continue
			}
			iqPort, err := strconv.ParseUint(tok[1], 10, 64)
			if err != nil {
				log.Printf("[DEBUG] server(%d): Ignoring new_receiver command with bad IQ port value '%s': %v", s.port, cmd, err)
				continue
			}
			controlPort, err := strconv.ParseUint(tok[2], 10, 64)
			if err != nil {
				log.Printf("[DEBUG] server(%d): Ignoring new_receiver command with bad control port value '%s': %v", s.port, cmd, err)
				continue
			}
			frequency, err := strconv.ParseUint(tok[3], 10, 64)
			if err != nil {
				log.Printf("[DEBUG] server(%d): Ignoring new_receiver command with bad frequency value '%s': %v", s.port, cmd, err)
				continue
			}
			err = s.addReceiver(uint(iqPort), uint(controlPort), uint(frequency))
			if err != nil {
				log.Printf("[DEBUG] server(%d): Unable to execute server command '%s': %v", s.port, cmd, err)
				continue
			}
		case "close_receiver":
			if len(tok) != 2 {
				log.Printf("[DEBUG] server(%d): Ignoring bad close_receiver command: %s", s.port, cmd)
				continue
			}
			controlPort, err := strconv.ParseUint(tok[1], 10, 64)
			if err != nil {
				log.Printf("[DEBUG] server(%d): Ignoring close_receiver command with bad control port value '%s': %v", s.port, cmd, err)
				continue
			}
			s.closeReceiver(uint(controlPort))
			log.Printf("[INFO] server(%d): Closed receiver listening on control port %d, %d receivers left", s.port, controlPort, s.receiverCount())
		default:
			log.Printf("[DEBUG] server(%d): Ignoring unsupported server command: %s", s.port, cmd)
		}
	}
}

func (s *Server) addReceiver(iqPort uint, controlPort uint, frequency uint) error {
	log.Printf("[DEBUG] server(%d): addReceiver(%d, %d, %d)", s.port, iqPort, controlPort, frequency)
	distributor := NewDistributor(s.port)

	rec, err := s.radio.AddReceiver(distributor.Distribute)
	if err != nil {
		log.Printf("[DEBUG] server(%d): radio.AddReceiver returned error: %v", s.port, err)
		return err
	}
	log.Printf("[DEBUG] server(%d): Added receiver on control port %d, closed: %v", s.port, controlPort, rec.IsClosed())
	stopReceiver := make(chan struct{})
	s.receiverMutex.Lock()
	s.receivers[controlPort] = rec
	s.stopReceivers[controlPort] = stopReceiver
	s.receiverMutex.Unlock()

	log.Printf("[INFO] server(%d): Added receiver listening on control port %d", s.port, controlPort)
	l, err := s.retrySocketListen(controlPort)
	if err != nil {
		s.closeReceiver(controlPort)
		return fmt.Errorf("error listening on control port %d: %w", controlPort, err)
	}
	controlListener, ok := l.(*net.TCPListener)
	if !ok {
		log.Fatal("controlListener is not a TCPListener")
	}
	go s.handleControlListener(controlListener, controlPort, rec, stopReceiver)

	log.Printf("[INFO] server(%d): Listening on IQ port %d", s.port, iqPort)
	l, err = s.retrySocketListen(iqPort)
	if err != nil {
		s.closeReceiver(controlPort)
		return fmt.Errorf("error listening on IQ port %d: %w", iqPort, err)
	}

	iqListener, ok := l.(*net.TCPListener)
	if !ok {
		log.Fatal("iqListener is not a TCPListener")
	}
	go s.handleIQListener(iqListener, iqPort, distributor, stopReceiver)

	rec.SetFrequency(frequency)
	s.checkHPF()
	return nil
}

func (s *Server) retrySocketListen(port uint) (net.Listener, error) {
	log.Printf("[DEBUG] server(%d): retrySocketListen(%d)", s.port, port)
	config := newReuseAddrListenConfig()
	retry := 5
	for {
		controlListener, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil || retry == 0 {
			if err == nil {
				log.Printf("[DEBUG] server(%d): retrySocketListen(%d) returns success", s.port, port)
			} else {
				log.Printf("[DEBUG] server(%d): retrySocketListen(%d) returns error %v", s.port, port, err)
			}
			return controlListener, err
		}
		retry--
		log.Printf("[DEBUG] server(%d): Error listening on port %d, %d retries remaining: %v", s.port, port, retry, err)
		time.Sleep(500 * time.Millisecond)
	}
}

func (s *Server) handleControlListener(controlListener *net.TCPListener, controlPort uint, rec hpsdr.Receiver, stopReceiver chan struct{}) {
	var controlConn net.Conn
	var err error
	var run, globalRun bool
	globalRun = true
	go func() {
		<-stopReceiver
		log.Printf("[DEBUG] server(%d): handleControlListener() on port %d received stopReceiver", s.port, controlPort)
		globalRun = false
		run = false
		if controlConn != nil {
			log.Printf("[DEBUG] server(%d): Closing connection on control port %d, %s", s.port, controlPort, controlConn.LocalAddr().String())
			err := controlConn.Close()
			if err != nil {
				log.Printf("[ERROR] server(%d): Error closing connection on control port %d, %s: %v", s.port, controlPort, err, controlConn.LocalAddr().String())
			}
		}
		log.Printf("[DEBUG] server(%d): Calling controlListener.Close() for port %d", s.port, controlPort)
		err := controlListener.Close()
		if err != nil {
			log.Printf("[DEBUG] server(%d): Error closing listener for control port %d, %s: %v", s.port, controlPort, controlListener.Addr().String(), err)
		}
		log.Printf("[DEBUG] server(%d): Finished controlListener.Close() for port %d", s.port, controlPort)
	}()
	log.Printf("[DEBUG] server(%d): Control goroutine for port %d starting", s.port, controlPort)
	for globalRun {
		log.Printf("[DEBUG] Calling Accept on control port %d", controlPort)
		controlConn, err = controlListener.Accept()
		if err != nil {
			log.Printf("[ERROR] server(%d): Error accepting connection on control port %d: %v", s.port, controlPort, err)
			break
		}
		log.Printf("[DEBUG] server(%d): Opened connection on control port %d", s.port, controlPort)
		go func(conn net.Conn) {
			for run = true; run; {
				buf := make([]byte, 128)
				cnt, err := conn.Read(buf)
				if err != nil {
					log.Printf("[DEBUG] server(%d): Error reading on control socket %d: %v", s.port, controlPort, err)
					run = false
					break
				}
				if cnt <= 0 {
					log.Printf("[DEBUG] server(%d): Zero-length read on control socket %d", s.port, controlPort)
					run = false
					break
				}
				cmd := strings.Trim(string(buf[:cnt]), "\x00\r\n ")
				log.Printf("[DEBUG] server(%d): Received command '%s'", s.port, cmd)
				tok := strings.Split(cmd, ":")
				log.Printf("[DEBUG] len(tok)=%d", len(tok))
				if len(tok) != 2 {
					log.Printf("[DEBUG] server(%d): Ignoring invalid command '%s'", s.port, cmd)
					continue
				}
				switch tok[0] {
				case "samp_rate":
					sr, err := strconv.ParseUint(tok[1], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] server(%d): Ignoring bad sample rate value in control command '%s': %v", s.port, cmd, err)
						continue
					}
					s.radio.SetSampleRate(uint(sr))
				case "center_freq":
					f, err := strconv.ParseUint(tok[1], 10, 64)
					if err != nil {
						log.Printf("[DEBUG] server(%d): Ignoring bad center frequency value in control command '%s': %v", s.port, cmd, err)
						continue
					}
					rec.SetFrequency(uint(f))
					s.checkHPF()
				case "rf_gain":
					val := strings.ToLower(tok[1])
					var lnaGain uint
					if val == "auto" || val == "none" {
						lnaGain = 20
					} else {
						gain, err := strconv.ParseUint(val, 10, 64)
						if err != nil {
							log.Printf("[DEBUG] server(%d): Ignoring bad gain value in control command '%s': %v", s.port, cmd, err)
						}
						lnaGain = uint(gain)
					}
					s.radio.SetLNAGain(lnaGain)
				default:
					log.Printf("[DEBUG] server(%d): Ignoring unsupported control command: %s", s.port, cmd)
				}
			}
		}(controlConn)
	}
	log.Printf("[INFO] server(%d): Control goroutine for port %d exiting", s.port, controlPort)
}

func (s *Server) handleIQListener(iqListener *net.TCPListener, iqPort uint, distributor *Distributor, stopReceiver chan struct{}) {
	var iqConn net.Conn
	var err error
	globalRun := true
	go func() {
		<-stopReceiver
		log.Printf("[DEBUG] server(%d): handleIQListener() on port %d received stopReceiver", s.port, iqPort)
		globalRun = false
		if iqConn != nil {
			err = iqConn.Close()
			if err != nil {
				log.Printf("[DEBUG] server(%d): Error closing IQ socket on port %d: %v", s.port, iqPort, err)
			}
		}
		log.Printf("[DEBUG] server(%d): Calling iqListener.Close() for port %d", s.port, iqPort)
		err = iqListener.Close()
		if err != nil {
			log.Printf("[DEBUG] server(%d): Error closing IQ listener on port %d: %v", s.port, iqPort, err)
		}
		log.Printf("[DEBUG] server(%d): Finished iqListener.Close() for port %d", s.port, iqPort)
	}()
	for globalRun {
		log.Printf("[DEBUG] server(%d): Calling Accept on IQ port %d", s.port, iqPort)
		iqConn, err = iqListener.Accept()
		if err != nil {
			log.Printf("[ERROR] server(%d): Error accepting connection on IQ port %d: %v", s.port, iqPort, err)
			break
		}
		log.Printf("[DEBUG] server(%d): Opened connection on IQ port %d", s.port, iqPort)
		go func(conn net.Conn) {
			bufConn := bufio.NewWriterSize(conn, 8192)
			sampleChan := distributor.Listen()
			defer func() {
				log.Printf("[DEBUG] server(%d): Calling distributor.Close() for IQ port %d", s.port, iqPort)
				distributor.Close(sampleChan)
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
					_, err := bufConn.Write(buf)
					if err != nil {
						log.Printf("[DEBUG] server(%d): Error writing to IQ port %d: %v", s.port, iqPort, err)
						return
					}
				}
			}
		}(iqConn)
	}
	log.Printf("[DEBUG] server(%d): IQ goroutine for port %d exiting", s.port, iqPort)
}

func (s *Server) sendTransmitSamples() {
	ts := make([]hpsdr.TransmitSample, s.radio.TransmitSamplesPerMessage())
	for {
		// Send empty transmit samples to pass config changes and keep watchdog timer happy
		s.radio.SendSamples(ts)
		time.Sleep(time.Second / time.Duration(48000/s.radio.TransmitSamplesPerMessage()))
	}
}

func (s *Server) receiverCount() int {
	s.receiverMutex.RLock()
	defer s.receiverMutex.RUnlock()
	return len(s.receivers)
}

func (s *Server) closeReceiver(controlPort uint) {
	log.Printf("[DEBUG] server(%d): closeReceiver(%d)", s.port, controlPort)
	s.receiverMutex.Lock()
	defer s.receiverMutex.Unlock()
	// tell goroutines to exit
	close(s.stopReceivers[controlPort])
	delete(s.stopReceivers, controlPort)
	rec := s.receivers[controlPort]
	if rec == nil {
		log.Printf("[INFO] server(%d): Receiver on control port %d already closed", s.port, controlPort)
		return
	}
	err := rec.Close()
	if err != nil {
		log.Printf("[INFO] server(%d): Error closing receiver on control port %d", s.port, controlPort)
	}
	delete(s.receivers, controlPort)
}

func (s *Server) checkHPF() {
	if s.radio.Device().Device == hpsdr.DeviceHermesLite2 {
		s.receiverMutex.RLock()
		defer s.receiverMutex.RUnlock()
		minFrequency := uint(math.MaxUint32)
		for _, r := range s.receivers {
			f := r.GetFrequency()
			if f < minFrequency {
				minFrequency = f
			}
		}
		log.Printf("[DEBUG] server(%d): minFrequency: %d", s.port, minFrequency)
		if minFrequency >= 3000000 {
			// Turn on high pass filter
			s.radio.SetOCOut(0b1000000)
		} else {
			s.radio.SetOCOut(0)
		}
	}
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

// Distributor distributes received samples to one or more IQ goroutines
type Distributor struct {
	sync.RWMutex
	serverPort uint
	listeners  map[chan []hpsdr.ReceiveSample]bool
}

// NewDistributor constructs a distributor
func NewDistributor(p uint) *Distributor {
	return &Distributor{
		serverPort: p,
		listeners:  map[chan []hpsdr.ReceiveSample]bool{},
	}
}

// Listen returms a channel for a listening goroutine to receive samples
func (d *Distributor) Listen() chan []hpsdr.ReceiveSample {
	c := make(chan []hpsdr.ReceiveSample, *sampleRateArg) // one second buffer
	d.Lock()
	d.listeners[c] = true
	d.Unlock()
	log.Printf("[DEBUG] server(%d): Added listener %v", d.serverPort, c)
	return c
}

// Close closes a channel when a goroutine is done
func (d *Distributor) Close(c chan []hpsdr.ReceiveSample) {
	log.Printf("[DEBUG] server(%d): Removing listener %v", d.serverPort, c)
	d.Lock()
	delete(d.listeners, c)
	d.Unlock()
	close(c)
	log.Printf("[DEBUG] server(%d): Removed listener %v", d.serverPort, c)
}

// Distribute receives samples from a radio and distributes them to listening goroutines
func (d *Distributor) Distribute(samples []hpsdr.ReceiveSample) {
	// log.Printf("[DEBUG] Got %d samples", len(samples))
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
