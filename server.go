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
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/logutils"
	"github.com/jancona/hpsdrconnector/radio"
	"github.com/smallnest/ringbuffer"
)

const bufferSize = 2048

var (
	iqPort      *uint   = flag.Uint("port", 4590, "IQ listen port")
	frequency   *uint   = flag.Uint("frequency", 7100000, "Tune to specified frequency in Hz")
	sampleRate  *uint   = flag.Uint("samplerate", 96000, "Use the specified samplerate: one of 48000, 96000, 192000, 384000")
	lnaGain     *uint   = flag.Uint("gain", 20, "LNA gain between 0 (-12dB) and 60 (48dB)")
	controlPort *uint   = flag.Uint("control", 0, "control socket port (default disabled)")
	radioIP     *string = flag.String("radio", "", "IP address of radio (default use first radio discovered)")
	isDebug     *bool   = flag.Bool("debug", false, "Emit debug log messages on stdout")
	version     *bool   = flag.Bool("version", false, "Display program version and exit")
)

func init() {
	// {"version", no_argument, NULL, 'v'},
	flag.UintVar(iqPort, "p", 4590, "IQ listen port")
	flag.UintVar(frequency, "f", 7100000, "Tune to specified frequency in Hz")
	flag.UintVar(sampleRate, "s", 96000, "Use the specified samplerate: one of 48000, 96000, 192000, 384000")
	flag.UintVar(lnaGain, "g", 20, "LNA gain between 0 (-12dB) and 60 (48dB)")
	flag.UintVar(controlPort, "c", 0, "control socket port (default disabled)")
	flag.StringVar(radioIP, "r", "", "IP address of radio (default use first radio discovered)")
	flag.BoolVar(isDebug, "d", false, "Emit debug log messages on stdout")
	flag.BoolVar(version, "v", false, "Display program version and exit")
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
	if *version {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			log.Fatal("Unable to retrieve BuildInfo")
		}
		fmt.Printf("%s %s\n", os.Args[0], bi.Main.Version)
		os.Exit(0)
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
		devices, err := radio.DiscoverDevices()
		if err != nil {
			log.Printf("[ERROR] Error discovering devices:%v", err)
		}
		log.Printf("[DEBUG] main: devices: %#v", devices)
		if len(devices) == 0 {
			log.Fatal("No devices detected. Exiting.")
		}
		addr = devices[0].Network.Address
	}
	r := radio.NewMetisState(addr)
	r.SetSampleRate(*sampleRate)
	r.SetRX1Frequency(*frequency)
	r.SetReceiveLNAGain(*lnaGain)
	log.Printf("[INFO] Starting radio on %s", addr.String())
	var controlConn, iqConn net.Conn
	rb := ringbuffer.New(int(*sampleRate) * 8 * 10) // 10 seconds
	err = r.Start()
	if err != nil {
		log.Fatalf("Error starting radio %v: %v", *r, err)
	}
	go func() {
		var count uint
		for {
			buf := new(bytes.Buffer)
			r.ReceiveSamples(
				func(r *radio.MetisState, samples []radio.ReceiverSample) {
					// log.Printf("[DEBUG] Got samples %#v", samples)
					for _, sample := range samples {
						binary.Write(buf, binary.LittleEndian, sample.QFloat())
						binary.Write(buf, binary.LittleEndian, sample.IFloat())
					}
					cnt, err := rb.Write(buf.Bytes())
					if err != nil {
						log.Printf("[INFO] Error writing to ringbuffer: %v", err)
					}
					if cnt <= 0 {
						log.Printf("[INFO] Wrote %d to ringbuffer", cnt)
					}
					buf.Reset()
					// Send empty transmit samples to pass config changes and keep watchdog timer happy
					if count%((*sampleRate/48000)*2) == 0 {
						r.SendSamples([]radio.TransmitSample{})
					}
					count++
				})
		}
	}()

	if *controlPort > 0 {
		log.Printf("[INFO] Listening on control port %d", *controlPort)
		config := newReuseAddrListenConfig()
		controlListener, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", *controlPort))
		if err != nil {
			log.Fatalf("Error listening on control port %d: %v", *controlPort, err)
		}
		go func() {
			for {
				log.Printf("[DEBUG] Calling Accept on control port %d", *controlPort)
				controlConn, err = controlListener.Accept()
				if err != nil {
					log.Fatalf("Error accepting connection on control port %d: %v", *controlPort, err)
				}
				log.Printf("[INFO] Opened connection on control port %d", *controlPort)
				run := true
				buf := make([]byte, 128)
				for run {
					cnt, err := controlConn.Read(buf)
					if err != nil {
						log.Printf("[ERROR] Error reading control socket: %v", err)
						run = false
						break
					}
					if cnt <= 0 {
						run = false
						break
					}
					cmd := strings.Trim(string(buf), "\x00\n ")
					log.Printf("[INFO] Received command '%s'", cmd)
					tok := strings.Split(cmd, ":")
					if len(tok) != 2 {
						log.Printf("[INFO] Ignoring invalid command '%s'", cmd)
						continue
					}
					switch tok[0] {
					case "samp_rate":
						sr, err := strconv.ParseUint(tok[1], 10, 64)
						if err != nil {
							log.Printf("[INFO] Ignoring bad sample rate value in control command '%s': %v", cmd, err)
						}
						*sampleRate = uint(sr)
						r.SetSampleRate(*sampleRate)
					case "center_freq":
						f, err := strconv.ParseUint(tok[1], 10, 64)
						if err != nil {
							log.Printf("[INFO] Ignoring bad center frrequency value in control command '%s': %v", cmd, err)
						}
						*frequency = uint(f)
						r.SetRX1Frequency(*frequency)
					case "rf_gain":
						val := strings.ToLower(tok[1])
						if val == "auto" || val == "none" {
							*lnaGain = 20
						} else {
							gain, err := strconv.ParseUint(val, 10, 64)
							if err != nil {
								log.Printf("[INFO] Ignoring bad gain value in control command '%s': %v", cmd, err)
							}
							*lnaGain = uint(gain)
						}
						r.SetReceiveLNAGain(*lnaGain)
					default:
						log.Printf("[INFO] Ignoring unsupported control command: %s", cmd)
					}
				}
			}
		}()
	}
	// time.Sleep(5 * time.Second)
	log.Printf("[INFO] Listening on IQ port %d", *iqPort)
	config := newReuseAddrListenConfig()
	iqListener, err := config.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", *iqPort))
	if err != nil {
		log.Fatalf("Error listening on port %d: %v", *iqPort, err)
	}
	go func() {
		for {
			log.Printf("[INFO] Calling Accept on IQ port %d", *iqPort)
			iqConn, err = iqListener.Accept()
			if err != nil {
				log.Fatalf("Error accepting connection on port %d: %v", *iqPort, err)
			}
			log.Printf("[INFO] Opened connection on IQ port %d", *iqPort)

			// dummy := make([]byte, 128)
			// iqConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			// _, err := iqConn.Read(dummy)
			// if err != nil {
			// 	log.Printf("[ERROR] Error reading IQ socket: %v", err)
			// }

			b := make([]byte, 504)
			for run := true; run; {
				cnt, err := rb.Read(b)
				if cnt > 0 {
					_, err := iqConn.Write(b[:cnt])
					if err != nil {
						log.Printf("[INFO] Error writing to IQ port %d: %v", *iqPort, err)
						run = false
					}
				}
				if err != nil && err != ringbuffer.ErrIsEmpty {
					log.Printf("[INFO] Error reading from ringbuffer: %v", err)
					run = false
				}
				if cnt == 0 || err == ringbuffer.ErrIsEmpty {
					// log.Printf("[INFO] No data read")
					// run = false
					// time.Sleep(time.Second / time.Duration(*sampleRate*2))
					time.Sleep(time.Second / time.Duration(*sampleRate))
				}
			}
			log.Printf("[INFO] Closing IQ socket on port %d", *iqPort)
			err = iqConn.Close()
			if err != nil {
				log.Printf("[INFO] Error closing IQ socket on port %d: %v", *iqPort, err)
			}
		}
	}()

	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan struct{})
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		log.Print("Received an interrupt, stopping...")
		r.Close()
		if controlConn != nil {
			controlConn.Close()
		}
		if iqConn != nil {
			iqConn.Close()
		}
		close(cleanupDone)
	}()
	<-cleanupDone
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
