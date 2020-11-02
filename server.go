package main // "github.com/jancona/hpsdrconnector"

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/hashicorp/logutils"
	"github.com/jancona/hpsdrconnector/radio"
)

const bufferSize = 2048

var (
	listenPort  uint
	frequency   uint
	sampleRate  uint
	lnaGain     uint
	controlPort uint
	radioIP     string
	debug       bool
)

func init() {
	flag.StringVar(&radioIP, "radio", "", "IP address of radio (default use first radio discovered)")
	flag.UintVar(&frequency, "frequency", 7100000, "Tune to specified frequency in Hz")
	flag.UintVar(&sampleRate, "samplerate", 96000, "Use the specified samplerate: one of 48000, 96000, 192000, 384000")
	flag.UintVar(&lnaGain, "gain", 20, "LNA gain between 0 (-12dB) and 60 (48dB)")
	flag.BoolVar(&debug, "debug", false, "Emit debug log messages on stderr")
	// flag.UintVar(&listenPort, "port", 4590, "listen port")
	// flag.UintVar(&controlPort, "control", 0, "control socket port (default disabled)")
}

func main() {
	flag.Parse()
	minLogLevel := ""
	if debug {
		minLogLevel = "DEBUG"
	}

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG"},
		MinLevel: logutils.LogLevel(minLogLevel),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)
	log.Print("[DEBUG] Debug is on")

	var addr *net.UDPAddr
	var err error
	if radioIP != "" {
		a := radioIP + ":1024"
		addr, err = net.ResolveUDPAddr("udp", a)
		if err != nil {
			log.Fatalf("Error resolving receiver address %s: %v", a, err)
		}
	} else {
		devices, err := radio.DiscoverDevices()
		if err != nil {
			log.Print(err)
		}
		log.Printf("[DEBUG] main: devices: %#v", devices)
		if len(devices) == 0 {
			log.Fatal("No devices detected. Exiting.")
		}
		addr = devices[0].Network.Address
	}
	r := radio.NewMetisState(addr)
	r.SetSampleRate(sampleRate)
	r.SetRX1Frequency(frequency)
	r.SetReceiveLNAGain(lnaGain)
	err = r.Start()
	if err != nil {
		log.Fatalf("Error starting radio %v: %v", *r, err)
	}
	go func() {
		for {
			r.ReceiveSamples(outIQ)
		}
	}()
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan struct{})
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		log.Print("Received an interrupt, stopping...")
		r.Close()
		close(cleanupDone)
	}()
	<-cleanupDone
}

var count uint

func outIQ(r *radio.MetisState, samples []radio.ReceiverSample) {
	// log.Printf("Got samples %#v", samples)
	// buf := new(bytes.Buffer)
	for _, sample := range samples {
		// binary.Write(buf, binary.LittleEndian, sample.QFloat())
		// binary.Write(buf, binary.LittleEndian, sample.IFloat())
		os.Stdout.Write([]byte{sample.Q2, sample.Q1, sample.Q0, sample.I2, sample.I1, sample.I0})
	}
	// os.Stdout.Write(buf.Bytes())
	if count%((sampleRate/48000)*2) == 0 {
		r.SendSamples([]radio.TransmitSample{})
	}
	count++
}

// func outIQ(samples hpsdrEP6Data) {
// 	for _, sample := range samples {
// 		os.Stdout.Write([]byte{sample.Q2, sample.Q1, sample.Q0, sample.I2, sample.I1, sample.I0})
// 	}
// }
