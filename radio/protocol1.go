package radio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

const lastEP2Address = 63

type metisEndpoint byte

// Valid metisEndpoint values
const (
	EP2 metisEndpoint = 0x2 // PC->Radio: Command and Control plus two audio streams
	EP4 metisEndpoint = 0x4 // Radio->PC: Bandscope data
	EP6 metisEndpoint = 0x6 // Radio->PC: IQ + microphone data
)

// Metis start/stop commands
const (
	metisStartIQ        = 0b01
	metisStartBandscope = 0b10
	metisStop           = 0
)

// MetisMessage represents a message sent to or from the radio
type MetisMessage struct {
	EF             byte
	FE             byte
	ID01           byte // If we were doing bootloader operations, we would need to be able to set this
	EndPoint       metisEndpoint
	SequenceNumber uint32
	Frame1         [512]byte
	Frame2         [512]byte
}

// NewMetisMessage builds a new Metis message for sending
func (state *MetisState) NewMetisMessage(endPoint metisEndpoint, frame1, frame2 [512]byte) MetisMessage {
	ret := MetisMessage{
		EF:             0xEF,
		FE:             0xFE,
		ID01:           0x01,
		EndPoint:       endPoint,
		SequenceNumber: state.sentSeqNum,
		Frame1:         frame1,
		Frame2:         frame2,
	}
	state.sentSeqNum++
	return ret
}

// MetisMessageFromBuffer deserializes a MetisMessage
func MetisMessageFromBuffer(buf *bytes.Buffer) (*MetisMessage, error) {
	mm := MetisMessage{}
	err := binary.Read(buf, binary.BigEndian, &mm)
	if err != nil {
		return nil, fmt.Errorf("Error deserializing MetisMessage: %w", err)
	}
	// do some sanity checks
	if mm.EF != 0xEF ||
		mm.FE != 0xFe ||
		mm.ID01 != 0x01 {
		return nil, fmt.Errorf("Received corrupted message: %#v", mm)
	}
	log.Printf("[DEBUG] Received MetisMessage: Endpoint %x, SequenceNumber %d", mm.EndPoint, mm.SequenceNumber)

	return &mm, nil
}

// Bytes serializes a MetisMessage as a byte slice
func (m *MetisMessage) Bytes() ([]byte, error) {
	log.Printf("[DEBUG] MetisMessage.Bytes(): %#v", *m)
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, m)
	return buf.Bytes(), err
}

// MetisState is the current desired state of the radio
type MetisState struct {
	running       bool
	deviceAddress *net.UDPAddr
	conn          *net.UDPConn

	sendIQ        bool
	sendBandscope bool
	mox           bool
	// These are the HL2 address definitions from https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#base-memory-map
	// since that is all we aim to support for now.
	// 0x00	[25:24]	Speed (00=48kHz, 01=96kHz, 10=192kHz, 11=384kHz)
	speed byte // 0b00=48kHz, 0b01=96kHz, 0b10=192kHz, 0b11=384kHz
	// 0x00	[23:17]	Open Collector Outputs on Penelope or Hermes
	ocOut byte
	// 0x00	[13]	Control MCP23008 GP7 (I2C device on N2ADR filter board) (0=TX antenna, 1=RX antenna)
	rxAntenna bool // false=TX antenna, true=RX antenna
	// 0x00	[12]	FPGA-generated power supply switching clock (0=on, 1=off)
	clockOff bool // false=on, true=off
	// 0x00	[10]	VNA fixed RX Gain (0=-6dB, 1=+6dB)
	vnaGain bool // false=-6db, true=+6db
	// 0x00	[6:3]	Number of Receivers (0000=1 to max 1011=12)
	receiverCount byte // 0b0000=1 to max 0b1011=12 - Note that this is number of receivers minus one
	// 0x00	[2]	Duplex (0=off, 1=on)
	duplex bool // false=off, true=on
	// 0x01	[31:0]	TX1 NCO Frequency in Hz
	tx1Frequency uint32
	// 0x02	[31:0]	RX1 NCO Frequency in Hz
	// 0x03	[31:0]	If present, RX2 NCO Frequency in Hz
	// 0x04	[31:0]	If present, RX3 NCO Frequency in Hz
	// 0x05	[31:0]	If present, RX4 NCO Frequency in Hz
	// 0x06	[31:0]	If present, RX5 NCO Frequency in Hz
	// 0x07	[31:0]	If present, RX6 NCO Frequency in Hz
	// 0x08	[31:0]	If present, RX7 NCO Frequency in Hz
	rx1Frequency uint32
	rx2Frequency uint32
	rx3Frequency uint32
	rx4Frequency uint32
	rx5Frequency uint32
	rx6Frequency uint32
	rx7Frequency uint32
	// 0x09	[31:24]	Hermes TX Drive Level (only [31:28] used)
	txDrive byte
	// 0x09	[23]	VNA mode (0=off, 1=on)
	vnaMode bool
	// 0x09	[22]	Alex manual mode (0=off, 1=on) (Not implemented yet)
	alexMode bool
	// 0x09	[20]	Tune request, set during TX spot or tune to initiate an ATU tune request
	tune bool
	// 0x09	[19]	Onboard PA (0=off, 1=on)
	paOn bool
	// 0x09	[18]	Q5 switch internal PTT in low power mode or 0=ATU tune and 1=ATU bypass when PA is on
	internalPTT bool
	// 0x09	[15:8]	I2C RX filter (Not implemented), or VNA count MSB
	// 0x09	[7:0]	I2C TX filter (Not implemented), or VNA count LSB
	vnaCount uint16
	// 0x0a	[22]	PureSignal (0=disable, 1=enable)
	pureSignal bool
	// 0x0a	[6]	See LNA gain section in https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#lna-gain
	hl2LNAMode bool // true=HL2 LNA mode, false=legacy Hermes mode
	// 0x0a	[5:0]	LNA[5:0] gain
	receiveLNAGain byte // When hermesLNAMode is false, valid values are between 0 (-12dB) and 60 (48dB)
	// 0x0e	[15]	Enable hardware managed LNA gain for TX
	hwTXLNA bool
	// 0x0e	[14]	See LNA gain section in https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#lna-gain
	// 0x0e	[13:8]	LNA[5:0] gain during TX if enabled
	// 0x0f	[24]	Enable CWX, I[0] of IQ stream is CWX keydown
	cwx bool
	// 0x10	[31:24]	CW Hang Time in ms, bits [9:2]
	// 0x10	[17:16]	CW Hang Time in ms, bits [1:0]
	cwHangTime uint16
	// 0x12	[31:0]	If present, RX8 NCO Frequency in Hz
	// 0x13	[31:0]	If present, RX9 NCO Frequency in Hz
	// 0x14	[31:0]	If present, RX10 NCO Frequency in Hz
	// 0x15	[31:0]	If present, RX11 NCO Frequency in Hz
	// 0x16	[31:0]	If present, RX12 NCO Frequency in Hz
	rx8Frequency  uint32
	rx9Frequency  uint32
	rx10Frequency uint32
	rx11Frequency uint32
	rx12Frequency uint32
	// 0x17	[12:8]	PTT hang time, default is 4ms
	pttHangTime byte
	// 0x17	[6:0]	TX buffer latency in ms, default is 10ms
	txBufferLatency byte
	// 0x2b	[31:24]	Predistortion subindex
	preDistortionSubIndex byte
	// 0x2b	[19:16]	Predistortion
	preDistortion byte
	// 0x39	[27:24]	Misc Commands
	// 				0x0 No command
	// 				0x9 Disable watchdog timer
	disableWatchdog bool
	// 0x39	[23]	Enable update of locked receivers
	// 0x39	[21]	Lock RX12 to RX 11
	// 0x39	[20]	Lock RX10 to RX 9
	// 0x39	[19]	Lock RX8 to RX7
	// 0x39	[18]	Lock RX6 to RX5
	// 0x39	[17]	Lock RX4 to RX3
	// 0x39	[16]	Lock RX2 to RX1
	// 0x39	[11:8]	Master Commands
	// 				0x0 No command
	// 				0x8 Disable Master
	// 				0x9 Enable Master
	// 0x39	[7:4]	Synchronization Commands
	// 				0x0 No command
	// 				0x8 Reset all filter pipelines
	// 				0x9 Reset and align all NCOs
	// 0x39	[3:0]	Clock Generator Commands
	// 				0x0 No command
	// 				0x8 Synchronize clock outputs
	// 				0xA Disable CL2 clock output
	// 				0xB Enable CL2 clock output
	// 				0xC Disable CL1 clock input
	// 				0XD Enable CL1 clock input
	// 0x3a	[0]	Reset HL2 on disconnect
	resetOnDisconnect bool
	// 0x3b	[31:24]	AD9866 SPI cookie, must be 0x06 to write
	// 0x3b	[20:16]	AD9866 SPI address
	// 0x3b	[7:0]	AD9866 SPI data
	// 0x3c	[31:24]	I2C1 cookie, must be 0x06 to write, 0x07 to read
	// 0x3c	[23]	I2C1 stop at end (0=continue, 1=stop)
	// 0x3c	[22:16]	I2C1 target chip address
	// 0x3c	[15:8]	I2C1 control
	// 0x3c	[7:0]	I2C1 data (only for write)
	// 0x3d	[31:24]	I2C2 cookie, must be 0x06 to write, 0x07 to read
	// 0x3d	[23]	I2C2 stop at end (0=continue, 1=stop)
	// 0x3d	[22:16]	I2C2 target chip address
	// 0x3d	[15:8]	I2C2 control
	// 0x3d	[7:0]	I2C2 data (only for write)
	// 0x3f	[31:0]	Error for responses

	// These are the HL2 received address definitions (see https://github.com/softerhardware/Hermes-Lite2/wiki/Protocol#data-from-hermes-lite2-to-pc)
	// We always set ACK==0, so responses are in classic mode.
	// C0	[7]		ACK==0
	// 		[6:3]	RADDR[3:0]
	// 		[2]		Dot, see below
	// 		[1]		Dash, always zero
	// 		[0]		PTT, see below
	// C1	[7:0]	RDATA[31:24]
	// C2	[7:0]	RDATA[23:16]
	// C3	[7:0]	RDATA[15:8]
	// C4	[7:0]	RDATA[7:0]
	PTT bool
	// 0x00	[24]	RF ADC Overload
	ADCOverload bool
	// 0x00	[15]	Under/overflow Recovery**
	OverflowRecovery bool
	// 0x00	[14:8]	TX IQ FIFO Count MSBs

	// 0x00	[7:0]	Firmware Version
	FirmwareVersion byte
	// 0x01	[31:16]	Temperature
	Temperature uint16
	// 0x01	[15:0]	Forward Power
	ForwardPower uint16
	// 0x02	[31:16]	Reverse Power
	ReversePower uint16
	// 0x02	[15:0]	Current
	Current uint16

	// Message state
	sentSeqNum         uint32
	lastReceivedSeqNum uint32

	nextEP2Address byte // Next EP2 address to send to. Value betwwen 0 and 64

}

// NewMetisState creates a MetisState with reasonable defaults
func NewMetisState(addr *net.UDPAddr) *MetisState {
	ret := MetisState{
		sendIQ:        true,
		deviceAddress: addr,
	}
	return &ret
}

// SetSampleRate sets the sample rate in Hz. Valid values are 48000, 96000, 192000 or 384000
func (state *MetisState) SetSampleRate(speed uint) error {
	log.Printf("[DEBUG] SetSampleRate: %d", speed)
	switch speed {
	case 48000:
		state.speed = 0b00
	case 96000:
		state.speed = 0b01
	case 192000:
		state.speed = 0b10
	case 384000:
		state.speed = 0b11
	default:
		return fmt.Errorf("Valid speed values are (48000, 96000, 192000, 384000), got %d", speed)
	}
	return nil
}

// SetRX1Frequency sets the RX1 NCO frequency
func (state *MetisState) SetRX1Frequency(frequency uint) {
	log.Printf("[DEBUG] SetRX1Frequency: %d", frequency)
	state.rx1Frequency = uint32(frequency)
	// Radio isn't happy if TX frequency is 0
	if state.tx1Frequency == 0 {
		state.tx1Frequency = state.rx1Frequency
	}
}

// SetReceiveLNAGain sets the LNA gain. Valid values are between 0 (-12dB) and 60 (48dB)
func (state *MetisState) SetReceiveLNAGain(gain uint) {
	state.hl2LNAMode = true
	if gain > 60 {
		gain = 60
	}
	state.receiveLNAGain = byte(gain)
}

// Start starts the radio
func (state *MetisState) Start() error {
	if !state.sendIQ && !state.sendBandscope {
		return errors.New("Neither IQ nor bandscope are enabled")
	}
	var err error
	if state.conn == nil {
		// Maybe we should bind to the discovered interface
		state.conn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("Error opening UDP connection: %w", err)
		}
	}
	err = state.sendMetisCommand(metisStop)
	if err != nil {
		return fmt.Errorf("Error sending stop command %w", err)
	}
	var frame1, frame2 [512]byte
	// initialize
	s := make([]TransmitSample, 126)
	frame1, err = state.buildEP2Frame(0x0, s[:63])
	if err != nil {
		return err
	}
	frame2, err = state.buildEP2Frame(0x1, s[63:])
	if err != nil {
		return err
	}
	msg := state.NewMetisMessage(EP2, frame1, frame2)
	err = state.writeMessage(msg)
	if err != nil {
		return err
	}
	frame1, err = state.buildEP2Frame(0x0, s[:63])
	if err != nil {
		return err
	}
	frame2, err = state.buildEP2Frame(0x2, s[63:])
	if err != nil {
		return err
	}
	msg = state.NewMetisMessage(EP2, frame1, frame2)
	err = state.writeMessage(msg)
	if err != nil {
		return err
	}

	var cmd byte
	if state.sendIQ {
		cmd |= metisStartIQ
	}
	if state.sendBandscope {
		cmd |= metisStartBandscope
	}
	err = state.sendMetisCommand(cmd)
	if err != nil {
		return fmt.Errorf("Error sending start command %w", err)
	}
	state.running = true
	return nil
}

// Stop stops the radio
func (state *MetisState) Stop() error {
	err := state.sendMetisCommand(metisStop)
	if err != nil {
		return fmt.Errorf("Error sending stop command %w", err)
	}
	state.running = false
	return nil
}

// Close the radio connection
func (state *MetisState) Close() {
	state.Stop()
	state.conn.Close()
}

// ReceiverSample represents a single EP6 IQ sample from the radio
type ReceiverSample struct {
	I2 byte
	I1 byte
	I0 byte
	Q2 byte
	Q1 byte
	Q0 byte
	M1 byte
	M0 byte
}

// IFloat returns the I value as a float
func (rs ReceiverSample) IFloat() float32 {
	i := uint32(rs.I2)<<16 | uint32(rs.I1)<<16 | uint32(rs.I0)
	return float32(i) / 8388607.0
}

// QFloat returns the Q value as a float
func (rs ReceiverSample) QFloat() float32 {
	i := uint32(rs.I2)<<16 | uint32(rs.I1)<<16 | uint32(rs.I0)
	return float32(i) / 8388607.0
}

// ReceiveSamples receives data from the radio
func (state *MetisState) ReceiveSamples(outFunc func(state *MetisState, samples []ReceiverSample)) {
	// log.Printf("[DEBUG] ReceiveSamples()")
	// Receiving a message
	buffer := make([]byte, 2048)
	// log.Printf("[DEBUG] ReceiveSamples: local address %v, remote address %v", r.conn.LocalAddr(), r.conn.RemoteAddr())
	state.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	l, _, err := state.conn.ReadFromUDP(buffer)
	if err != nil {
		if neterr, ok := err.(net.Error); ok {
			if neterr.Timeout() {
				log.Print("[DEBUG] ReceiveSamples: timeout")
			}
			if operr, ok := neterr.(*net.OpError); ok {
				msg := fmt.Sprintf("ReceiveSamples: Error(): %s, Temporary(): %t, Timeout(): %t, Op: %s, Net: %s, Err: %#v",
					operr.Error(),
					operr.Temporary(),
					operr.Timeout(),
					operr.Op,
					operr.Net,
					operr.Err,
				)
				log.Print(msg)
			} else {
				log.Printf("ReceiveSamples: neterr: %#v", neterr)
			}
		} else {
			log.Printf("ReceiveSamples: Error reading from receiver: %#v", err)
		}
		return
	}
	buf := bytes.NewBuffer(buffer[:l])
	mm, err := MetisMessageFromBuffer(buf)
	if err != nil {
		log.Printf("ReceiveSamples: error processing packet: %v", err)
	}
	s, err := state.decodeSamples(mm.Frame1)
	if err != nil {
		log.Printf("ReceiveSamples: error decoding Frame1 samples: %v", err)
	}
	outFunc(state, s)
	s, err = state.decodeSamples(mm.Frame2)
	if err != nil {
		log.Printf("ReceiveSamples: error decoding Frame2 samples: %v", err)
	}
	outFunc(state, s)
	// log.Printf("[DEBUG] ReceiveSamples: %#v", *mm)
}

type ep6Data struct {
	Sync    [3]byte
	C0      byte
	C1      byte
	C2      byte
	C3      byte
	C4      byte
	Samples [63]ReceiverSample
}

func (state *MetisState) decodeSamples(frame [512]byte) ([]ReceiverSample, error) {
	buf := bytes.NewBuffer(frame[:])
	var packet ep6Data

	err := binary.Read(buf, binary.BigEndian, &packet)
	if err != nil {
		return nil, fmt.Errorf("Error decoding received samples: %w", err)
	}
	// sanity check
	if packet.Sync[0] != 0x7f || packet.Sync[1] != 0x7f || packet.Sync[2] != 0x7f {
		return nil, fmt.Errorf("Received corrupted EP6 frame. Incorrect Sync bytes: %#v", packet)
	}
	if (packet.C0 & 0b10000000) != 0 {
		return nil, fmt.Errorf("Received EP6 frame with ACK set: %#v", packet)
	}
	state.PTT = (packet.C0 & 0b1) != 0
	var addr byte
	addr = (packet.C0 & 0b01111000) >> 3
	rdata := uint32(packet.C1) << 24
	rdata |= uint32(packet.C2) << 16
	rdata |= uint32(packet.C3) << 8
	rdata |= uint32(packet.C4)
	switch addr {
	case 0x00:
		state.ADCOverload = (rdata & 1 << 24) != 0
		state.OverflowRecovery = (rdata & 1 << 15) != 0
		state.FirmwareVersion = byte(rdata & 0xff)
		log.Printf("[DEBUG] ADCOverload: %v, OverflowRecovery: %v, FirmwareVersion: %v", state.ADCOverload, state.OverflowRecovery, state.FirmwareVersion)
	case 0x01:
		state.ForwardPower = uint16(rdata & 0xffff)
		state.Temperature = uint16((rdata >> 16) & 0xffff)
		log.Printf("[DEBUG] ForwardPower: %v, Temperature: %v", state.ForwardPower, state.Temperature)
	case 0x02:
		state.Current = uint16(rdata & 0xffff)
		state.ReversePower = uint16((rdata >> 16) & 0xffff)
	}
	return packet.Samples[:], nil
}

func assemble(hi, mid, lo byte) uint32 {
	return uint32(lo) | uint32(mid)<<8 | uint32(hi)<<16
}

// TransmitSample represents a single EP2 transmit sample sent to the radio
type TransmitSample struct {
	Left  uint32
	Right uint32
	I     uint32
	Q     uint32
}

// SendSamples send data to the radio and updates its state
func (state *MetisState) SendSamples(samples []TransmitSample) error {
	// Eventually we should buffer until we have enough to send a packet.
	// For now, if we dont have have a multiple of 126 samples, we send what we have and pad with empty ones
	var frame1, frame2 [512]byte
	var err error

	s := samples
	if len(samples) < 126 {
		s = make([]TransmitSample, 126)
		copy(s, samples)
	}
	frame1, err = state.buildEP2Frame(state.nextEP2Address, s[:63])
	if err != nil {
		return err
	}
	if state.nextEP2Address < lastEP2Address {
		state.nextEP2Address++
	} else {
		state.nextEP2Address = 0
	}

	frame2, err = state.buildEP2Frame(state.nextEP2Address, s[63:])
	if err != nil {
		return err
	}
	if state.nextEP2Address < lastEP2Address {
		state.nextEP2Address++
	} else {
		state.nextEP2Address = 0
	}
	msg := state.NewMetisMessage(EP2, frame1, frame2)

	err = state.writeMessage(msg)

	if err != nil {
		return err
	}
	return nil
}

func (state *MetisState) writeMessage(msg MetisMessage) error {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, msg)
	if err != nil {
		return err
	}
	cnt, err := state.conn.WriteToUDP(buf.Bytes(), state.deviceAddress)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG] Sent %d byte EP2 message", cnt)
	return nil
}

type ep2Data struct {
	Sync    [3]byte
	C0      byte
	C1      byte
	C2      byte
	C3      byte
	C4      byte
	Samples [63]TransmitSample
}

func (state *MetisState) buildEP2Frame(ep2Address byte, samples []TransmitSample) ([512]byte, error) {
	arr := [512]byte{}
	data := ep2Data{
		Sync: [3]byte{0x7F, 0x7F, 0x7F},
	}
	copy(data.Samples[:], samples)
	if state.mox {
		data.C0 |= 0x01
	}
	data.C0 |= ep2Address << 1

	var tdata uint32
	switch ep2Address {
	case 0x00:
		tdata |= uint32(state.speed) << 24
		if state.rxAntenna {
			tdata |= 1 << 13
		}
		if state.clockOff {
			tdata |= 1 << 12
		}
		if state.vnaGain {
			tdata |= 1 << 10
		}
		tdata |= uint32(state.receiverCount) << 3
		if state.duplex {
			tdata |= 1 << 2
		}
	case 0x01:
		tdata = state.tx1Frequency
	case 0x02:
		tdata = state.rx1Frequency
	case 0x03:
		tdata = state.rx2Frequency
	case 0x04:
		tdata = state.rx3Frequency
	case 0x05:
		tdata = state.rx4Frequency
	case 0x06:
		tdata = state.rx5Frequency
	case 0x07:
		tdata = state.rx6Frequency
	case 0x08:
		tdata = state.rx7Frequency
	case 0x09:
		tdata |= uint32(state.txDrive) >> 24
		if state.vnaMode {
			tdata |= 1 << 23
		}
		if state.alexMode {
			tdata |= 1 << 22
		}
		if state.tune {
			tdata |= 1 << 20
		}
		if state.paOn {
			tdata |= 1 << 19
		}
		tdata |= uint32(state.vnaCount)
	case 0x0a:
		if state.pureSignal {
			tdata |= 1 << 22
		}
		if state.hl2LNAMode {
			tdata |= 1 << 6
			tdata |= uint32(state.receiveLNAGain)
		} else {
			// not implemented
		}
	case 0x0e:
		if state.hwTXLNA {
			tdata |= 1 << 15
		}
		// Other TX LNA gain not implemented
	case 0x0f:
		// CWX not implemented
	case 0x10:
		// CW hang time not implemented
	case 0x12:
		tdata = state.rx8Frequency
	case 0x13:
		tdata = state.rx9Frequency
	case 0x14:
		tdata = state.rx10Frequency
	case 0x15:
		tdata = state.rx11Frequency
	case 0x16:
		tdata = state.rx12Frequency
	case 0x17:
		tdata |= uint32(state.pttHangTime) << 8
		tdata |= uint32(state.txBufferLatency)
	case 0x2b:
		tdata |= uint32(state.preDistortionSubIndex) << 24
		tdata |= uint32(state.preDistortion) << 16
		// Rest of commands not implemented
	}
	log.Printf("[DEBUG] Sending address: %x, value: %x, %d", ep2Address, tdata, tdata)
	data.C1 = byte(tdata >> 24)
	data.C2 = byte(tdata >> 16)
	data.C3 = byte(tdata >> 8)
	data.C4 = byte(tdata)

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, data)
	if err != nil {
		return arr, err
	}
	cnt := copy(arr[:], buf.Bytes())
	if cnt != 512 {
		return arr, fmt.Errorf("Built short EP2 frame (should be 512, was %d)", cnt)
	}
	return arr, nil
}

type metisStartStop struct {
	EF      byte
	FE      byte
	ID04    byte
	Command byte
	Filler  [60]byte
}

func (state *MetisState) sendMetisCommand(command byte) error {
	msg := metisStartStop{
		EF:      0xEF,
		FE:      0xFE,
		ID04:    0x04,
		Command: command,
		Filler:  [60]byte{},
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, msg)
	if err != nil {
		return err
	}
	cnt, err := state.conn.WriteToUDP(buf.Bytes(), state.deviceAddress)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG] Sent %d byte command", cnt)
	return nil
}
