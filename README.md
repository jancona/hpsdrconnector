# hpsdrconnector
An OpenWebRX connector for HPSDR radios

## Installation

The HPSDR connector is packaged with OpenWebRX, so a separate installation isn't usually needed. For a manually installed OpenWebRX, see the [Manual Installation](https://github.com/jancona/hpsdrconnector#manual-installation) section below.

## Usage
Navigate to the OpenWebRX settings area, "SDR devices and profiles". Click "Add new device" and select the device type "HPSDR devices (Hermes / Hermes Lite 2 / Red Pitaya)" from the dropdown. Give it a name and click the "Apply and save" button.

Then create one or more profiles for the device. Be sure to specify a sample rate supported by the HPSDR device, i.e. one of 48000, 96000, 192000 or 384000.

The version of the connector installed with OpenWebRX 1.0 and 1.1 only supports a single receiver. The current version supports multiple receivers, up to the number the hardware is capable of, e.g. 4 for a Hermes-Lite 2 with standard gateware. Until this version is packaged in an OpenWebRX release, you can experiment with it by using the OpenWebRX experimental repositories or by following the [manual installation](https://github.com/jancona/hpsdrconnector#manual-installation) process and then defining additional devices and profiles in the OWRX settings. The same sample rate is used for all receivers, so starting a profile with a different sample rate will affect other running devices. To avoid problems, it may be best to use a single sample rate for all profiles.

## Limitations
* Only the original HPSDR Protocol 1 is supported.
* So far, this has been tested with the [Hermes-Lite 2](https://github.com/softerhardware/Hermes-Lite2/wiki) and the [Red Pitaya](https://www.redpitaya.com/Catalog/p25/stemlab-125-14-sdr-kit?cat=a102). Feel free to create [issues](https://github.com/jancona/hpsdrconnector/issues) with reports of success or failure using other hardware.

## Manual Installation

There are now released binaries, so you no longer have to install Go to build from source. (If you wish to build from source see [Building](https://github.com/jancona/hpsdrconnector#building) below.)

1. Download the proper binary for your OS and architecture from the list below.
2. Rename the binary to `hpsdrconnector` and make it executable (`chmod +x hpsdrconnector`).
3. Place the it in a directory in your `PATH` (e.g. `/usr/local/bin`).
4. Test your installation by running `hpsdrconnector -h`. You should see a usage message.

| Operating System | Executable Name |
| ---------------- | --------------- |
| Desktop Linux | [hpsdrconnector_linux_amd64](https://github.com/jancona/hpsdrconnector/releases/latest/download/hpsdrconnector_linux_amd64) |
| Raspberry Pi (and other Arm) Linux | [hpsdrconnector_linux_arm](https://github.com/jancona/hpsdrconnector/releases/latest/download/hpsdrconnector_linux_arm) |
| MacOS amd64 | [hpsdrconnector_macos_amd64](https://github.com/jancona/hpsdrconnector/releases/latest/download/hpsdrconnector_macos_amd64) |

## Developer Information

### Command line options
```
  -c, --control uint
        control socket port (default disabled)
  -p, --port uint
        IQ listen port (default 4590)
  -d, --debug
        Emit debug log messages on stderr
  -f, --frequency uint
        Tune to specified frequency in Hz (default 7100000)
  -g, --gain uint
        LNA gain between 0 (-12dB) and 60 (48dB) (default 20)
  -r, --radio string
        IP address of radio (default use first radio discovered)
  -s, --samplerate uint
        Use the specified samplerate: one of 48000, 96000, 192000, 384000 (default 96000)
```

### Building
1. Download Go from https://golang.org/dl/
2. Install Go, following the instructions for your OS at https://golang.org/doc/install. Be sure to add the Go bin directory to your PATH if the installer hasn't done that for you.
3. In the `hpsdrconnector` directory, run `go install`
4. Test your installation by running `hpsdrconnector -h`. You should see a usage message.
