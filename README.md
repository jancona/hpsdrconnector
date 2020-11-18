# hpsdrconnector
An OpenWebRX connector for HPSDR radios

## Installation

There are now released binaries, so you no longer have to install Go to build from source. (If you wish to build from source see [Building](https://github.com/jancona/hpsdrconnector#building) below.)

1. Download the proper binary for your OS and architecture from the list below.
2. Place the it in your `PATH`.
3. For the Linux and MacOS binaries, you will need to rename the binary to `hpsdrconnector` and make it executable (`chmod +x hpsdrconnector`).
4. Test your installation by running `hpsdrconnector -h`. You should see a usage message.

| Operating System | Executable Name |
| ---------------- | --------------- |
| Windows | [hpsdrconnector.exe](/jancona/hpsdrconnector/releases/latest/download/hpsdrconnector.exe)
| Desktop Linux | [hpsdrconnector_linux_amd64](/jancona/hpsdrconnector/releases/latest/download/hpsdrconnector_linux_amd64) |
| Raspberry Pi (and other Arm) Linux | [hpsdrconnector_linux_arm](/jancona/hpsdrconnector/releases/latest/download/hpsdrconnector_linux_arm) |
| MacOS amd64 | [hpsdrconnector_macos_amd64](/jancona/hpsdrconnector/releases/latest/download/hpsdrconnector_macos_amd64) |

## Limitations
* Only the original HPSDR Protocol 1 is supported.
* So far, this has only been tested with the [Hermes-Lite 2](https://github.com/softerhardware/Hermes-Lite2/wiki). Feel free to create [issues](https://github.com/jancona/hpsdrconnector/issues) with reports of success or failure using other hardware.
* Currently only one receiver is supported.

## Usage
In order to use hpsdrconnector with OpenWebRX you will need a version of OpenWebRX that supports it. Right now, that means installing from source from this branch: https://github.com/jancona/openwebrx/tree/hpsdr_connector
Once this code is merged into OpenWebRX and released, a normal installation will suffice.

You will also need to update `config_webrx.py`. Here is a sample SDR definition:
```python
sdrs = {
    "HL2": {
        "name": "Hermes-Lite 2",
        "type": "hpsdr",
        # if the following line is commented out, the connector will use the first radio it discovers
        # "remote": "192.168.1.123", # IP Address of radio
        "samp_rate": 192000,
        "rf_gain": "20",
        "profiles": {
            "40m": {
                "name": "40m",
                "center_freq": 7150000,
                "start_freq": 7150000,
                "start_mod": "lsb",
            },
            "bcb": {
                "name": "bcb",
                "center_freq": 630000,
                "start_freq": 580000,
                "start_mod": "am",
            },
            "20m": {
                "name": "20m",
                "center_freq": 14120000,
                "start_freq": 14100000,
                "start_mod": "usb",
            },
            "30m": {
                "name": "30m",
                "center_freq": 10125000,
                "start_freq": 10142000,
                "start_mod": "usb",
            },
            "80m": {
                "name": "80m",
                "center_freq": 3850000,
                "start_freq": 3870000,
                "start_mod": "lsb",
            },
        },
    },
}
```

Command line options:
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

## Building
1. Download Go from https://golang.org/dl/
2. Install Go, following the instructions for your OS at https://golang.org/doc/install. Be sure to add the Go bin directory to your PATH if the installer hasn't done that for you.
3. In the `hpsdrconnector` directory, run `go install`
4. Test your installation by running `hpsdrconnector -h`. You should see a usage message.

