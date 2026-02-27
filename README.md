# BLEPTD - BLE Privacy Threat Detector

ESP32 CYD firmware for detecting Bluetooth Low Energy devices that may compromise privacy or be used in targeted surveillance attacks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-ESP32-green.svg)
![Hardware](https://img.shields.io/badge/hardware-CYD%202.8%22-yellow.svg)

## Overview

BLEPTD is a portable BLE surveillance detection platform that runs on the ESP32-based "Cheap Yellow Display" (CYD). It detects and identifies:

- **Tracking Devices** - AirTags, Tile, SmartTags, Chipolo, etc.
- **Smart Glasses** - Meta Ray-Ban, Snap Spectacles, Echo Frames
- **Medical Devices** - CGMs, insulin pumps, pacemakers (for VIP security assessments)
- **Wearables** - Smartwatches, fitness trackers
- **Audio Devices** - Wireless earbuds, headphones

## Features

- **Real-time BLE scanning** with signature-based device identification
- **Interactive touchscreen UI** for field operation
- **Category filtering** to focus on specific device types
- **TX Simulation mode** for testing and countermeasures
- **Confusion mode** to generate false positives
- **Serial command interface** for automation and logging
- **JSON output** for integration with other tools

## Hardware Requirements

- ESP32 "Cheap Yellow Display" (CYD) 2.8"
  - ESP32-WROOM-32 module
  - 2.8" ILI9341 TFT LCD (320x240)
  - XPT2046 resistive touchscreen
  - MicroSD card slot

Available on AliExpress for ~$10-15 USD.

## Installation

### Prerequisites

- [PlatformIO](https://platformio.org/) (recommended) or Arduino IDE
- USB-C cable
- CH340 USB drivers (if not already installed)

### Build & Flash

```bash
# Clone the repository
git clone https://github.com/haxorthematrix/BLEPTD.git
cd BLEPTD

# Build and upload with PlatformIO
pio run -t upload

# Monitor serial output
pio device monitor
```

### Arduino IDE

1. Install ESP32 board support via Board Manager
2. Install TFT_eSPI library
3. Copy `User_Setup.h` from `lib/TFT_eSPI/` to your TFT_eSPI library folder
4. Open `src/main.cpp`, rename to `.ino`
5. Select "ESP32 Dev Module" board
6. Upload

## Usage

### Touchscreen Interface

The device has four main screens accessible via the bottom navigation bar:

1. **SCAN** - View detected devices with RSSI and category indicators
2. **FILTER** - Enable/disable device categories
3. **TX** - Transmit simulated BLE advertisements
4. **SETTINGS** - Configure scan parameters, serial output, display

### Serial Commands

Connect at 115200 baud. Available commands:

```
HELP            - Show command list
VERSION         - Firmware version
STATUS          - Current operational status

SCAN START      - Begin BLE scanning
SCAN STOP       - Stop scanning
SCAN CLEAR      - Clear detected devices
SCAN LIST       - List all detected devices

FILTER SET <category> <on|off>
JSON <on|off>   - Toggle JSON output mode
```

### Example Output

Human-readable:
```
[12345] DETECT AirTag (Registered) MAC=AA:BB:CC:DD:EE:FF RSSI=-42 CAT=TRACKER
[12456] DETECT Meta Ray-Ban MAC=11:22:33:44:55:66 RSSI=-58 CAT=GLASSES
```

JSON mode:
```json
{"event":"detect","ts":12345,"device":"AirTag (Registered)","mac":"AA:BB:CC:DD:EE:FF","rssi":-42,"category":"TRACKER","company_id":"0x004C"}
```

## Device Categories

| Category | Color | Description |
|----------|-------|-------------|
| TRACKER | Red | Location tracking devices |
| GLASSES | Orange | Camera-equipped smart glasses |
| MEDICAL | Yellow | Medical/health devices |
| WEARABLE | Blue | Smartwatches, fitness bands |
| AUDIO | Magenta | Wireless earbuds/headphones |

## Detection Method

BLEPTD identifies devices using multiple BLE advertisement fields:

1. **Company Identifier** - Mandatory 16-bit ID in manufacturer-specific data
2. **Payload Patterns** - Signature byte sequences at specific offsets
3. **Service UUIDs** - 16-bit or 128-bit service identifiers

This approach works even when devices use randomized MAC addresses.

## Adding Custom Signatures

Signatures can be added via serial command:

```
SIG ADD {"name":"Custom Device","category":"TRACKER","company_id":"0x1234","threat_level":3}
```

Or by editing `src/detection/signatures.h` and rebuilding.

## Legal & Ethical Use

This tool is intended for:

- Personal privacy protection
- Authorized security assessments
- Security research and education
- Penetration testing with written authorization

**WARNING:** Transmitting BLE advertisements that impersonate other devices may violate local regulations. Use TX/confusion features only in controlled environments with proper authorization.

## Contributing

Contributions welcome! Especially:

- New device signatures (open an issue with company ID and payload data)
- UI improvements
- Additional detection methods
- Documentation

## Credits

- Inspired by [CYD_ESP32-AirTag-Scanner](https://github.com/haxorthematrix/CYD_ESP32-AirTag-Scanner)
- [Nearby Glasses](https://github.com/yvesj/nearby-glasses) for smart glasses detection research
- [ESP32 Cheap Yellow Display](https://github.com/witnessmenow/ESP32-Cheap-Yellow-Display) community

## License

MIT License - See [LICENSE](LICENSE) file.
