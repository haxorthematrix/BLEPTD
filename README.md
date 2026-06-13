# BLEPTD - BLE Privacy Threat Detector

ESP32 CYD firmware for detecting Bluetooth Low Energy devices that may compromise privacy or be used in targeted surveillance attacks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-ESP32-green.svg)
![Hardware](https://img.shields.io/badge/hardware-CYD%202.8%22-yellow.svg)

## Overview

BLEPTD is a portable BLE surveillance detection platform that runs on the ESP32-based "Cheap Yellow Display" (CYD). It detects and identifies:

- **Tracking Devices** - AirTags, Tile, SmartTags, Chipolo, Flipper Zero, etc.
- **Smart Glasses** - Meta Ray-Ban, Snap Spectacles, Echo Frames
- **Medical Devices** - CGMs, insulin pumps, pacemakers (for VIP security assessments)
- **Wearables** - Smartwatches, fitness trackers
- **Audio Devices** - Wireless earbuds, headphones

## Features

- **Real-time BLE scanning** with signature-based device identification
- **128-bit UUID detection** for devices like Flipper Zero
- **Interactive touchscreen UI** for field operation
- **Category filtering** to focus on specific device types
- **TX Simulation mode** for testing and countermeasures
- **Confusion mode** to generate false positives
- **Power save mode** - screen auto-off after 5 min idle, wakes on new detection
- **Serial command interface** for automation and logging
- **JSON output** for integration with other tools

## Hardware Requirements

ESP32 "Cheap Yellow Display" (CYD) 2.8", available on AliExpress / Amazon for
~$10-15 USD. Both shipping revisions are supported:

| Variant | Connector | TFT controller | Board ID |
|---------|-----------|----------------|----------|
| Original | micro-USB only | ILI9341 | ESP32-2432S028R (v1/v2) |
| Newer | USB-C (sometimes + micro-USB) | ILI9342 | ESP32-2432S028R v3 |

Shared specs on both revisions:
- ESP32-WROOM-32 module
- 2.8" TFT LCD (320x240)
- XPT2046 resistive touchscreen
- MicroSD card slot

> **You must pick the matching firmware/build env for your board.** Flashing the
> ILI9341 firmware to an ILI9342 board (or vice versa) results in a fully white
> screen with the backlight on — the controller silently ignores the wrong
> init sequence. See [Identifying your CYD variant](#identifying-your-cyd-variant).

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

# Build and upload with PlatformIO — pick the env that matches your CYD:
pio run -e cyd_microusb -t upload   # micro-USB CYD  (ILI9341 driver)
pio run -e cyd_usbc     -t upload   # USB-C CYD      (ILI9342 driver)

# Monitor serial output
pio device monitor
```

If you are not sure which board you have, see
[Identifying your CYD variant](#identifying-your-cyd-variant) below.
`pio run -t upload` (no `-e`) still builds the micro-USB variant for backwards
compatibility via the `cyd` env alias.

### Prebuilt binaries

Each release under [`releases/`](releases/) ships two firmware images, one per
variant — flash the one that matches your board. The latest release
([v1.0.2](releases/v1.0.2/)) is the first to include a working USB-C image.

### Arduino IDE

1. Install ESP32 board support via Board Manager
2. Install TFT_eSPI library
3. Copy the matching `User_Setup.h` for your variant (ILI9341 for micro-USB,
   ILI9342 + `TFT_RGB_ORDER TFT_RGB` + `TFT_INVERSION_ON` for USB-C) into your
   TFT_eSPI library folder, and for the USB-C variant construct the display
   object as `TFT_eSPI tft = TFT_eSPI(240, 320);` so `setRotation(1)` produces
   the correct 320×240 landscape geometry
4. Open `src/main.cpp`, rename to `.ino`
5. Select "ESP32 Dev Module" board
6. Upload

### Identifying your CYD variant

The two boards are mechanically and electrically almost identical — the
controller chip is the only thing that changes — so the simplest tell is the
USB connector(s):

- **Single micro-USB port** → ILI9341 → use `cyd_microusb` /
  `BLEPTD_v*_microusb.bin`
- **USB-C port** (alone, or alongside a second micro-USB) → ILI9342 → use
  `cyd_usbc` / `BLEPTD_v*_usbc.bin`

After flashing, the boot banner and the `VERSION` serial command confirm which
variant you built for:

```
BLEPTD v1.0.2 (USB-C/ILI9342)
BLEPTD v1.0.2 (microUSB/ILI9341)
```

A fully white screen with the backlight on is the universal symptom of flashing
the wrong variant.

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

POWERSAVE STATUS        - Show power save status
POWERSAVE ON|OFF        - Enable/disable power save
POWERSAVE TIMEOUT <sec> - Set idle timeout (10-3600s)
POWERSAVE WAKE          - Wake screen immediately
```

### Power Save Configuration

Power save settings are stored in `/config.txt` on SPIFFS:

```
powersave_enabled=true
powersave_timeout_sec=300
```

Upload config with: `pio run -t uploadfs`

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

1. **Company Identifier** - 16-bit Bluetooth SIG assigned ID in manufacturer-specific data
2. **Payload Patterns** - Signature byte sequences at specific offsets
3. **16-bit Service UUIDs** - Standard BLE service identifiers
4. **128-bit Service UUIDs** - Custom service identifiers (e.g., Flipper Zero)
5. **Device Name Matching** - Case-insensitive pattern matching

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
