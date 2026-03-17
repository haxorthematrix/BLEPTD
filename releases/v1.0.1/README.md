# BLEPTD v1.0.1 Release

**Release Date:** 2026-03-16

## What's New

- **128-bit Service UUID Detection** - Full support for 128-bit BLE service UUIDs, enabling detection of devices like Flipper Zero
- **Flipper Zero Detection** - Added signature for Flipper Zero devices (company ID 0x0499 + 128-bit UUID)
- **Power Save Mode** - Screen automatically turns off after 5 minutes of no new device detections, wakes instantly when new device is found
- **Device Name Pattern Matching** - Case-insensitive name matching for improved detection

## Files Included

| File | Description |
|------|-------------|
| `BLEPTD_v1.0.1.bin` | Main firmware binary (flash at 0x10000) |
| `bootloader.bin` | ESP32 bootloader (flash at 0x1000) |
| `partitions.bin` | Partition table (flash at 0x8000) |
| `BLEPTD.ino` | Arduino IDE sketch (alternative to PlatformIO) |

## Flashing Instructions

### Option 1: esptool (Recommended)

```bash
# Install esptool if needed
pip install esptool

# Flash all binaries (replace /dev/ttyUSB0 with your port)
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 460800 \
    write_flash \
    0x1000 bootloader.bin \
    0x8000 partitions.bin \
    0x10000 BLEPTD_v1.0.1.bin
```

### Option 2: ESP Flash Download Tool (Windows)

1. Download from Espressif: https://www.espressif.com/en/support/download/other-tools
2. Select ESP32, Develop mode
3. Add files:
   - `bootloader.bin` @ 0x1000
   - `partitions.bin` @ 0x8000
   - `BLEPTD_v1.0.1.bin` @ 0x10000
4. Set baud to 460800, click START

### Option 3: Arduino IDE

1. Open `BLEPTD.ino` in Arduino IDE
2. Install TFT_eSPI library and configure User_Setup.h per comments in sketch
3. Install XPT2046_Touchscreen library
4. Select "ESP32 Dev Module" board
5. Upload

## Power Save Configuration

Power save is enabled by default (5 minute timeout). To configure:

**Via Serial Commands (115200 baud):**
```
POWERSAVE STATUS        - Show current status
POWERSAVE ON            - Enable power save
POWERSAVE OFF           - Disable power save
POWERSAVE TIMEOUT 300   - Set timeout to 300 seconds
POWERSAVE WAKE          - Wake screen immediately
```

**Via Source Code (Arduino):**
Edit these lines in the sketch:
```cpp
#define POWERSAVE_ENABLED       true    // Set to false to disable
#define POWERSAVE_TIMEOUT_SEC   300     // Seconds until screen sleep
```

## Hardware Requirements

- ESP32-2432S028R (CYD 2.8" with micro-USB)
- NOT compatible with USB-C variant (different display driver)

## Changelog

See [SPECIFICATION.md](../../SPECIFICATION.md) for full feature list.
