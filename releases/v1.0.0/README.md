# BLEPTD v1.0.0 Release

BLE Privacy Threat Detector for ESP32 CYD (Cheap Yellow Display)

## Supported Hardware

**ONLY the ESP32-2432S028R (2.8" CYD with micro-USB)** is supported.

| Model | USB Type | Status |
|-------|----------|--------|
| ESP32-2432S028R | Micro-USB | **Supported** |
| ESP32-2432S028 | Micro-USB | **Supported** (same board) |
| ESP32-2432S028**C** | USB-C | NOT Compatible |
| Other CYD variants | - | NOT Compatible |

### How to Identify Your Board
- Must have **micro-USB** connector (not USB-C)
- 2.8" diagonal display (320x240 resolution)
- Yellow PCB

## Release Contents

| File | Description |
|------|-------------|
| `BLEPTD_v1.0.0.bin` | Main firmware binary |
| `bootloader.bin` | ESP32 bootloader |
| `partitions.bin` | Partition table |
| `BLEPTD.ino` | Arduino IDE sketch (standalone) |

## Installation Options

### Option 1: Flash Pre-compiled Binary (Recommended)

Using esptool.py (Python):
```bash
pip install esptool

esptool.py --chip esp32 --port /dev/cu.usbserial-XXXXX --baud 460800 \
  --before default_reset --after hard_reset write_flash \
  -z --flash_mode dio --flash_freq 40m --flash_size 4MB \
  0x1000 bootloader.bin \
  0x8000 partitions.bin \
  0x10000 BLEPTD_v1.0.0.bin
```

Replace `/dev/cu.usbserial-XXXXX` with your serial port:
- **macOS**: `/dev/cu.usbserial-*` (use `ls /dev/cu.*` to find it)
- **Linux**: `/dev/ttyUSB0` or `/dev/ttyACM0`
- **Windows**: `COM3`, `COM4`, etc. (check Device Manager)

### Option 2: Arduino IDE

1. Install Arduino IDE 2.x
2. Add ESP32 board support:
   - Go to File > Preferences
   - Add to "Additional Board Manager URLs":
     ```
     https://espressif.github.io/arduino-esp32/package_esp32_index.json
     ```
   - Go to Tools > Board > Board Manager
   - Search "esp32" and install "ESP32 by Espressif Systems"

3. Install required libraries (Sketch > Include Library > Manage Libraries):
   - **TFT_eSPI** by Bodmer
   - **XPT2046_Touchscreen** by Paul Stoffregen
   - **ArduinoJson** by Benoit Blanchon

4. Configure TFT_eSPI for CYD:
   - Find the TFT_eSPI library folder
   - Edit `User_Setup.h` and add at the top:
     ```c
     #define ILI9341_2_DRIVER
     #define TFT_WIDTH 240
     #define TFT_HEIGHT 320
     #define TFT_MISO 12
     #define TFT_MOSI 13
     #define TFT_SCLK 14
     #define TFT_CS 15
     #define TFT_DC 2
     #define TFT_RST -1
     #define TFT_BL 21
     #define USE_HSPI_PORT
     #define SPI_FREQUENCY 55000000
     ```

5. Open `BLEPTD.ino` in Arduino IDE

6. Select board settings:
   - Board: "ESP32 Dev Module"
   - Upload Speed: 460800
   - Flash Size: 4MB
   - Partition Scheme: Default 4MB with spiffs

7. Connect your CYD and click Upload

### Option 3: PlatformIO (Recommended for Development)

```bash
git clone https://github.com/haxorthematrix/BLEPTD.git
cd BLEPTD
pio run -t upload
pio device monitor
```

## First Boot

1. Connect the CYD via USB
2. The display should show "BLEPTD v1.0.0" and begin scanning
3. Connect to serial port at 115200 baud to see output and send commands
4. Use touch screen to navigate between SCAN, FILTER, TX, and SETUP screens

## Serial Commands

Connect at **115200 baud**. Type `HELP` to see all commands.

## Features

- **Detection**: 54 device signatures (trackers, glasses, medical, wearables, audio)
- **TX Mode**: Simulate 20 transmittable devices
- **Confusion Mode**: Broadcast multiple device types simultaneously
- **Touch UI**: Navigate and control via touchscreen
- **Serial CLI**: Full command-line control

## Troubleshooting

### Board not detected
- Try a different USB cable (some cables are charge-only)
- Install CH340/CP2102 USB-serial drivers if needed
- Press the BOOT button while connecting

### Display is blank
- Check that you're using the correct CYD model (micro-USB version)
- Verify TFT_eSPI is configured correctly

### Touch not working
- Touch uses separate SPI bus, ensure XPT2046_Touchscreen library is installed
- Touch is calibrated for landscape mode

## License

MIT License - See repository for details

## Links

- Repository: https://github.com/haxorthematrix/BLEPTD
- Issues: https://github.com/haxorthematrix/BLEPTD/issues
