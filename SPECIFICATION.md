# BLE Privacy Threat Detector (BLEPTD)
## CYD ESP32 Firmware Specification

**Version:** 1.0.0-draft
**Target Hardware:** ESP32 "Cheap Yellow Display" (CYD) 2.8" ILI9341 (non-USB-C variant ESP32-2432S028R)
**Authors:** Security Research Team
**License:** MIT

---

## Implementation Status

### Completed Features ✓

| Feature | Status | Notes |
|---------|--------|-------|
| Project structure | ✓ | PlatformIO setup, config.h, main.cpp |
| Display driver | ✓ | ILI9341_2_DRIVER for non-USB-C CYD, landscape mode |
| Touch screen | ✓ | XPT2046 on VSPI, calibrated for landscape |
| Navigation UI | ✓ | 4-tab navigation (SCAN, FILTER, TX, SETUP) |
| Scan screen | ✓ | Device list with category colors, MAC address display |
| Filter screen | ✓ | Category toggles via touch |
| TX screen | ✓ | Touch device selection, STOP/CONFUSE buttons |
| Settings screen | ✓ | Display-only settings info |
| Device detail view | ✓ | Tap device to see full info (MAC, RSSI, times, category) |
| List scrolling | ✓ | Scroll through long device lists with indicators |
| BLE scanning | ✓ | Detection with signature matching, 5-second intervals |
| Signature database | ✓ | 54 devices: 11 trackers, 9 glasses, 18 medical, 9 wearables, 7 audio |
| Detection engine | ✓ | Company ID, payload pattern, service UUID matching |
| TX manager | ✓ | Single device transmission with consistent MAC per session |
| TX touch controls | ✓ | Tap device to start TX, STOP button, detailed TX info display |
| TX display info | ✓ | Shows device name, MAC address, company ID, category, packet count |
| Confusion mode | ✓ | Multi-device broadcast (20 devices) with random MAC per packet |
| CONFUSE button | ✓ | Touch button to start confusion with all transmittable devices |
| Serial commands | ✓ | HELP, VERSION, STATUS, SCAN, TX, CONFUSE, FILTER, JSON, DISPLAY |
| Optimized refresh | ✓ | Display only updates on content changes, TX screen 500ms refresh |

### Device Signature Database

| Category | Detection | Transmittable | Devices |
|----------|-----------|---------------|---------|
| Trackers | 11 | 11 | AirTag (2), SmartTag (2), Tile (2), Chipolo, Google, Eufy, Pebblebee, Cube |
| Glasses | 9 | 9 | Meta Ray-Ban (3), Snap Spectacles, Echo Frames, Bose Frames, Vuzix, XREAL, TCL |
| Medical | 18 | 0 | Diabetes (12): Dexcom, Medtronic, Omnipod, Abbott, Tandem, etc. Cardiac (4), Respiratory (2) |
| Wearables | 9 | 0 | Fitbit, Garmin, Whoop, Oura, Polar, Suunto, Xiaomi, Amazfit, Huawei |
| Audio | 7 | 0 | Sony, Bose, Jabra, JBL, Plantronics, Skullcandy, Bang & Olufsen |
| **Total** | **54** | **20** | |

---

## Quick Start Guide

### Compilation

**Prerequisites:**
- PlatformIO IDE or CLI
- USB cable for ESP32

**Build and Upload:**
```bash
# Clone the repository
git clone https://github.com/haxorthematrix/BLEPTD.git
cd BLEPTD

# Build firmware
pio run

# Upload to device
pio run -t upload

# Monitor serial output
pio device monitor
```

### Hardware Setup

The firmware is designed for the **ESP32-2432S028R** (CYD 2.8" non-USB-C variant):
- Connect via micro-USB
- Display should show BLEPTD interface on boot
- Touch the screen to navigate

### Touch Controls

**Navigation Bar (bottom of screen):**
- **SCAN** - View detected devices
- **FILTER** - Toggle device categories
- **TX** - Transmit/simulate devices
- **SETUP** - View settings

**Scan Screen:**
- Tap a device to view details
- Scroll by tapping top/bottom of list
- Devices show: Name, last 3 MAC octets, RSSI, category

**TX Screen:**
- Tap any device to start transmitting
- **CONFUSE** button (purple) - Start confusion mode with all 20 transmittable devices
- **STOP** button (red) - Stop active transmission
- Display shows: Device name, MAC address, company ID, packet count

**Filter Screen:**
- Tap category to toggle on/off
- Categories: TRACKER, GLASSES, MEDICAL, WEARABLE, AUDIO

### Serial Commands

Connect at **115200 baud**. Available commands:

```
HELP                    - Show command list
STATUS                  - Current device status
VERSION                 - Firmware version

SCAN START              - Begin scanning
SCAN STOP               - Stop scanning
SCAN CLEAR              - Clear detected devices

TX LIST                 - List transmittable devices
TX START <device>       - Start transmitting (e.g., TX START AirTag)
TX STOP <device|ALL>    - Stop transmission
TX STATUS               - Show active transmissions

CONFUSE ADD <device>    - Add device to confusion list
CONFUSE LIST            - Show confusion entries
CONFUSE START           - Start confusion mode
CONFUSE STOP            - Stop confusion mode
CONFUSE CLEAR           - Clear confusion list

FILTER SET <cat> <on|off> - Toggle category filter
FILTER LIST             - Show current filters

JSON ON|OFF             - Toggle JSON output mode
```

---

## Supported Devices

### Trackers (11 devices) - All Transmittable

| Device | Company ID | Payload Pattern | Notes |
|--------|------------|-----------------|-------|
| AirTag (Registered) | 0x004C | `4C 00 07 19` | Apple FindMy network |
| AirTag (Unregistered) | 0x004C | `4C 00 12 19` | Lost/separated mode |
| Samsung SmartTag | 0x0075 | `75 00 42 09 01` | SmartThings Find |
| Samsung SmartTag2 | 0x0075 | `75 00 42 09 02` | UWB version |
| Tile Tracker | 0xFEEC | `EC FE` | Multiple variants |
| Tile (Alt) | 0xFEED | `ED FE` | Alternate ID |
| Chipolo | 0xFE65 | `65 FE` | Chipolo ONE/CARD |
| Google Tracker | 0x00E0 | Service: 0xFE2C | Find My Device network |
| Eufy Tracker | 0x0757 | - | Anker ecosystem |
| Pebblebee | 0x0822 | - | FindMy compatible |
| Cube Tracker | 0x0843 | - | Cube devices |

### Smart Glasses (9 devices) - All Transmittable

| Device | Company ID | Notes |
|--------|------------|-------|
| Meta Ray-Ban | 0x01AB | Meta Platforms Inc - Camera glasses |
| Meta Ray-Ban (Tech) | 0x058E | Meta Platforms Technologies |
| Meta Ray-Ban (Luxottica) | 0x0D53 | Luxottica manufacturer |
| Snap Spectacles | 0x03C2 | Snap Inc - Camera glasses |
| Amazon Echo Frames | 0x0171 | Amazon - Audio glasses |
| Bose Frames | 0x009E | Bose - Audio sunglasses |
| Vuzix Blade | 0x077A | AR smart glasses |
| XREAL Air | 0x0A14 | AR display glasses |
| TCL RayNeo | 0x0992 | AR smart glasses |

### Medical Devices - Diabetes (12 devices)

| Device | Company ID | Service UUID | Notes |
|--------|------------|--------------|-------|
| Dexcom G6/G7 | 0x00D1 | 0xFEBC | Continuous glucose monitor |
| Medtronic Pump | 0x02A5 | - | Insulin pump |
| Omnipod | 0x0822 | 0x1830 | Insulet insulin pump |
| Abbott FreeStyle | 0x0618 | - | Libre CGM |
| Tandem t:slim | 0x0801 | - | Insulin pump |
| Senseonics Eversense | 0x07E1 | - | Implantable CGM |
| Ascensia Contour | 0x0702 | 0x1808 | Glucose meter |
| Roche Accu-Chek | 0x0077 | 0x1808 | Glucose meter |
| Ypsomed mylife | 0x08B4 | - | YpsoPump |
| Bigfoot Unity | 0x093B | - | Smart pen caps |
| Beta Bionics iLet | 0x0964 | - | Bionic pancreas |
| LifeScan OneTouch | 0x03F0 | 0x1808 | Glucose meter |

### Medical Devices - Cardiac (4 devices)

| Device | Company ID | Notes |
|--------|------------|-------|
| Biotronik Cardiac | 0x00A3 | Pacemakers/ICDs |
| Boston Scientific | 0x0149 | Cardiac devices |
| AliveCor Kardia | 0x041B | Mobile ECG |
| Zoll LifeVest | 0x0571 | Wearable defibrillator |

### Medical Devices - Respiratory & Other (6 devices)

| Device | Company ID | Service UUID | Notes |
|--------|------------|--------------|-------|
| ResMed CPAP | 0x02B5 | - | Sleep apnea |
| Philips CPAP | 0x0030 | - | Sleep apnea |
| Withings Health | 0x05E3 | - | Health monitors |
| Omron BP Monitor | 0x020E | 0x1810 | Blood pressure |
| Qardio Heart Health | 0x0415 | - | Heart monitors |
| iHealth Devices | 0x02C1 | - | Health monitors |

### Wearables (9 devices)

| Device | Company ID | Notes |
|--------|------------|-------|
| Fitbit | 0x0224 | Fitness trackers |
| Garmin Watch | 0x0087 | Sports watches |
| Whoop Band | 0x0643 | Recovery tracker |
| Oura Ring | 0x0781 | Sleep/health ring |
| Polar Watch | 0x006B | Sports watches |
| Suunto Watch | 0x0068 | Sports watches |
| Xiaomi Mi Band | 0x038F | Fitness bands |
| Amazfit Watch | 0x0157 | Smartwatches |
| Huawei Watch | 0x027D | Smartwatches |

### Audio Devices (7 devices)

| Device | Company ID | Notes |
|--------|------------|-------|
| Sony Audio | 0x012D | Headphones/earbuds |
| Bose Audio | 0x009E | Headphones/speakers |
| Jabra Headset | 0x0067 | Business headsets |
| JBL Audio | 0x0057 | Speakers/headphones |
| Plantronics | 0x0055 | Headsets |
| Skullcandy | 0x02A0 | Headphones/earbuds |
| Bang & Olufsen | 0x0059 | Premium audio |

### Pending Features

| Feature | Priority | Notes |
|---------|----------|-------|
| RSSI threshold slider | Low | Touch-adjustable on filter screen |
| Configuration persistence | Medium | Save/load settings to flash |
| SD card logging | Low | Export scan logs to SD |
| Custom signature management | Low | SIG ADD/DELETE via serial |
| Export functions | Low | SCAN EXPORT csv/json |
| FreeRTOS tasks | Low | Multi-core task distribution |
| Brightness control | Low | Display brightness adjustment |
| Sound alerts | Low | Buzzer feedback |

---

## 1. Executive Summary

BLEPTD is a portable BLE (Bluetooth Low Energy) surveillance detection platform designed for privacy protection and VIP security assessments. The firmware runs on the ESP32-based "Cheap Yellow Display" and provides:

- **Detection** of privacy-compromising BLE devices (trackers, smart glasses, medical devices)
- **Simulation** of BLE advertising packets for testing and countermeasures
- **Interactive touchscreen UI** for field operation
- **Serial interface** for automated testing and integration

---

## 2. Hardware Platform

### 2.1 Target Device: CYD 2.8"

| Component | Specification |
|-----------|---------------|
| MCU | ESP32-WROOM-32 (Dual-core 240MHz, 520KB SRAM) |
| Display | 2.8" TFT LCD, 320x240 pixels, ILI9341 driver |
| Touch | Resistive touchscreen (XPT2046 controller) |
| Storage | MicroSD card slot, 4MB onboard flash |
| Connectivity | WiFi 802.11 b/g/n, Bluetooth 4.2 BLE |
| Power | 5V USB, ~115mA typical |
| Dimensions | 50mm x 86mm |

### 2.2 Pin Assignments (Reference)

```
TFT_MISO  = 12    TFT_MOSI  = 13    TFT_SCLK  = 14
TFT_CS    = 15    TFT_DC    = 2     TFT_RST   = -1
TFT_BL    = 21    TOUCH_CS  = 33    SD_CS     = 5
```

---

## 3. Device Detection Database

### 3.1 Detection Methods

BLEPTD uses multiple BLE advertisement field analysis techniques:

| Method | Field | Description |
|--------|-------|-------------|
| **Company ID** | Manufacturer Specific Data (0xFF) | 16-bit Bluetooth SIG assigned company identifier |
| **Payload Pattern** | Raw advertisement bytes | Signature matching against known byte sequences |
| **Service UUID** | Complete/Incomplete Service UUIDs | 16-bit or 128-bit service identifiers |
| **Device Name** | Complete/Shortened Local Name | String pattern matching (fallback method) |

### 3.2 Device Categories

#### 3.2.1 Tracking Devices (Category: TRACKER)

| Device | Company ID | Payload Pattern | Notes |
|--------|------------|-----------------|-------|
| **Apple AirTag (Registered)** | 0x004C | `4C 00 07 19` | FindMy network |
| **Apple AirTag (Unregistered)** | 0x004C | `4C 00 12 19` | Lost/separated mode |
| **Apple FindMy Accessory** | 0x004C | `4C 00 07 xx` | Third-party FindMy |
| **Samsung SmartTag** | 0x0075 | `75 00 42 09 01` | SmartThings Find |
| **Samsung SmartTag2** | 0x0075 | `75 00 42 09 02` | Enhanced UWB version |
| **Tile (Classic)** | 0xFEED | `ED FE` | Multiple variants |
| **Tile (Pro/Mate)** | 0xFEEC | `EC FE`, `7C 06`, `84 FD` | Enhanced range |
| **Chipolo** | 0xFE65 | `65 FE`, `C3 08`, `33 FE` | Multiple products |
| **Chipolo ONE Spot** | 0x004C | FindMy compatible | Uses Apple network |
| **Pebblebee** | 0xFE99 | `99 FE` | FindMy + Google compatible |
| **eufy SmartTrack** | 0x0969 | TBD | FindMy compatible |
| **Milli** | 0x004C | FindMy clone | Uses Apple network |

#### 3.2.2 Smart Glasses (Category: GLASSES)

| Device | Company ID | Notes |
|--------|------------|-------|
| **Meta Ray-Ban (Meta Platforms)** | 0x01AB | Meta Platforms Inc |
| **Meta Ray-Ban (Meta Tech)** | 0x058E | Meta Platforms Technologies |
| **Meta Ray-Ban (Luxottica)** | 0x0D53 | Luxottica manufacturer ID |
| **Snap Spectacles** | 0x03C2 | Snap Inc |
| **Amazon Echo Frames** | 0x0171 | Amazon.com Services |
| **Bose Frames** | 0x009E | Bose Corporation |
| **Razer Anzu** | 0x0532 | Razer Inc |

#### 3.2.3 Medical Devices (Category: MEDICAL)

> **WARNING:** Medical device detection is for authorized security assessments only. These signatures are documented for VIP protection scenarios where detecting nearby medical devices may indicate specific individuals.

| Device Type | Company ID | Service UUID | Notes |
|-------------|------------|--------------|-------|
| **Medtronic Insulin Pump** | 0x02A5 | Various | Multiple pump models |
| **Omnipod** | 0x0822 | `1830` (CGM) | Insulet Corporation |
| **Dexcom CGM** | 0x00D1 | `FEBC` | Continuous glucose monitor |
| **Abbott FreeStyle** | 0x0618 | Various | Libre CGM system |
| **Tandem t:slim** | 0x0916 | Various | Insulin pump |
| **Medtronic Pacemaker** | 0x02A5 | Proprietary | CareLink compatible |
| **Boston Scientific ICD** | 0x04E2 | Proprietary | Implantable defibrillator |
| **Abbott/St. Jude Cardiac** | 0x0618 | Proprietary | Pacemakers/ICDs |

#### 3.2.4 Wearables (Category: WEARABLE)

| Device | Company ID | Notes |
|--------|------------|-------|
| **Apple Watch** | 0x004C | Various continuity payloads |
| **Fitbit** | 0x0224 | Google/Fitbit |
| **Garmin** | 0x0087 | Garmin Ltd |
| **Whoop** | 0x0969 | Whoop Inc |
| **Oura Ring** | 0x0A14 | Oura Health |

#### 3.2.5 Audio/Recording Devices (Category: AUDIO)

| Device | Company ID | Notes |
|--------|------------|-------|
| **AirPods** | 0x004C | Proximity pairing pattern |
| **AirPods Pro** | 0x004C | Different payload structure |
| **Galaxy Buds** | 0x0075 | Samsung |
| **Sony WF/WH Series** | 0x012D | Sony Corporation |
| **Bose QC** | 0x009E | Bose Corporation |

### 3.3 Device Signature Data Structure

```c
typedef struct {
    char name[32];                  // Human-readable device name
    uint8_t category;               // TRACKER, GLASSES, MEDICAL, etc.
    uint16_t company_id;            // Bluetooth SIG Company ID (0 if not used)
    uint8_t payload_pattern[8];     // Byte pattern to match
    uint8_t pattern_length;         // Length of pattern (0 if not used)
    uint8_t pattern_offset;         // Offset in payload (-1 for any position)
    uint16_t service_uuid;          // 16-bit Service UUID (0 if not used)
    uint8_t threat_level;           // 1-5 severity rating
    uint32_t flags;                 // Detection flags (see below)
} device_signature_t;

// Detection flags
#define SIG_FLAG_COMPANY_ID     0x0001  // Match on company ID
#define SIG_FLAG_PAYLOAD        0x0002  // Match on payload pattern
#define SIG_FLAG_SERVICE_UUID   0x0004  // Match on service UUID
#define SIG_FLAG_NAME_PATTERN   0x0008  // Match on device name
#define SIG_FLAG_EXACT_MATCH    0x0010  // All specified fields must match
#define SIG_FLAG_TRANSMITTABLE  0x0020  // Can simulate this device
#define SIG_FLAG_MEDICAL        0x0040  // Medical device (special handling)
```

---

## 4. User Interface Design

### 4.1 Display Layout (320x240 Landscape)

```
+--------------------------------------------------+
|  BLEPTD v1.0            [MODE]     [BATT] 12:34  |  <- Status Bar (20px)
+--------------------------------------------------+
|                                                  |
|                                                  |
|                  MAIN CONTENT                    |  <- Content Area (180px)
|                    AREA                          |
|                                                  |
|                                                  |
+--------------------------------------------------+
|  [TAB1]  |  [TAB2]  |  [TAB3]  |  [TAB4]        |  <- Navigation (40px)
+--------------------------------------------------+
```

### 4.2 Main Menu Screens

#### 4.2.1 Home Screen (Tab: SCAN)

```
+--------------------------------------------------+
|  BLEPTD v1.0           SCANNING      ■■■■  12:34 |
+--------------------------------------------------+
|  ┌──────────────────────────────────────────┐   |
|  │  DETECTED DEVICES                    [15] │   |
|  ├──────────────────────────────────────────┤   |
|  │ ▲ AirTag           -42 dBm   TRACKER  ●  │   |
|  │   SmartTag2        -58 dBm   TRACKER  ●  │   |
|  │   Ray-Ban Meta     -31 dBm   GLASSES  ●  │   |
|  │   Dexcom G7        -67 dBm   MEDICAL  ●  │   |
|  │   Tile Pro         -72 dBm   TRACKER  ●  │   |
|  │ ▼ [Scroll for more...]                   │   |
|  └──────────────────────────────────────────┘   |
|                                                  |
+--------------------------------------------------+
|  [SCAN]  |  [FILTER] |  [TX]    |  [SETTINGS]   |
+--------------------------------------------------+

Legend:
● = Threat indicator (color-coded by category)
    Red    = TRACKER
    Orange = GLASSES
    Yellow = MEDICAL
    Blue   = WEARABLE
    Purple = AUDIO
```

#### 4.2.2 Filter Configuration Screen (Tab: FILTER)

```
+--------------------------------------------------+
|  BLEPTD v1.0           FILTER        ■■■■  12:34 |
+--------------------------------------------------+
|                                                  |
|   DEVICE CATEGORIES                              |
|   ┌────────────────────────────────────────┐    |
|   │  [✓] TRACKER    Tracking devices       │    |
|   │  [✓] GLASSES    Smart glasses/cameras  │    |
|   │  [ ] MEDICAL    Medical devices        │    |
|   │  [✓] WEARABLE   Smartwatches/bands     │    |
|   │  [ ] AUDIO      Earbuds/headphones     │    |
|   │  [ ] ALL        Show all BLE devices   │    |
|   └────────────────────────────────────────┘    |
|                                                  |
|   MIN RSSI: [-80 dBm ─────●───── -20 dBm]       |
|                                                  |
+--------------------------------------------------+
|  [SCAN]  |  [FILTER] |  [TX]    |  [SETTINGS]   |
+--------------------------------------------------+
```

#### 4.2.3 Transmit/Simulate Screen (Tab: TX)

```
+--------------------------------------------------+
|  BLEPTD v1.0           TRANSMIT      ■■■■  12:34 |
+--------------------------------------------------+
|                                                  |
|   SELECT DEVICE TO SIMULATE                      |
|   ┌────────────────────────────────────────┐    |
|   │ ▲ Apple AirTag (Registered)            │    |
|   │   Apple AirTag (Unregistered)          │    |
|   │   Samsung SmartTag2                    │    |
|   │   Tile Pro                             │    |
|   │   Meta Ray-Ban Glasses                 │    |
|   │   Snap Spectacles                      │    |
|   │ ▼ [Scroll for more...]                 │    |
|   └────────────────────────────────────────┘    |
|                                                  |
|   [▶ START TX]  Interval: [100ms ▼] Count: [∞]  |
|                                                  |
+--------------------------------------------------+
|  [SCAN]  |  [FILTER] |  [TX]    |  [SETTINGS]   |
+--------------------------------------------------+
```

#### 4.2.4 Confusion Attack Mode (TX Submenu)

```
+--------------------------------------------------+
|  BLEPTD v1.0           CONFUSION     ■■■■  12:34 |
+--------------------------------------------------+
|                                                  |
|   CONFUSION MODE - MULTI-DEVICE BROADCAST       |
|                                                  |
|   Active Simulations:                            |
|   ┌────────────────────────────────────────┐    |
|   │  [✓] AirTag x5         (rotating MAC)  │    |
|   │  [✓] SmartTag x3       (rotating MAC)  │    |
|   │  [✓] Tile x4           (rotating MAC)  │    |
|   │  [ ] Meta Glasses x2                   │    |
|   └────────────────────────────────────────┘    |
|                                                  |
|   Total TX Rate: 50 pkts/sec                     |
|                                                  |
|   [▶ START CONFUSION]        [STOP ALL]          |
|                                                  |
+--------------------------------------------------+
|  [SCAN]  |  [FILTER] |  [TX]    |  [SETTINGS]   |
+--------------------------------------------------+
```

#### 4.2.5 Settings Screen (Tab: SETTINGS)

```
+--------------------------------------------------+
|  BLEPTD v1.0           SETTINGS      ■■■■  12:34 |
+--------------------------------------------------+
|                                                  |
|   SCAN SETTINGS                                  |
|   ├─ Scan Duration:     [1s ▼]                  |
|   ├─ Scan Interval:     [100ms ▼]               |
|   └─ Active Scan:       [ON/off]                |
|                                                  |
|   SERIAL INTERFACE                               |
|   ├─ Baud Rate:         [115200 ▼]              |
|   ├─ JSON Output:       [ON/off]                |
|   └─ Echo Commands:     [on/OFF]                |
|                                                  |
|   DISPLAY                                        |
|   ├─ Brightness:        [●─────────]            |
|   ├─ Screen Timeout:    [30s ▼]                 |
|   └─ Sound Alerts:      [ON/off]                |
|                                                  |
|   [SAVE]  [RESET DEFAULTS]  [EXPORT SIGS]       |
|                                                  |
+--------------------------------------------------+
|  [SCAN]  |  [FILTER] |  [TX]    |  [SETTINGS]   |
+--------------------------------------------------+
```

#### 4.2.6 Device Detail View (Tap on detected device)

```
+--------------------------------------------------+
|  BLEPTD v1.0           DETAIL        ■■■■  12:34 |
+--------------------------------------------------+
|                                              [X] |
|   DEVICE: Apple AirTag (Registered)              |
|   ─────────────────────────────────────────────  |
|   Category:    TRACKER                           |
|   Threat:      ●●●●○ (4/5)                       |
|   MAC:         AA:BB:CC:DD:EE:FF                 |
|   RSSI:        -42 dBm (Strong)                  |
|   Company ID:  0x004C (Apple Inc.)               |
|   First Seen:  12:30:15                          |
|   Last Seen:   12:34:22                          |
|   Detections:  47                                |
|                                                  |
|   RAW PAYLOAD (hex):                             |
|   4C 00 07 19 01 02 03 04 05 06 07 08 09 0A...  |
|                                                  |
|   [TRACK]  [SIMULATE]  [ADD TO BLOCKLIST]       |
|                                                  |
+--------------------------------------------------+
```

### 4.3 Touch Interaction Zones

```
Touch Calibration Points:
  Top-Left:     (0, 0)      -> Screen (0, 0)
  Top-Right:    (4095, 0)   -> Screen (320, 0)
  Bottom-Left:  (0, 4095)   -> Screen (0, 240)
  Bottom-Right: (4095, 4095)-> Screen (320, 240)

Navigation Tab Zones (y: 200-240):
  Tab 1 (SCAN):     x: 0-80
  Tab 2 (FILTER):   x: 80-160
  Tab 3 (TX):       x: 160-240
  Tab 4 (SETTINGS): x: 240-320

List Scroll Zones:
  Scroll Up:   Touch top 20% of list area
  Scroll Down: Touch bottom 20% of list area
  Select Item: Touch middle 60% of list item
```

### 4.4 Visual Feedback States

| State | Indicator | Description |
|-------|-----------|-------------|
| Scanning Active | Pulsing radar icon | BLE scan in progress |
| Device Detected | Flash + optional beep | New device found |
| TX Active | Blinking TX icon | Transmitting packets |
| Serial Command | Brief highlight | Command received via serial |
| Error | Red banner | Error condition |
| Low Battery | Flashing battery icon | Battery below 20% |

---

## 5. Serial Communication Protocol

### 5.1 Connection Parameters

| Parameter | Value |
|-----------|-------|
| Baud Rate | 115200 (configurable: 9600-921600) |
| Data Bits | 8 |
| Parity | None |
| Stop Bits | 1 |
| Flow Control | None |
| Line Ending | `\n` (LF) |

### 5.2 Output Formats

#### 5.2.1 Human-Readable Mode (Default)

```
[12:34:56] DETECT AirTag (Registered) MAC=AA:BB:CC:DD:EE:FF RSSI=-42 CAT=TRACKER
[12:34:57] DETECT SmartTag2 MAC=11:22:33:44:55:66 RSSI=-58 CAT=TRACKER
[12:35:01] TX_START device=AirTag interval=100ms count=inf
[12:35:05] TX_STOP device=AirTag sent=40
```

#### 5.2.2 JSON Mode (Machine-Readable)

```json
{"event":"detect","ts":1709042096,"device":"AirTag","subtype":"Registered","mac":"AA:BB:CC:DD:EE:FF","rssi":-42,"category":"TRACKER","company_id":"0x004C","payload":"4C0007190102030405060708090A"}
{"event":"detect","ts":1709042097,"device":"SmartTag2","mac":"11:22:33:44:55:66","rssi":-58,"category":"TRACKER","company_id":"0x0075","payload":"75004209020102030405"}
{"event":"tx_start","ts":1709042101,"device":"AirTag","interval_ms":100,"count":-1}
{"event":"tx_stop","ts":1709042105,"device":"AirTag","packets_sent":40}
{"event":"cmd_ack","ts":1709042106,"cmd":"scan_start","status":"ok"}
{"event":"error","ts":1709042110,"code":101,"message":"Invalid device name"}
```

### 5.3 Command Interface

#### 5.3.1 Command Format

```
COMMAND [arg1] [arg2] [...]\n
```

Commands are case-insensitive. Arguments are space-separated.

#### 5.3.2 Command Reference

| Command | Arguments | Description |
|---------|-----------|-------------|
| `HELP` | | Display command list |
| `VERSION` | | Show firmware version |
| `STATUS` | | Current operational status |
| **Scanning** | | |
| `SCAN START` | | Begin BLE scanning |
| `SCAN STOP` | | Stop BLE scanning |
| `SCAN CLEAR` | | Clear detected device list |
| `SCAN LIST` | | List all detected devices |
| `SCAN EXPORT` | `[csv\|json]` | Export scan results |
| **Filtering** | | |
| `FILTER SET` | `<category>` `<on\|off>` | Enable/disable category |
| `FILTER LIST` | | Show current filter config |
| `FILTER RSSI` | `<min_dbm>` | Set minimum RSSI threshold |
| `FILTER RESET` | | Reset to defaults |
| **Transmission** | | |
| `TX START` | `<device>` `[interval_ms]` `[count]` | Start simulating device |
| `TX STOP` | `[device\|all]` | Stop transmission |
| `TX LIST` | | List transmittable devices |
| `TX STATUS` | | Show active transmissions |
| **Confusion Mode** | | |
| `CONFUSE START` | `<profile>` | Start confusion attack |
| `CONFUSE STOP` | | Stop confusion mode |
| `CONFUSE ADD` | `<device>` `<count>` | Add device to confusion set |
| `CONFUSE CLEAR` | | Clear confusion set |
| **Configuration** | | |
| `CONFIG GET` | `<key>` | Get configuration value |
| `CONFIG SET` | `<key>` `<value>` | Set configuration value |
| `CONFIG SAVE` | | Save to flash |
| `CONFIG RESET` | | Factory reset |
| **Display** | | |
| `DISPLAY ON` | | Turn on display |
| `DISPLAY OFF` | | Turn off display |
| `DISPLAY BRIGHTNESS` | `<0-100>` | Set brightness |
| `DISPLAY SCREEN` | `<screen_name>` | Navigate to screen |
| `DISPLAY MESSAGE` | `<text>` `[duration_ms]` | Show message overlay |
| **Signatures** | | |
| `SIG LIST` | `[category]` | List device signatures |
| `SIG ADD` | `<json_definition>` | Add custom signature |
| `SIG DELETE` | `<name>` | Remove signature |
| `SIG EXPORT` | | Export all signatures |
| `SIG IMPORT` | `<json_array>` | Import signatures |

#### 5.3.3 Command Examples

```bash
# Start scanning with filter
FILTER SET TRACKER on
FILTER SET MEDICAL off
SCAN START

# Simulate an AirTag every 200ms, 100 times
TX START "AirTag (Registered)" 200 100

# Start confusion mode with multiple trackers
CONFUSE ADD AirTag 5
CONFUSE ADD SmartTag 3
CONFUSE ADD Tile 4
CONFUSE START

# Navigate display to TX screen
DISPLAY SCREEN TX

# Show alert message on display
DISPLAY MESSAGE "Target Acquired" 3000

# Add custom signature
SIG ADD {"name":"Custom Tracker","category":"TRACKER","company_id":"0x1234","threat_level":3}

# Export results as JSON
SCAN EXPORT json
```

### 5.4 Response Format

```
OK [message]           # Success
ERROR <code> <message> # Failure
DATA ...              # Data response (continues until blank line)
```

### 5.5 Error Codes

| Code | Description |
|------|-------------|
| 100 | Unknown command |
| 101 | Invalid argument |
| 102 | Missing required argument |
| 103 | Device not found |
| 104 | Operation not permitted |
| 105 | Resource busy |
| 106 | Memory allocation failed |
| 107 | Storage error |
| 108 | BLE error |
| 109 | Configuration error |

---

## 6. Software Architecture

### 6.1 Module Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                       │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│   UI_MGR    │  SCAN_MGR   │   TX_MGR    │   SERIAL_MGR     │
│  (Display/  │   (BLE      │   (Packet   │   (Command       │
│   Touch)    │   Scanner)  │   Transmit) │   Interface)     │
├─────────────┴─────────────┴─────────────┴──────────────────┤
│                      SERVICE LAYER                          │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│  SIG_DB     │  DETECT_ENG │  PKT_FORGE  │   CONFIG_SVC     │
│ (Signature  │  (Detection │  (Packet    │  (Persistent     │
│  Database)  │   Engine)   │  Forging)   │   Config)        │
├─────────────┴─────────────┴─────────────┴──────────────────┤
│                      HARDWARE ABSTRACTION                    │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│  BLE_HAL    │  DISP_HAL   │  TOUCH_HAL  │   STORAGE_HAL    │
│  (ESP32 BT) │  (ILI9341)  │  (XPT2046)  │   (SPIFFS/SD)    │
└─────────────┴─────────────┴─────────────┴──────────────────┘
```

### 6.2 Core Components

#### 6.2.1 Signature Database (SIG_DB)

```c
// Signature storage and lookup
void sig_db_init(void);
int sig_db_load(void);                              // Load from flash
int sig_db_save(void);                              // Save to flash
const device_signature_t* sig_db_lookup(const uint8_t* adv_data, size_t len);
int sig_db_add(const device_signature_t* sig);
int sig_db_remove(const char* name);
int sig_db_count(void);
int sig_db_iterate(sig_callback_t callback, void* ctx);
```

#### 6.2.2 Detection Engine (DETECT_ENG)

```c
// Detection processing
typedef struct {
    char device_name[32];
    uint8_t category;
    uint8_t mac[6];
    int8_t rssi;
    uint16_t company_id;
    uint8_t payload[31];
    uint8_t payload_len;
    uint32_t first_seen;
    uint32_t last_seen;
    uint32_t detection_count;
    uint8_t threat_level;
} detected_device_t;

void detect_engine_init(void);
void detect_engine_process(BLEAdvertisedDevice* device);
int detect_engine_get_count(void);
detected_device_t* detect_engine_get_device(int index);
void detect_engine_clear(void);
void detect_engine_set_filter(uint8_t category_mask);
void detect_engine_set_rssi_threshold(int8_t min_rssi);
```

#### 6.2.3 Packet Forger (PKT_FORGE)

```c
// Advertisement packet construction
typedef struct {
    uint8_t adv_data[31];
    uint8_t adv_len;
    uint8_t scan_rsp_data[31];
    uint8_t scan_rsp_len;
    uint8_t mac[6];
    bool random_mac;
} forged_packet_t;

int pkt_forge_build(const device_signature_t* sig, forged_packet_t* pkt);
int pkt_forge_set_mac(forged_packet_t* pkt, const uint8_t* mac);
int pkt_forge_randomize_mac(forged_packet_t* pkt);
```

#### 6.2.4 Transmit Manager (TX_MGR)

```c
// Transmission control
typedef struct {
    const device_signature_t* sig;
    uint32_t interval_ms;
    int32_t remaining_count;    // -1 for infinite
    uint32_t packets_sent;
    bool active;
    bool random_mac_per_packet;
} tx_session_t;

void tx_mgr_init(void);
int tx_mgr_start(const char* device_name, uint32_t interval_ms, int32_t count);
int tx_mgr_stop(const char* device_name);
void tx_mgr_stop_all(void);
int tx_mgr_get_active_count(void);
tx_session_t* tx_mgr_get_session(int index);

// Confusion mode
int tx_mgr_confuse_add(const char* device_name, int instance_count);
int tx_mgr_confuse_start(void);
void tx_mgr_confuse_stop(void);
```

### 6.3 FreeRTOS Task Structure

| Task | Priority | Stack | Core | Description |
|------|----------|-------|------|-------------|
| `ble_scan_task` | 5 | 4096 | 0 | BLE scanning and detection |
| `ble_tx_task` | 4 | 4096 | 0 | Packet transmission |
| `ui_task` | 3 | 8192 | 1 | Display and touch handling |
| `serial_task` | 2 | 4096 | 1 | Serial command processing |
| `main_task` | 1 | 2048 | 1 | Coordination and housekeeping |

### 6.4 Event System

```c
// Inter-task communication via FreeRTOS queues
typedef enum {
    EVT_DEVICE_DETECTED,
    EVT_DEVICE_LOST,
    EVT_TX_STARTED,
    EVT_TX_STOPPED,
    EVT_TX_PACKET_SENT,
    EVT_SERIAL_COMMAND,
    EVT_TOUCH_EVENT,
    EVT_CONFIG_CHANGED,
    EVT_ERROR
} event_type_t;

typedef struct {
    event_type_t type;
    uint32_t timestamp;
    union {
        detected_device_t device;
        tx_session_t tx;
        char command[64];
        touch_event_t touch;
        error_info_t error;
    } data;
} system_event_t;
```

---

## 7. File Structure

```
bleptd/
├── src/
│   ├── main.cpp                 # Entry point, task initialization
│   ├── config.h                 # Build configuration, pin definitions
│   │
│   ├── ble/
│   │   ├── ble_hal.cpp          # ESP32 BLE abstraction
│   │   ├── ble_hal.h
│   │   ├── scanner.cpp          # BLE scanning implementation
│   │   ├── scanner.h
│   │   ├── transmitter.cpp      # BLE advertising transmission
│   │   └── transmitter.h
│   │
│   ├── detection/
│   │   ├── detect_engine.cpp    # Detection processing
│   │   ├── detect_engine.h
│   │   ├── sig_db.cpp           # Signature database
│   │   ├── sig_db.h
│   │   └── signatures.h         # Built-in signature definitions
│   │
│   ├── packet/
│   │   ├── pkt_forge.cpp        # Packet construction
│   │   ├── pkt_forge.h
│   │   ├── tx_mgr.cpp           # Transmission manager
│   │   └── tx_mgr.h
│   │
│   ├── ui/
│   │   ├── ui_mgr.cpp           # UI state machine
│   │   ├── ui_mgr.h
│   │   ├── screens/
│   │   │   ├── screen_scan.cpp
│   │   │   ├── screen_filter.cpp
│   │   │   ├── screen_tx.cpp
│   │   │   ├── screen_settings.cpp
│   │   │   └── screen_detail.cpp
│   │   ├── widgets/
│   │   │   ├── widget_list.cpp
│   │   │   ├── widget_button.cpp
│   │   │   ├── widget_slider.cpp
│   │   │   └── widget_checkbox.cpp
│   │   └── themes/
│   │       └── theme_default.h
│   │
│   ├── serial/
│   │   ├── serial_mgr.cpp       # Serial command processing
│   │   ├── serial_mgr.h
│   │   ├── cmd_parser.cpp       # Command parsing
│   │   └── cmd_parser.h
│   │
│   ├── storage/
│   │   ├── config_svc.cpp       # Configuration persistence
│   │   ├── config_svc.h
│   │   ├── storage_hal.cpp      # SPIFFS/SD abstraction
│   │   └── storage_hal.h
│   │
│   └── hal/
│       ├── display_hal.cpp      # ILI9341 driver wrapper
│       ├── display_hal.h
│       ├── touch_hal.cpp        # XPT2046 driver wrapper
│       └── touch_hal.h
│
├── data/
│   └── signatures.json          # Default signature database
│
├── lib/
│   └── README.md                # PlatformIO library info
│
├── include/
│   └── README.md
│
├── test/
│   ├── test_sig_db.cpp
│   ├── test_detect_engine.cpp
│   └── test_pkt_forge.cpp
│
├── platformio.ini               # PlatformIO configuration
├── README.md
├── LICENSE
├── SPECIFICATION.md             # This document
└── CHANGELOG.md
```

---

## 8. Build Configuration

### 8.1 PlatformIO Configuration

```ini
; platformio.ini
[env:cyd]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
upload_speed = 460800

lib_deps =
    bodmer/TFT_eSPI@^2.5.0
    https://github.com/PaulStoffregen/XPT2046_Touchscreen.git
    bblanchon/ArduinoJson@^6.21.0

build_flags =
    ; TFT_eSPI configuration for CYD 2.8" (non-USB-C version ESP32-2432S028R)
    -DUSER_SETUP_LOADED=1
    -DILI9341_2_DRIVER=1
    -DTFT_WIDTH=240
    -DTFT_HEIGHT=320
    -DTFT_MISO=12
    -DTFT_MOSI=13
    -DTFT_SCLK=14
    -DTFT_CS=15
    -DTFT_DC=2
    -DTFT_RST=-1
    -DTFT_BL=21
    -DTFT_BACKLIGHT_ON=HIGH
    -DUSE_HSPI_PORT=1
    -DTOUCH_CS=33
    -DSPI_FREQUENCY=55000000
    -DSPI_READ_FREQUENCY=20000000
    -DSPI_TOUCH_FREQUENCY=2500000
    -DCORE_DEBUG_LEVEL=1

board_build.partitions = default.csv
```

**Note:** The non-USB-C CYD variant (ESP32-2432S028R) requires `ILI9341_2_DRIVER` instead of `ILI9341_DRIVER`. Touch is handled separately via XPT2046_Touchscreen library on VSPI (CLK=25, MISO=39, MOSI=32, CS=33).

### 8.2 Memory Budget

| Region | Size | Usage |
|--------|------|-------|
| Flash (Code) | 1.5 MB | Firmware + signatures |
| Flash (SPIFFS) | 1.5 MB | Config, logs, custom sigs |
| SRAM | 520 KB | Runtime |
| PSRAM | N/A | Not available on CYD |

---

## 9. Testing Requirements

### 9.1 Unit Tests

- Signature database CRUD operations
- Detection engine pattern matching
- Packet forging correctness
- Command parser validation

### 9.2 Integration Tests

- End-to-end detection flow
- TX -> RX loopback (two devices)
- Serial command automation
- Display state transitions

### 9.3 Hardware Tests

- Touch calibration verification
- BLE range testing
- Power consumption profiling
- SD card logging reliability

---

## 10. Security Considerations

### 10.1 Ethical Use

This tool is designed for:
- **Personal privacy protection** - Detecting trackers placed on your person/vehicle
- **VIP security assessments** - Authorized security evaluations
- **Security research** - Understanding BLE device fingerprinting
- **Penetration testing** - With explicit written authorization

### 10.2 Legal Notice

> **WARNING:** Transmitting BLE advertisements that impersonate other devices may violate local regulations. The "confusion mode" feature should only be used in controlled environments with proper authorization. Medical device detection capabilities are provided for authorized security assessments only.

### 10.3 Implemented Safeguards

- TX mode requires explicit user confirmation
- Medical device category disabled by default
- No persistent storage of MAC addresses by default
- Clear visual indicators when transmitting

---

## 11. Future Enhancements (v2.0+)

- [ ] WiFi web interface for remote monitoring
- [ ] MQTT integration for alerting
- [ ] GPS logging (external module)
- [ ] Device tracking history with graphs
- [ ] Directional RSSI mapping
- [ ] Custom signature sharing platform
- [ ] iOS/Android companion app
- [ ] Extended signature database (community-contributed)
- [ ] Machine learning-based unknown device classification

---

## Appendix A: Bluetooth SIG Company Identifiers Reference

Company IDs used in the signature database:

### Major Tech Companies
| Company ID | Company Name |
|------------|--------------|
| 0x004C | Apple, Inc. |
| 0x0006 | Microsoft |
| 0x0075 | Samsung Electronics |
| 0x00E0 | Google |
| 0x0171 | Amazon.com Services |
| 0x01AB | Meta Platforms, Inc. |
| 0x058E | Meta Platforms Technologies |
| 0x012D | Sony Corporation |
| 0x027D | Huawei Technologies |

### Tracker Companies
| Company ID | Company Name |
|------------|--------------|
| 0xFEEC | Tile, Inc. |
| 0xFEED | Tile, Inc. (alternate) |
| 0xFE65 | Chipolo d.o.o. |
| 0x0757 | Eufy (Anker) |
| 0x0843 | Cube |

### Smart Glasses / AR
| Company ID | Company Name |
|------------|--------------|
| 0x03C2 | Snap Inc. |
| 0x0D53 | Luxottica Group S.p.A. |
| 0x077A | Vuzix Corporation |
| 0x0A14 | XREAL (formerly Nreal) |
| 0x0992 | TCL (RayNeo) |

### Medical - Diabetes
| Company ID | Company Name |
|------------|--------------|
| 0x00D1 | Dexcom, Inc. |
| 0x02A5 | Medtronic, Inc. |
| 0x0618 | Abbott |
| 0x0822 | Insulet Corporation (Omnipod) |
| 0x0801 | Tandem Diabetes Care |
| 0x07E1 | Senseonics |
| 0x0702 | Ascensia Diabetes Care |
| 0x0077 | Roche (Accu-Chek) |
| 0x08B4 | Ypsomed |
| 0x093B | Bigfoot Biomedical |
| 0x0964 | Beta Bionics |
| 0x03F0 | LifeScan (OneTouch) |

### Medical - Cardiac & Other
| Company ID | Company Name |
|------------|--------------|
| 0x00A3 | Biotronik |
| 0x0149 | Boston Scientific |
| 0x041B | AliveCor |
| 0x0571 | Zoll Medical |
| 0x02B5 | ResMed |
| 0x0030 | Philips |
| 0x05E3 | Withings |
| 0x020E | Omron Healthcare |
| 0x0415 | Qardio |
| 0x02C1 | iHealth Labs |

### Wearables & Audio
| Company ID | Company Name |
|------------|--------------|
| 0x0224 | Fitbit, Inc. |
| 0x0087 | Garmin Ltd. |
| 0x0643 | Whoop, Inc. |
| 0x0781 | Oura Health |
| 0x006B | Polar Electro |
| 0x0068 | Suunto |
| 0x038F | Xiaomi |
| 0x0157 | Amazfit (Huami) |
| 0x009E | Bose Corporation |
| 0x0067 | GN Audio (Jabra) |
| 0x0057 | Harman (JBL) |
| 0x0055 | Plantronics |
| 0x02A0 | Skullcandy |
| 0x0059 | Bang & Olufsen |

Full list: https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/

---

## Appendix B: Sample Signature JSON

```json
{
  "signatures": [
    {
      "name": "Apple AirTag (Registered)",
      "category": "TRACKER",
      "company_id": "0x004C",
      "payload_pattern": "4C000719",
      "pattern_offset": 0,
      "threat_level": 4,
      "flags": ["COMPANY_ID", "PAYLOAD", "TRANSMITTABLE"],
      "notes": "FindMy network registered tag"
    },
    {
      "name": "Meta Ray-Ban Glasses",
      "category": "GLASSES",
      "company_id": "0x0D53",
      "threat_level": 5,
      "flags": ["COMPANY_ID", "TRANSMITTABLE"],
      "notes": "Camera-equipped smart glasses"
    },
    {
      "name": "Dexcom G7 CGM",
      "category": "MEDICAL",
      "company_id": "0x00D1",
      "service_uuid": "0xFEBC",
      "threat_level": 3,
      "flags": ["COMPANY_ID", "SERVICE_UUID", "MEDICAL"],
      "notes": "Continuous glucose monitor - VIP indicator"
    }
  ]
}
```

---

*End of Specification*
