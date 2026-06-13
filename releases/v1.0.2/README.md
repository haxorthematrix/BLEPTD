# BLEPTD v1.0.2 Release

**Release Date:** 2026-06-13

## What's New

- **USB-C CYD support (ILI9342 driver)** — the v3 CYD board with a USB-C
  connector no longer comes up as a white screen. The original micro-USB board
  (ILI9341) is still fully supported; the correct driver is now picked at
  compile time. The USB-C variant also forces portrait-native init dimensions
  (240×320) in the `TFT_eSPI` constructor so `setRotation(1)` correctly maps
  to the 320×240 landscape panel — without this the right ~80 px showed up as
  a gray bar.
- **Variant-aware boot banner and `VERSION` command** — both now print which
  board variant the firmware was built for, e.g.
  `BLEPTD v1.0.2 (USB-C/ILI9342)`.
- **Two PlatformIO environments** (`cyd_microusb`, `cyd_usbc`) plus a backward
  compatible `cyd` alias for the original micro-USB build.

## Which firmware do I need?

| Your CYD | Display controller | Use this firmware |
|----------|--------------------|-------------------|
| Single micro-USB connector (ESP32-2432S028R v1/v2) | ILI9341 | `microusb/BLEPTD_v1.0.2_microusb.bin` |
| USB-C connector (ESP32-2432S028R v3, with or without an extra micro-USB) | ILI9342 | `usbc/BLEPTD_v1.0.2_usbc.bin` |

If you flash the wrong image the symptom is unambiguous: a fully **white screen**
with the backlight on but no UI rendered. Flash the other variant.

> **Testing status:** The USB-C build was developed and verified on a real
> USB-C CYD (full panel, correct orientation). The micro-USB build was
> produced from the same code base — only the TFT_eSPI driver defines and
> the `TFT_eSPI` constructor dimensions differ between the two variants —
> and has not been retested on a micro-USB board for this release; please
> file an issue if you see regressions.

## Files Included

```
releases/v1.0.2/
├── microusb/
│   ├── BLEPTD_v1.0.2_microusb.bin   # Main firmware (flash at 0x10000)
│   ├── bootloader.bin               # ESP32 bootloader (flash at 0x1000)
│   └── partitions.bin               # Partition table (flash at 0x8000)
├── usbc/
│   ├── BLEPTD_v1.0.2_usbc.bin       # Main firmware (flash at 0x10000)
│   ├── bootloader.bin               # ESP32 bootloader (flash at 0x1000)
│   └── partitions.bin               # Partition table (flash at 0x8000)
└── README.md
```

## Flashing Instructions

### esptool (recommended)

USB-C CYD:

```bash
pip install esptool
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 460800 \
    write_flash \
    0x1000 usbc/bootloader.bin \
    0x8000 usbc/partitions.bin \
    0x10000 usbc/BLEPTD_v1.0.2_usbc.bin
```

micro-USB CYD:

```bash
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 460800 \
    write_flash \
    0x1000 microusb/bootloader.bin \
    0x8000 microusb/partitions.bin \
    0x10000 microusb/BLEPTD_v1.0.2_microusb.bin
```

### ESP Flash Download Tool (Windows)

1. Download from Espressif: https://www.espressif.com/en/support/download/other-tools
2. Select ESP32, Develop mode
3. Add the three files for your variant at the offsets shown above
4. Set baud to 460800, click START

### Building from source

```bash
# micro-USB / ILI9341 board
pio run -e cyd_microusb -t upload

# USB-C / ILI9342 board
pio run -e cyd_usbc -t upload
```

## Verifying you flashed the right image

Open a serial monitor at 115200 baud after boot, or send `VERSION`. You should
see:

```
BLEPTD v1.0.2 (USB-C/ILI9342)
```

or

```
BLEPTD v1.0.2 (microUSB/ILI9341)
```

## Background: why two firmware images?

The "Cheap Yellow Display" sold as ESP32-2432S028R has shipped in two hardware
revisions that share the ESP32 module, the touch controller, and the pinout —
but use **different TFT controllers**:

- Boards with a single micro-USB connector: ILI9341
- Boards with a USB-C connector (sometimes plus a second micro-USB): ILI9342

The TFT_eSPI driver chip is selected at compile time, so a single binary cannot
serve both. Flashing the ILI9341 build to an ILI9342 board leaves the panel in
its default white/uninitialised state because the ILI9342 ignores the ILI9341
init sequence. The ILI9342 panel on the USB-C board also needs `TFT_RGB_ORDER =
TFT_RGB` and `TFT_INVERSION_ON`, plus a `TFT_eSPI(240, 320)` constructor
override so the rotation table maps to the panel's actual 320×240 landscape
geometry instead of leaving a gray bar on the right.

> Note: Earlier community reports identified the USB-C CYD as using an ST7789
> controller. That's incorrect — the panel is actually an ILI9342, which is a
> close ILI9341 cousin with landscape-native dimensions. The intermediate
> ST7789 build attempted during development of this release still produced a
> white screen on the real hardware; ILI9342 is the working configuration.
