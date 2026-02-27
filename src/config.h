/**
 * BLEPTD - BLE Privacy Threat Detector
 * Configuration Header
 */

#ifndef CONFIG_H
#define CONFIG_H

// =============================================================================
// VERSION
// =============================================================================
#ifndef BLEPTD_VERSION
#define BLEPTD_VERSION "1.0.0"
#endif

// =============================================================================
// HARDWARE PIN DEFINITIONS (CYD 2.8")
// =============================================================================

// TFT Display (ILI9341)
#define TFT_MISO_PIN    12
#define TFT_MOSI_PIN    13
#define TFT_SCLK_PIN    14
#define TFT_CS_PIN      15
#define TFT_DC_PIN      2
#define TFT_RST_PIN     -1
#define TFT_BL_PIN      21

// Touch Screen (XPT2046)
#define TOUCH_CS_PIN    33
#define TOUCH_IRQ_PIN   36

// SD Card
#define SD_CS_PIN       5

// =============================================================================
// DISPLAY SETTINGS
// =============================================================================
#define SCREEN_WIDTH    320
#define SCREEN_HEIGHT   240
#define SCREEN_ROTATION 1   // Landscape

// UI Layout
#define STATUS_BAR_HEIGHT   20
#define NAV_BAR_HEIGHT      40
#define CONTENT_HEIGHT      (SCREEN_HEIGHT - STATUS_BAR_HEIGHT - NAV_BAR_HEIGHT)

// =============================================================================
// BLE SETTINGS
// =============================================================================
#define BLE_SCAN_DURATION_SEC   1
#define BLE_SCAN_INTERVAL_MS    100
#define BLE_SCAN_WINDOW_MS      99
#define BLE_ACTIVE_SCAN         true

// TX Settings
#define TX_DEFAULT_INTERVAL_MS  100
#define TX_MAX_CONCURRENT       8
#define TX_CONFUSION_MAX_DEVICES 16

// =============================================================================
// SERIAL SETTINGS
// =============================================================================
#define SERIAL_BAUD_RATE        115200
#define SERIAL_CMD_BUFFER_SIZE  256
#define SERIAL_JSON_OUTPUT      false   // Default to human-readable

// =============================================================================
// STORAGE SETTINGS
// =============================================================================
#define CONFIG_NAMESPACE        "bleptd"
#define SIG_DB_MAX_ENTRIES      128
#define DETECTED_DEVICES_MAX    64

// =============================================================================
// DEVICE CATEGORIES
// =============================================================================
typedef enum {
    CAT_UNKNOWN   = 0x00,
    CAT_TRACKER   = 0x01,
    CAT_GLASSES   = 0x02,
    CAT_MEDICAL   = 0x04,
    CAT_WEARABLE  = 0x08,
    CAT_AUDIO     = 0x10,
    CAT_ALL       = 0xFF
} device_category_t;

// Default filter (excludes medical by default)
#define DEFAULT_CATEGORY_FILTER (CAT_TRACKER | CAT_GLASSES | CAT_WEARABLE | CAT_AUDIO)

// =============================================================================
// THREAT LEVELS
// =============================================================================
#define THREAT_NONE     0
#define THREAT_LOW      1
#define THREAT_MEDIUM   2
#define THREAT_HIGH     3
#define THREAT_SEVERE   4
#define THREAT_CRITICAL 5

// =============================================================================
// COLOR THEME
// =============================================================================
// Using 16-bit RGB565 format
#define COLOR_BG            0x0000  // Black
#define COLOR_FG            0xFFFF  // White
#define COLOR_ACCENT        0xFD20  // Orange
#define COLOR_SUCCESS       0x07E0  // Green
#define COLOR_WARNING       0xFFE0  // Yellow
#define COLOR_ERROR         0xF800  // Red

// Category colors
#define COLOR_CAT_TRACKER   0xF800  // Red
#define COLOR_CAT_GLASSES   0xFD20  // Orange
#define COLOR_CAT_MEDICAL   0xFFE0  // Yellow
#define COLOR_CAT_WEARABLE  0x001F  // Blue
#define COLOR_CAT_AUDIO     0xF81F  // Magenta

// =============================================================================
// FREERTOS TASK CONFIGURATION
// =============================================================================
#define TASK_BLE_SCAN_STACK     4096
#define TASK_BLE_SCAN_PRIORITY  5
#define TASK_BLE_SCAN_CORE      0

#define TASK_BLE_TX_STACK       4096
#define TASK_BLE_TX_PRIORITY    4
#define TASK_BLE_TX_CORE        0

#define TASK_UI_STACK           8192
#define TASK_UI_PRIORITY        3
#define TASK_UI_CORE            1

#define TASK_SERIAL_STACK       4096
#define TASK_SERIAL_PRIORITY    2
#define TASK_SERIAL_CORE        1

// =============================================================================
// DEBUG MACROS
// =============================================================================
#ifdef DEBUG_MODE
    #define DBG_PRINT(x)    Serial.print(x)
    #define DBG_PRINTLN(x)  Serial.println(x)
    #define DBG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
    #define DBG_PRINT(x)
    #define DBG_PRINTLN(x)
    #define DBG_PRINTF(...)
#endif

#endif // CONFIG_H
