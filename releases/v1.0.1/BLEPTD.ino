/**
 * BLEPTD - BLE Privacy Threat Detector
 * Arduino IDE Combined Sketch v1.0.1
 *
 * Hardware: ESP32-2432S028R (CYD 2.8" with micro-USB)
 *
 * New in v1.0.1:
 *   - 128-bit service UUID detection (Flipper Zero support)
 *   - Power save mode (screen off after 5 min idle, wakes on detection)
 *   - Device name pattern matching for detection
 *
 * Required Libraries:
 *   - TFT_eSPI by Bodmer (configure User_Setup.h for CYD)
 *   - XPT2046_Touchscreen by Paul Stoffregen
 *
 * TFT_eSPI User_Setup.h configuration:
 *   #define ILI9341_2_DRIVER
 *   #define TFT_WIDTH 240
 *   #define TFT_HEIGHT 320
 *   #define TFT_MISO 12
 *   #define TFT_MOSI 13
 *   #define TFT_SCLK 14
 *   #define TFT_CS 15
 *   #define TFT_DC 2
 *   #define TFT_RST -1
 *   #define TFT_BL 21
 *   #define USE_HSPI_PORT
 *   #define SPI_FREQUENCY 55000000
 *
 * Power Save: Edit POWERSAVE_ENABLED and POWERSAVE_TIMEOUT_SEC below
 */

#include <Arduino.h>
#include <TFT_eSPI.h>
#include <SPI.h>
#include <XPT2046_Touchscreen.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <esp_bt.h>
#include <esp_gap_ble_api.h>

// =============================================================================
// VERSION & CONFIG
// =============================================================================
#define BLEPTD_VERSION "1.0.1"

// Hardware pins
#define TFT_BL_PIN      21
#define XPT2046_IRQ     36
#define XPT2046_MOSI    32
#define XPT2046_MISO    39
#define XPT2046_CLK     25
#define XPT2046_CS      33

// Display
#define SCREEN_WIDTH    320
#define SCREEN_HEIGHT   240
#define SCREEN_ROTATION 1
#define STATUS_BAR_HEIGHT   20
#define NAV_BAR_HEIGHT      40
#define CONTENT_HEIGHT      (SCREEN_HEIGHT - STATUS_BAR_HEIGHT - NAV_BAR_HEIGHT)

// BLE
#define BLE_SCAN_DURATION_SEC   1
#define BLE_SCAN_INTERVAL_MS    100
#define BLE_SCAN_WINDOW_MS      99
#define BLE_ACTIVE_SCAN         true

// TX
#define TX_DEFAULT_INTERVAL_MS  100
#define TX_MAX_CONCURRENT       8
#define TX_CONFUSION_MAX_DEVICES 16

// Serial
#define SERIAL_BAUD_RATE        115200
#define SERIAL_CMD_BUFFER_SIZE  256

// Storage
#define DETECTED_DEVICES_MAX    64

// Power Save - Edit these values to configure
#define POWERSAVE_ENABLED       true    // Set to false to disable
#define POWERSAVE_TIMEOUT_SEC   300     // 5 minutes

// Categories
#define CAT_UNKNOWN   0x00
#define CAT_TRACKER   0x01
#define CAT_GLASSES   0x02
#define CAT_MEDICAL   0x04
#define CAT_WEARABLE  0x08
#define CAT_AUDIO     0x10
#define DEFAULT_CATEGORY_FILTER (CAT_TRACKER | CAT_GLASSES | CAT_WEARABLE | CAT_AUDIO)

// Threat levels
#define THREAT_NONE     0
#define THREAT_LOW      1
#define THREAT_MEDIUM   2
#define THREAT_HIGH     3
#define THREAT_SEVERE   4
#define THREAT_CRITICAL 5

// Signature flags
#define SIG_FLAG_COMPANY_ID       0x0001
#define SIG_FLAG_PAYLOAD          0x0002
#define SIG_FLAG_SERVICE_UUID     0x0004
#define SIG_FLAG_NAME_PATTERN     0x0008
#define SIG_FLAG_EXACT_MATCH      0x0010
#define SIG_FLAG_TRANSMITTABLE    0x0020
#define SIG_FLAG_MEDICAL          0x0040
#define SIG_FLAG_SERVICE_UUID_128 0x0080

// Company IDs
#define COMPANY_APPLE           0x004C
#define COMPANY_SAMSUNG         0x0075
#define COMPANY_GOOGLE          0x00E0
#define COMPANY_AMAZON          0x0171
#define COMPANY_META            0x01AB
#define COMPANY_META_TECH       0x058E
#define COMPANY_TILE            0xFEEC
#define COMPANY_TILE_ALT        0xFEED
#define COMPANY_CHIPOLO         0xFE65
#define COMPANY_PEBBLEBEE       0x0822
#define COMPANY_EUFY            0x0757
#define COMPANY_CUBE            0x0843
#define COMPANY_FLIPPER         0x0499
#define COMPANY_SNAP            0x03C2
#define COMPANY_LUXOTTICA       0x0D53
#define COMPANY_VUZIX           0x077A
#define COMPANY_XREAL           0x0A14
#define COMPANY_TCLTV           0x0992
#define COMPANY_BOSE            0x009E
#define COMPANY_DEXCOM          0x00D1
#define COMPANY_MEDTRONIC       0x02A5
#define COMPANY_INSULET         0x0822
#define COMPANY_FITBIT          0x0224
#define COMPANY_GARMIN          0x0087
#define COMPANY_SONY            0x012D

// =============================================================================
// SIGNATURES
// =============================================================================
#define UUID128_EMPTY {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
#define UUID128_FLIPPER_SERIAL {0x00,0x00,0xFE,0x60,0xCC,0x7A,0x48,0x2A,0x98,0x4A,0x7F,0x2E,0xD5,0xB3,0xE5,0x8F}

typedef struct {
    char name[32];
    uint8_t category;
    uint16_t company_id;
    uint8_t payload_pattern[8];
    uint8_t pattern_length;
    int8_t pattern_offset;
    uint16_t service_uuid;
    uint8_t service_uuid_128[16];
    uint8_t threat_level;
    uint32_t flags;
} device_signature_t;

static const device_signature_t BUILTIN_SIGNATURES[] = {
    // Trackers
    {"AirTag (Registered)",     CAT_TRACKER, COMPANY_APPLE,    {0x4C,0x00,0x07,0x19,0,0,0,0}, 4,  0, 0, UUID128_EMPTY, THREAT_SEVERE,   SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"AirTag (Unregistered)",   CAT_TRACKER, COMPANY_APPLE,    {0x4C,0x00,0x12,0x19,0,0,0,0}, 4,  0, 0, UUID128_EMPTY, THREAT_SEVERE,   SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Samsung SmartTag",        CAT_TRACKER, COMPANY_SAMSUNG,  {0x75,0x00,0x42,0x09,0x01,0,0,0}, 5, 0, 0, UUID128_EMPTY, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Samsung SmartTag2",       CAT_TRACKER, COMPANY_SAMSUNG,  {0x75,0x00,0x42,0x09,0x02,0,0,0}, 5, 0, 0, UUID128_EMPTY, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Tile Tracker",            CAT_TRACKER, COMPANY_TILE,     {0xEC,0xFE,0,0,0,0,0,0}, 2, -1, 0, UUID128_EMPTY, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Chipolo",                 CAT_TRACKER, COMPANY_CHIPOLO,  {0x65,0xFE,0,0,0,0,0,0}, 2, -1, 0, UUID128_EMPTY, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Google Tracker",          CAT_TRACKER, COMPANY_GOOGLE,   {0,0,0,0,0,0,0,0}, 0, -1, 0xFE2C, UUID128_EMPTY, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_TRANSMITTABLE},
    {"Eufy Tracker",            CAT_TRACKER, COMPANY_EUFY,     {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Cube Tracker",            CAT_TRACKER, COMPANY_CUBE,     {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Flipper Zero",            CAT_TRACKER, COMPANY_FLIPPER,  {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_FLIPPER_SERIAL, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID_128 | SIG_FLAG_NAME_PATTERN},
    // Glasses
    {"Meta Ray-Ban",            CAT_GLASSES, COMPANY_META,      {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Meta Ray-Ban (Tech)",     CAT_GLASSES, COMPANY_META_TECH, {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Snap Spectacles",         CAT_GLASSES, COMPANY_SNAP,      {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Amazon Echo Frames",      CAT_GLASSES, COMPANY_AMAZON,    {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_HIGH, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Bose Frames",             CAT_GLASSES, COMPANY_BOSE,      {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Vuzix Blade",             CAT_GLASSES, COMPANY_VUZIX,     {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"XREAL Air",               CAT_GLASSES, COMPANY_XREAL,     {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_HIGH, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    // Medical
    {"Dexcom G6/G7",            CAT_MEDICAL, COMPANY_DEXCOM,    {0,0,0,0,0,0,0,0}, 0, -1, 0xFEBC, UUID128_EMPTY, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Medtronic Pump",          CAT_MEDICAL, COMPANY_MEDTRONIC, {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    // Wearables
    {"Fitbit",                  CAT_WEARABLE, COMPANY_FITBIT,   {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Garmin Watch",            CAT_WEARABLE, COMPANY_GARMIN,   {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    // Audio
    {"Sony Audio",              CAT_AUDIO, COMPANY_SONY,        {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Bose Audio",              CAT_AUDIO, COMPANY_BOSE,        {0,0,0,0,0,0,0,0}, 0, -1, 0, UUID128_EMPTY, THREAT_LOW, SIG_FLAG_COMPANY_ID},
};
#define BUILTIN_SIGNATURE_COUNT (sizeof(BUILTIN_SIGNATURES) / sizeof(device_signature_t))

// =============================================================================
// TX MANAGER (simplified inline version)
// =============================================================================
typedef struct {
    char deviceName[32];
    const device_signature_t* sig;
    uint32_t intervalMs;
    int32_t remainingCount;
    uint32_t packetsSent;
    uint32_t lastTxTime;
    uint8_t currentMac[6];
    bool randomMacPerPacket;
    bool active;
} tx_session_t;

typedef struct {
    char deviceName[32];
    const device_signature_t* sig;
    uint8_t instanceCount;
    bool enabled;
} confusion_entry_t;

class TXManager {
public:
    tx_session_t _sessions[TX_MAX_CONCURRENT];
    confusion_entry_t _confusionEntries[TX_CONFUSION_MAX_DEVICES];
    bool _confusionActive = false;
    uint32_t _totalPacketsSent = 0;
    uint8_t _confusionIndex = 0;

    void init() { Serial.println("[TX] Initialized"); }

    void generateRandomMac(uint8_t* mac) {
        for (int i = 0; i < 6; i++) mac[i] = esp_random() & 0xFF;
        mac[0] = (mac[0] | 0x02) & 0xFE;
    }

    const device_signature_t* findSignatureByName(const char* name) {
        for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
            if ((BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) && strcasestr(BUILTIN_SIGNATURES[i].name, name))
                return &BUILTIN_SIGNATURES[i];
        }
        return nullptr;
    }

    int getTransmittableCount() {
        int c = 0;
        for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++)
            if (BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) c++;
        return c;
    }

    const device_signature_t* getTransmittableSignature(int idx) {
        int c = 0;
        for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
            if (BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) {
                if (c == idx) return &BUILTIN_SIGNATURES[i];
                c++;
            }
        }
        return nullptr;
    }

    int getActiveCount() {
        int c = 0;
        for (int i = 0; i < TX_MAX_CONCURRENT; i++) if (_sessions[i].active) c++;
        return c;
    }

    tx_session_t* getSession(int i) { return (i >= 0 && i < TX_MAX_CONCURRENT) ? &_sessions[i] : nullptr; }
    tx_session_t* findSession(const char* name) {
        for (int i = 0; i < TX_MAX_CONCURRENT; i++)
            if (_sessions[i].active && strcasecmp(_sessions[i].deviceName, name) == 0) return &_sessions[i];
        return nullptr;
    }

    int startTx(const char* name, uint32_t interval, int32_t count, bool randomMac) {
        const device_signature_t* sig = findSignatureByName(name);
        if (!sig) return -1;
        if (findSession(name)) return -2;
        for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
            if (!_sessions[i].active) {
                strncpy(_sessions[i].deviceName, sig->name, 31);
                _sessions[i].sig = sig;
                _sessions[i].intervalMs = interval;
                _sessions[i].remainingCount = count;
                _sessions[i].packetsSent = 0;
                _sessions[i].lastTxTime = 0;
                _sessions[i].randomMacPerPacket = randomMac;
                _sessions[i].active = true;
                generateRandomMac(_sessions[i].currentMac);
                return i;
            }
        }
        return -3;
    }

    int stopTx(const char* name) {
        tx_session_t* s = findSession(name);
        if (s) { s->active = false; return 0; }
        return -1;
    }

    void stopAll() {
        for (int i = 0; i < TX_MAX_CONCURRENT; i++) _sessions[i].active = false;
        _confusionActive = false;
    }

    int confuseAdd(const char* name, uint8_t cnt) {
        const device_signature_t* sig = findSignatureByName(name);
        if (!sig) return -1;
        for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
            if (!_confusionEntries[i].enabled) {
                strncpy(_confusionEntries[i].deviceName, sig->name, 31);
                _confusionEntries[i].sig = sig;
                _confusionEntries[i].instanceCount = cnt;
                _confusionEntries[i].enabled = true;
                return i;
            }
        }
        return -2;
    }

    int confuseRemove(const char* name) {
        for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++)
            if (_confusionEntries[i].enabled && strcasecmp(_confusionEntries[i].deviceName, name) == 0) {
                _confusionEntries[i].enabled = false; return 0;
            }
        return -1;
    }

    void confuseClear() {
        for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) _confusionEntries[i].enabled = false;
        _confusionActive = false;
    }

    int getConfusionEntryCount() {
        int c = 0;
        for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) if (_confusionEntries[i].enabled) c++;
        return c;
    }

    confusion_entry_t* getConfusionEntry(int idx) {
        int c = 0;
        for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
            if (_confusionEntries[i].enabled) {
                if (c == idx) return &_confusionEntries[i];
                c++;
            }
        }
        return nullptr;
    }

    int confuseStart() {
        if (getConfusionEntryCount() == 0) return -1;
        _confusionActive = true;
        _confusionIndex = 0;
        return getConfusionEntryCount();
    }

    void confuseStop() { _confusionActive = false; }
    bool isConfusionActive() { return _confusionActive; }
    uint32_t getTotalPacketsSent() { return _totalPacketsSent; }

    bool buildAdvData(const device_signature_t* sig, uint8_t* data, uint8_t* len) {
        uint8_t p = 0;
        data[p++] = 0x02; data[p++] = 0x01; data[p++] = 0x06;
        if (sig->company_id != 0) {
            if (sig->pattern_length > 0 && sig->pattern_offset == 0) {
                data[p++] = sig->pattern_length + 1;
                data[p++] = 0xFF;
                memcpy(&data[p], sig->payload_pattern, sig->pattern_length);
                p += sig->pattern_length;
            } else {
                data[p++] = 7; data[p++] = 0xFF;
                data[p++] = sig->company_id & 0xFF;
                data[p++] = (sig->company_id >> 8) & 0xFF;
                for (int i = 0; i < 4; i++) data[p++] = esp_random() & 0xFF;
            }
        }
        if (sig->service_uuid != 0) {
            data[p++] = 0x03; data[p++] = 0x03;
            data[p++] = sig->service_uuid & 0xFF;
            data[p++] = (sig->service_uuid >> 8) & 0xFF;
        }
        *len = p;
        return p > 0;
    }

    void transmitPacket(tx_session_t* s) {
        if (!s->active || !s->sig) return;
        uint8_t advData[31]; uint8_t advLen = 0;
        if (!buildAdvData(s->sig, advData, &advLen)) return;
        if (s->randomMacPerPacket) generateRandomMac(s->currentMac);
        esp_ble_gap_set_rand_addr(s->currentMac);
        esp_ble_adv_params_t params = {.adv_int_min=0x20,.adv_int_max=0x20,.adv_type=ADV_TYPE_NONCONN_IND,.own_addr_type=BLE_ADDR_TYPE_RANDOM,.peer_addr={0},.peer_addr_type=BLE_ADDR_TYPE_PUBLIC,.channel_map=ADV_CHNL_ALL,.adv_filter_policy=ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY};
        esp_ble_gap_config_adv_data_raw(advData, advLen);
        delay(10);
        esp_ble_gap_start_advertising(&params);
        delay(30);
        esp_ble_gap_stop_advertising();
        delay(5);
        s->packetsSent++;
        s->lastTxTime = millis();
        _totalPacketsSent++;
        if (s->remainingCount > 0 && --s->remainingCount == 0) s->active = false;
    }

    void transmitConfusion() {
        if (!_confusionActive) return;
        for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
            int idx = (_confusionIndex + i) % TX_CONFUSION_MAX_DEVICES;
            if (_confusionEntries[idx].enabled) {
                uint8_t advData[31]; uint8_t advLen = 0;
                if (buildAdvData(_confusionEntries[idx].sig, advData, &advLen)) {
                    uint8_t mac[6]; generateRandomMac(mac);
                    esp_ble_gap_set_rand_addr(mac);
                    esp_ble_adv_params_t params = {.adv_int_min=0x20,.adv_int_max=0x20,.adv_type=ADV_TYPE_NONCONN_IND,.own_addr_type=BLE_ADDR_TYPE_RANDOM,.peer_addr={0},.peer_addr_type=BLE_ADDR_TYPE_PUBLIC,.channel_map=ADV_CHNL_ALL,.adv_filter_policy=ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY};
                    esp_ble_gap_config_adv_data_raw(advData, advLen);
                    delay(5);
                    esp_ble_gap_start_advertising(&params);
                    delay(25);
                    esp_ble_gap_stop_advertising();
                    _totalPacketsSent++;
                }
                _confusionIndex = (idx + 1) % TX_CONFUSION_MAX_DEVICES;
                return;
            }
        }
    }

    void process() {
        uint32_t now = millis();
        for (int i = 0; i < TX_MAX_CONCURRENT; i++)
            if (_sessions[i].active && now - _sessions[i].lastTxTime >= _sessions[i].intervalMs)
                transmitPacket(&_sessions[i]);
        if (_confusionActive) {
            static uint32_t lastC = 0;
            if (now - lastC >= 20) { transmitConfusion(); lastC = now; }
        }
    }
};

TXManager txManager;

// =============================================================================
// GLOBALS
// =============================================================================
TFT_eSPI tft = TFT_eSPI();
SPIClass touchSpi(VSPI);
XPT2046_Touchscreen ts(XPT2046_CS);
BLEScan* pBLEScan = nullptr;

volatile bool scanning = false;
volatile bool txActive = false;
uint8_t currentScreen = 0;
uint8_t categoryFilter = DEFAULT_CATEGORY_FILTER;
int8_t rssiThreshold = -80;
int scrollOffset = 0;
int selectedDeviceIdx = -1;
const int ITEMS_PER_PAGE = 9;
const int ITEM_HEIGHT = 18;

// Power save
bool powerSaveEnabled = POWERSAVE_ENABLED;
uint32_t powerSaveTimeoutSec = POWERSAVE_TIMEOUT_SEC;
uint32_t lastNewDeviceTime = 0;
bool screenAsleep = false;

struct DetectedDevice {
    char name[32];
    uint8_t mac[6];
    int8_t rssi;
    uint8_t category;
    uint16_t companyId;
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint16_t detectionCount;
    uint8_t threatLevel;
    bool active;
};
DetectedDevice detectedDevices[DETECTED_DEVICES_MAX];
int detectedCount = 0;

char cmdBuffer[SERIAL_CMD_BUFFER_SIZE];
int cmdIndex = 0;
bool jsonOutput = false;

// Forward declarations
void drawStatusBar();
void drawNavBar();
void drawScanScreen();
void drawFilterScreen();
void drawTXScreen();
void drawSettingsScreen();
void drawDetailScreen();
void wakeScreen();

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================
const char* getCategoryString(uint8_t cat) {
    switch(cat) {
        case CAT_TRACKER: return "TRACKER";
        case CAT_GLASSES: return "GLASSES";
        case CAT_MEDICAL: return "MEDICAL";
        case CAT_WEARABLE: return "WEARABLE";
        case CAT_AUDIO: return "AUDIO";
        default: return "UNKNOWN";
    }
}

static bool isUuid128Empty(const uint8_t* uuid) {
    for (int i = 0; i < 16; i++) if (uuid[i] != 0) return false;
    return true;
}

// =============================================================================
// SIGNATURE MATCHING (with 128-bit UUID support)
// =============================================================================
const device_signature_t* matchSignature(BLEAdvertisedDevice* device) {
    uint8_t* payload = device->getPayload();
    size_t payloadLen = device->getPayloadLength();
    uint16_t mfgCompanyId = 0;
    bool hasMfgData = false;
    uint16_t serviceUuid16 = 0;
    bool hasServiceUuid16 = false;
    uint8_t serviceUuid128[16] = {0};
    bool hasServiceUuid128 = false;
    std::string deviceName = device->getName();

    size_t idx = 0;
    while (idx < payloadLen) {
        uint8_t len = payload[idx];
        if (len == 0 || idx + len >= payloadLen) break;
        uint8_t type = payload[idx + 1];
        switch (type) {
            case 0xFF:
                if (len >= 3) { mfgCompanyId = payload[idx+2] | (payload[idx+3]<<8); hasMfgData = true; }
                break;
            case 0x02: case 0x03:
                if (len >= 3) { serviceUuid16 = payload[idx+2] | (payload[idx+3]<<8); hasServiceUuid16 = true; }
                break;
            case 0x06: case 0x07:
                if (len >= 17) { memcpy(serviceUuid128, &payload[idx+2], 16); hasServiceUuid128 = true; }
                break;
        }
        idx += len + 1;
    }

    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        const device_signature_t* sig = &BUILTIN_SIGNATURES[i];
        bool matched = false;

        if ((sig->flags & SIG_FLAG_COMPANY_ID) && hasMfgData && sig->company_id == mfgCompanyId) matched = true;
        if ((sig->flags & SIG_FLAG_SERVICE_UUID) && hasServiceUuid16 && sig->service_uuid == serviceUuid16) matched = true;
        if ((sig->flags & SIG_FLAG_SERVICE_UUID_128) && hasServiceUuid128 && !isUuid128Empty(sig->service_uuid_128))
            if (memcmp(sig->service_uuid_128, serviceUuid128, 16) == 0) matched = true;
        if ((sig->flags & SIG_FLAG_NAME_PATTERN) && deviceName.length() > 0) {
            std::string ln = deviceName, ls = sig->name;
            for (auto& c : ln) c = tolower(c);
            for (auto& c : ls) c = tolower(c);
            if (ln.find(ls) != std::string::npos || ls.find(ln) != std::string::npos) matched = true;
        }
        if ((sig->flags & SIG_FLAG_PAYLOAD) && sig->pattern_length > 0) {
            bool found = false;
            if (sig->pattern_offset >= 0) {
                if ((size_t)(sig->pattern_offset + sig->pattern_length) <= payloadLen)
                    if (memcmp(payload + sig->pattern_offset, sig->payload_pattern, sig->pattern_length) == 0) found = true;
            } else {
                for (size_t j = 0; j + sig->pattern_length <= payloadLen; j++)
                    if (memcmp(payload + j, sig->payload_pattern, sig->pattern_length) == 0) { found = true; break; }
            }
            if (sig->flags & SIG_FLAG_EXACT_MATCH) matched = matched && found;
            else matched = matched || found;
        }
        if (matched) return sig;
    }
    return nullptr;
}

// =============================================================================
// BLE SCAN CALLBACK
// =============================================================================
class ScanCallbacks : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) override {
        const device_signature_t* sig = matchSignature(&advertisedDevice);
        if (!sig) return;
        if (!(sig->category & categoryFilter)) return;
        if (advertisedDevice.getRSSI() < rssiThreshold) return;

        uint8_t mac[6];
        memcpy(mac, advertisedDevice.getAddress().getNative(), 6);

        int existingIdx = -1;
        for (int i = 0; i < detectedCount; i++)
            if (memcmp(detectedDevices[i].mac, mac, 6) == 0) { existingIdx = i; break; }

        if (existingIdx >= 0) {
            detectedDevices[existingIdx].rssi = advertisedDevice.getRSSI();
            detectedDevices[existingIdx].lastSeen = millis();
            detectedDevices[existingIdx].detectionCount++;
            detectedDevices[existingIdx].active = true;
        } else if (detectedCount < DETECTED_DEVICES_MAX) {
            DetectedDevice* dev = &detectedDevices[detectedCount];
            strncpy(dev->name, sig->name, 31);
            memcpy(dev->mac, mac, 6);
            dev->rssi = advertisedDevice.getRSSI();
            dev->category = sig->category;
            dev->companyId = sig->company_id;
            dev->firstSeen = millis();
            dev->lastSeen = millis();
            dev->detectionCount = 1;
            dev->threatLevel = sig->threat_level;
            dev->active = true;
            detectedCount++;
            wakeScreen();  // Wake on new device
            char macStr[18];
            snprintf(macStr, 18, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
            Serial.printf("[%lu] DETECT %s MAC=%s RSSI=%d CAT=%s\n", millis(), dev->name, macStr, dev->rssi, getCategoryString(dev->category));
        }
    }
};

// =============================================================================
// POWER SAVE
// =============================================================================
void wakeScreen() {
    if (screenAsleep) {
        digitalWrite(TFT_BL_PIN, HIGH);
        screenAsleep = false;
        Serial.println("[PowerSave] Screen woke");
    }
    lastNewDeviceTime = millis();
}

void sleepScreen() {
    if (!screenAsleep) {
        digitalWrite(TFT_BL_PIN, LOW);
        screenAsleep = true;
        Serial.println("[PowerSave] Screen sleeping");
    }
}

void checkPowerSave() {
    if (!powerSaveEnabled || txActive) return;
    if ((millis() - lastNewDeviceTime) / 1000 >= powerSaveTimeoutSec && !screenAsleep) sleepScreen();
}

// =============================================================================
// DISPLAY FUNCTIONS (simplified)
// =============================================================================
void initDisplay() {
    tft.init();
    tft.setRotation(SCREEN_ROTATION);
    tft.fillScreen(TFT_BLACK);
    pinMode(TFT_BL_PIN, OUTPUT);
    digitalWrite(TFT_BL_PIN, HIGH);
    drawStatusBar();
    drawNavBar();
}

void drawStatusBar() {
    tft.fillRect(0, 0, SCREEN_WIDTH, STATUS_BAR_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("BLEPTD v" BLEPTD_VERSION, 4, 6, 1);
    String mode = txManager.isConfusionActive() ? "CONFUSE" : txManager.getActiveCount() > 0 ? "TX" : scanning ? "SCANNING" : "IDLE";
    uint16_t col = txManager.isConfusionActive() ? TFT_RED : txManager.getActiveCount() > 0 ? TFT_YELLOW : scanning ? TFT_GREEN : TFT_WHITE;
    tft.setTextDatum(TR_DATUM);
    tft.setTextColor(col);
    tft.drawString(mode, SCREEN_WIDTH - 4, 6, 1);
}

void drawNavBar() {
    int y = SCREEN_HEIGHT - NAV_BAR_HEIGHT;
    tft.fillRect(0, y, SCREEN_WIDTH, NAV_BAR_HEIGHT, TFT_DARKGREY);
    const char* tabs[] = {"SCAN", "FILTER", "TX", "SETUP"};
    int tw = SCREEN_WIDTH / 4;
    for (int i = 0; i < 4; i++) {
        tft.setTextColor(i == currentScreen ? TFT_YELLOW : TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString(tabs[i], i * tw + tw/2, y + NAV_BAR_HEIGHT/2, 2);
    }
}

void drawScanScreen() {
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("DETECTED DEVICES", 4, STATUS_BAR_HEIGHT + 4, 2);
    int y = STATUS_BAR_HEIGHT + 24;
    int displayed = 0;
    for (int i = scrollOffset; i < detectedCount && displayed < ITEMS_PER_PAGE; i++) {
        if (!(detectedDevices[i].category & categoryFilter)) continue;
        uint16_t col = TFT_WHITE;
        switch(detectedDevices[i].category) {
            case CAT_TRACKER: col = TFT_RED; break;
            case CAT_GLASSES: col = TFT_ORANGE; break;
            case CAT_MEDICAL: col = TFT_YELLOW; break;
            case CAT_WEARABLE: col = TFT_BLUE; break;
            case CAT_AUDIO: col = TFT_MAGENTA; break;
        }
        tft.fillCircle(SCREEN_WIDTH - 10, y + 7, 4, col);
        tft.setTextColor(TFT_WHITE);
        tft.drawString(detectedDevices[i].name, 4, y, 1);
        char rssi[8]; snprintf(rssi, 8, "%d", detectedDevices[i].rssi);
        tft.setTextColor(TFT_YELLOW);
        tft.drawString(rssi, 260, y, 1);
        y += ITEM_HEIGHT;
        displayed++;
    }
    if (detectedCount == 0) {
        tft.setTextDatum(MC_DATUM);
        tft.setTextColor(TFT_DARKGREY);
        tft.drawString("Scanning...", SCREEN_WIDTH/2, SCREEN_HEIGHT/2, 2);
    }
}

void drawFilterScreen() {
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("CATEGORIES", 4, STATUS_BAR_HEIGHT + 4, 2);
    struct { uint8_t c; const char* n; uint16_t col; } cats[] = {
        {CAT_TRACKER,"TRACKER",TFT_RED},{CAT_GLASSES,"GLASSES",TFT_ORANGE},{CAT_MEDICAL,"MEDICAL",TFT_YELLOW},{CAT_WEARABLE,"WEARABLE",TFT_BLUE},{CAT_AUDIO,"AUDIO",TFT_MAGENTA}
    };
    int y = STATUS_BAR_HEIGHT + 28;
    for (int i = 0; i < 5; i++) {
        bool on = categoryFilter & cats[i].c;
        tft.drawRect(8, y, 14, 14, cats[i].col);
        if (on) tft.fillRect(10, y+2, 10, 10, cats[i].col);
        tft.setTextColor(on ? TFT_WHITE : TFT_DARKGREY);
        tft.drawString(cats[i].n, 28, y+2, 1);
        y += 22;
    }
}

void drawTXScreen() {
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    if (txManager.isConfusionActive() || txManager.getActiveCount() > 0) {
        tft.setTextColor(txManager.isConfusionActive() ? TFT_RED : TFT_YELLOW);
        tft.drawString(txManager.isConfusionActive() ? "CONFUSION" : "TRANSMITTING", 4, STATUS_BAR_HEIGHT + 4, 2);
        tft.fillRoundRect(220, STATUS_BAR_HEIGHT + 4, 90, 28, 4, TFT_RED);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("STOP", 265, STATUS_BAR_HEIGHT + 18, 2);
    } else {
        tft.setTextColor(TFT_WHITE);
        tft.drawString("TAP TO TX", 4, STATUS_BAR_HEIGHT + 4, 2);
        tft.fillRoundRect(220, STATUS_BAR_HEIGHT + 4, 90, 28, 4, TFT_MAGENTA);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("CONFUSE", 265, STATUS_BAR_HEIGHT + 18, 2);
        int y = STATUS_BAR_HEIGHT + 40;
        int cnt = txManager.getTransmittableCount();
        for (int i = 0; i < cnt && i < 8; i++) {
            const device_signature_t* s = txManager.getTransmittableSignature(i);
            if (s) {
                tft.setTextDatum(TL_DATUM);
                tft.setTextColor(TFT_WHITE);
                tft.drawString(s->name, 24, y, 1);
                y += 18;
            }
        }
    }
}

void drawSettingsScreen() {
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("SETTINGS", 4, STATUS_BAR_HEIGHT + 4, 2);
    int y = STATUS_BAR_HEIGHT + 28;
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Power Save:", 4, y, 1);
    tft.setTextColor(powerSaveEnabled ? TFT_GREEN : TFT_RED);
    tft.drawString(powerSaveEnabled ? "ON" : "OFF", 100, y, 1);
    y += 16;
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Timeout:", 4, y, 1);
    char buf[16]; snprintf(buf, 16, "%lus", powerSaveTimeoutSec);
    tft.setTextColor(TFT_WHITE);
    tft.drawString(buf, 100, y, 1);
    y += 16;
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Devices:", 4, y, 1);
    snprintf(buf, 16, "%d", detectedCount);
    tft.setTextColor(TFT_WHITE);
    tft.drawString(buf, 100, y, 1);
}

void drawDetailScreen() {
    if (selectedDeviceIdx < 0 || selectedDeviceIdx >= detectedCount) { currentScreen = 0; drawScanScreen(); return; }
    DetectedDevice* d = &detectedDevices[selectedDeviceIdx];
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_YELLOW);
    tft.drawString(d->name, 4, STATUS_BAR_HEIGHT + 4, 2);
    tft.setTextDatum(TR_DATUM);
    tft.setTextColor(TFT_RED);
    tft.drawString("[X]", SCREEN_WIDTH - 4, STATUS_BAR_HEIGHT + 4, 2);
}

// =============================================================================
// TOUCH HANDLING
// =============================================================================
#define TOUCH_X_MIN 300
#define TOUCH_X_MAX 3650
#define TOUCH_Y_MIN 400
#define TOUCH_Y_MAX 3750

void handleTouch() {
    static uint32_t lastTouch = 0;
    TS_Point p = ts.getPoint();
    if (p.z < 100) return;
    if (millis() - lastTouch < 250) return;
    if (screenAsleep) { wakeScreen(); lastTouch = millis(); return; }
    lastNewDeviceTime = millis();
    int16_t tx = map(p.y, TOUCH_Y_MIN, TOUCH_Y_MAX, 0, SCREEN_WIDTH);
    int16_t ty = map(p.x, TOUCH_X_MAX, TOUCH_X_MIN, 0, SCREEN_HEIGHT);
    tx = constrain(tx, 0, SCREEN_WIDTH - 1);
    ty = constrain(ty, 0, SCREEN_HEIGHT - 1);
    lastTouch = millis();

    if (currentScreen == 4) { currentScreen = 0; drawScanScreen(); drawNavBar(); return; }

    if (ty >= SCREEN_HEIGHT - NAV_BAR_HEIGHT) {
        int newScreen = tx / (SCREEN_WIDTH / 4);
        if (newScreen != currentScreen && newScreen <= 3) {
            currentScreen = newScreen;
            scrollOffset = 0;
            switch(currentScreen) {
                case 0: drawScanScreen(); break;
                case 1: drawFilterScreen(); break;
                case 2: drawTXScreen(); break;
                case 3: drawSettingsScreen(); break;
            }
            drawNavBar();
        }
    }
    else if (currentScreen == 1 && ty > STATUS_BAR_HEIGHT + 24) {
        int idx = (ty - STATUS_BAR_HEIGHT - 28) / 22;
        uint8_t cats[] = {CAT_TRACKER, CAT_GLASSES, CAT_MEDICAL, CAT_WEARABLE, CAT_AUDIO};
        if (idx >= 0 && idx < 5) { categoryFilter ^= cats[idx]; drawFilterScreen(); }
    }
    else if (currentScreen == 2 && ty > STATUS_BAR_HEIGHT) {
        if (tx >= 220 && tx <= 310 && ty >= STATUS_BAR_HEIGHT + 4 && ty <= STATUS_BAR_HEIGHT + 32) {
            if (txManager.isConfusionActive() || txManager.getActiveCount() > 0) {
                txManager.stopAll();
                txActive = false;
            } else {
                txManager.confuseClear();
                int cnt = txManager.getTransmittableCount();
                for (int i = 0; i < cnt; i++) {
                    const device_signature_t* s = txManager.getTransmittableSignature(i);
                    if (s) txManager.confuseAdd(s->name, 1);
                }
                txManager.confuseStart();
                txActive = true;
            }
            drawTXScreen();
        }
    }
}

// =============================================================================
// SERIAL COMMANDS
// =============================================================================
void processCommand(const char* cmd) {
    String c = String(cmd); c.trim(); c.toUpperCase();
    if (c == "HELP") {
        Serial.println("Commands: HELP VERSION STATUS SCAN START/STOP/CLEAR/LIST TX LIST/START/STOP CONFUSE ADD/START/STOP/CLEAR POWERSAVE STATUS/ON/OFF/TIMEOUT/WAKE");
    }
    else if (c == "VERSION") Serial.printf("BLEPTD v%s\n", BLEPTD_VERSION);
    else if (c == "STATUS") Serial.printf("Scanning:%s TX:%d Devices:%d\n", scanning?"ON":"OFF", txManager.getActiveCount(), detectedCount);
    else if (c == "SCAN START") { scanning = true; Serial.println("OK"); }
    else if (c == "SCAN STOP") { scanning = false; pBLEScan->stop(); Serial.println("OK"); }
    else if (c == "SCAN CLEAR") { detectedCount = 0; Serial.println("OK"); }
    else if (c == "POWERSAVE STATUS") Serial.printf("Enabled:%s Timeout:%lus Screen:%s\n", powerSaveEnabled?"true":"false", powerSaveTimeoutSec, screenAsleep?"sleeping":"awake");
    else if (c == "POWERSAVE ON") { powerSaveEnabled = true; Serial.println("OK"); }
    else if (c == "POWERSAVE OFF") { powerSaveEnabled = false; if(screenAsleep) wakeScreen(); Serial.println("OK"); }
    else if (c == "POWERSAVE WAKE") { wakeScreen(); Serial.println("OK"); }
    else if (c.startsWith("POWERSAVE TIMEOUT ")) {
        uint32_t t = c.substring(18).toInt();
        if (t >= 10 && t <= 3600) { powerSaveTimeoutSec = t; Serial.printf("OK Timeout=%lus\n", t); }
        else Serial.println("ERROR: 10-3600");
    }
    else Serial.printf("Unknown: %s\n", cmd);
}

// =============================================================================
// MAIN
// =============================================================================
void setup() {
    Serial.begin(SERIAL_BAUD_RATE);
    Serial.println("BLEPTD v" BLEPTD_VERSION);
    initDisplay();
    pinMode(XPT2046_CS, OUTPUT);
    digitalWrite(XPT2046_CS, HIGH);
    touchSpi.begin(XPT2046_CLK, XPT2046_MISO, XPT2046_MOSI, XPT2046_CS);
    ts.begin(touchSpi);
    ts.setRotation(0);
    BLEDevice::init("BLEPTD");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new ScanCallbacks(), true);
    pBLEScan->setActiveScan(BLE_ACTIVE_SCAN);
    pBLEScan->setInterval(BLE_SCAN_INTERVAL_MS);
    pBLEScan->setWindow(BLE_SCAN_WINDOW_MS);
    txManager.init();
    drawScanScreen();
    lastNewDeviceTime = millis();
    scanning = true;
    Serial.println("Ready. Type HELP for commands.");
}

void loop() {
    checkPowerSave();
    handleTouch();
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (cmdIndex > 0) { cmdBuffer[cmdIndex] = '\0'; processCommand(cmdBuffer); cmdIndex = 0; }
        } else if (cmdIndex < SERIAL_CMD_BUFFER_SIZE - 1) cmdBuffer[cmdIndex++] = c;
    }
    txManager.process();
    txActive = txManager.getActiveCount() > 0 || txManager.isConfusionActive();
    static uint32_t lastScan = 0;
    if (scanning && !txActive && millis() - lastScan > 5000) {
        lastScan = millis();
        pBLEScan->start(BLE_SCAN_DURATION_SEC, false);
        pBLEScan->clearResults();
    }
    static uint8_t lastScreen = 255;
    static int lastCount = -1;
    if (lastScreen != currentScreen || (currentScreen == 0 && lastCount != detectedCount)) {
        switch(currentScreen) {
            case 0: drawScanScreen(); break;
            case 1: drawFilterScreen(); break;
            case 2: drawTXScreen(); break;
            case 3: drawSettingsScreen(); break;
            case 4: drawDetailScreen(); break;
        }
        if (currentScreen != 4) drawNavBar();
        drawStatusBar();
        lastScreen = currentScreen;
        lastCount = detectedCount;
    }
    delay(10);
}
