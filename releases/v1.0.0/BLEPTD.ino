/**
 * BLEPTD - BLE Privacy Threat Detector
 * Arduino IDE Combined Sketch
 *
 * Hardware: ESP32-2432S028R (CYD 2.8" with micro-USB)
 *
 * Required Libraries:
 *   - TFT_eSPI by Bodmer (configure User_Setup.h for CYD)
 *   - XPT2046_Touchscreen by Paul Stoffregen
 *   - ArduinoJson by Benoit Blanchon
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
// VERSION
// =============================================================================
#define BLEPTD_VERSION "1.0.0"

// =============================================================================
// HARDWARE PIN DEFINITIONS (CYD 2.8")
// =============================================================================
#define TFT_BL_PIN      21
#define XPT2046_IRQ     36
#define XPT2046_MOSI    32
#define XPT2046_MISO    39
#define XPT2046_CLK     25
#define XPT2046_CS      33

// =============================================================================
// DISPLAY SETTINGS
// =============================================================================
#define SCREEN_WIDTH    320
#define SCREEN_HEIGHT   240
#define SCREEN_ROTATION 1

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
#define TX_DEFAULT_INTERVAL_MS  100
#define TX_MAX_CONCURRENT       8
#define TX_CONFUSION_MAX_DEVICES 16

// =============================================================================
// SERIAL SETTINGS
// =============================================================================
#define SERIAL_BAUD_RATE        115200
#define SERIAL_CMD_BUFFER_SIZE  256
#define SERIAL_JSON_OUTPUT      false

// =============================================================================
// STORAGE SETTINGS
// =============================================================================
#define DETECTED_DEVICES_MAX    64

// =============================================================================
// DEVICE CATEGORIES
// =============================================================================
#define CAT_UNKNOWN   0x00
#define CAT_TRACKER   0x01
#define CAT_GLASSES   0x02
#define CAT_MEDICAL   0x04
#define CAT_WEARABLE  0x08
#define CAT_AUDIO     0x10
#define CAT_ALL       0xFF
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
// SIGNATURE FLAGS
// =============================================================================
#define SIG_FLAG_COMPANY_ID     0x0001
#define SIG_FLAG_PAYLOAD        0x0002
#define SIG_FLAG_SERVICE_UUID   0x0004
#define SIG_FLAG_NAME_PATTERN   0x0008
#define SIG_FLAG_EXACT_MATCH    0x0010
#define SIG_FLAG_TRANSMITTABLE  0x0020
#define SIG_FLAG_MEDICAL        0x0040

// =============================================================================
// BLUETOOTH SIG COMPANY IDENTIFIERS
// =============================================================================
#define COMPANY_APPLE           0x004C
#define COMPANY_SAMSUNG         0x0075
#define COMPANY_GOOGLE          0x00E0
#define COMPANY_AMAZON          0x0171
#define COMPANY_META            0x01AB
#define COMPANY_META_TECH       0x058E
#define COMPANY_SONY            0x012D
#define COMPANY_HUAWEI          0x027D
#define COMPANY_TILE            0xFEEC
#define COMPANY_TILE_ALT        0xFEED
#define COMPANY_CHIPOLO         0xFE65
#define COMPANY_PEBBLEBEE       0x0822
#define COMPANY_EUFY            0x0757
#define COMPANY_CUBE            0x0843
#define COMPANY_SNAP            0x03C2
#define COMPANY_LUXOTTICA       0x0D53
#define COMPANY_VUZIX           0x077A
#define COMPANY_XREAL           0x0A14
#define COMPANY_TCLTV           0x0992
#define COMPANY_BOSE            0x009E
#define COMPANY_JABRA           0x0067
#define COMPANY_PLANTRONICS     0x0055
#define COMPANY_JBL             0x0057
#define COMPANY_SKULLCANDY      0x02A0
#define COMPANY_BANG_OLUFSEN    0x0059
#define COMPANY_FITBIT          0x0224
#define COMPANY_GARMIN          0x0087
#define COMPANY_WHOOP           0x0643
#define COMPANY_OURA            0x0781
#define COMPANY_POLAR           0x006B
#define COMPANY_SUUNTO          0x0068
#define COMPANY_XIAOMI          0x038F
#define COMPANY_AMAZFIT         0x0157
#define COMPANY_DEXCOM          0x00D1
#define COMPANY_MEDTRONIC       0x02A5
#define COMPANY_ABBOTT          0x0618
#define COMPANY_INSULET         0x0822
#define COMPANY_TANDEM          0x0801
#define COMPANY_SENSEONICS      0x07E1
#define COMPANY_ASCENSIA        0x0702
#define COMPANY_ROCHE           0x0077
#define COMPANY_YPSOMED         0x08B4
#define COMPANY_BIGFOOT         0x093B
#define COMPANY_BETA_BIONICS    0x0964
#define COMPANY_LIFESCAN        0x03F0
#define COMPANY_BIOTRONIK       0x00A3
#define COMPANY_BOSTON_SCI      0x0149
#define COMPANY_ZOLL            0x0571
#define COMPANY_ALIVECOR        0x041B
#define COMPANY_RESMED          0x02B5
#define COMPANY_PHILIPS_MED     0x0030
#define COMPANY_WITHINGS        0x05E3
#define COMPANY_OMRON           0x020E
#define COMPANY_QARDIO          0x0415
#define COMPANY_IHEALTH         0x02C1

// =============================================================================
// SIGNATURE STRUCTURE
// =============================================================================
typedef struct {
    char name[32];
    uint8_t category;
    uint16_t company_id;
    uint8_t payload_pattern[8];
    uint8_t pattern_length;
    int8_t pattern_offset;
    uint16_t service_uuid;
    uint8_t threat_level;
    uint32_t flags;
} device_signature_t;

// =============================================================================
// BUILT-IN SIGNATURES
// =============================================================================
static const device_signature_t BUILTIN_SIGNATURES[] = {
    // Trackers
    {"AirTag (Registered)",     CAT_TRACKER, COMPANY_APPLE,    {0x4C,0x00,0x07,0x19,0,0,0,0}, 4,  0, 0, THREAT_SEVERE,   SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"AirTag (Unregistered)",   CAT_TRACKER, COMPANY_APPLE,    {0x4C,0x00,0x12,0x19,0,0,0,0}, 4,  0, 0, THREAT_SEVERE,   SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Samsung SmartTag",        CAT_TRACKER, COMPANY_SAMSUNG,  {0x75,0x00,0x42,0x09,0x01,0,0,0}, 5, 0, 0, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Samsung SmartTag2",       CAT_TRACKER, COMPANY_SAMSUNG,  {0x75,0x00,0x42,0x09,0x02,0,0,0}, 5, 0, 0, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Tile Tracker",            CAT_TRACKER, COMPANY_TILE,     {0xEC,0xFE,0,0,0,0,0,0}, 2, -1, 0, THREAT_SEVERE,         SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Tile (Alt)",              CAT_TRACKER, COMPANY_TILE_ALT, {0xED,0xFE,0,0,0,0,0,0}, 2, -1, 0, THREAT_SEVERE,         SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Chipolo",                 CAT_TRACKER, COMPANY_CHIPOLO,  {0x65,0xFE,0,0,0,0,0,0}, 2, -1, 0, THREAT_SEVERE,         SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Google Tracker",          CAT_TRACKER, COMPANY_GOOGLE,   {0,0,0,0,0,0,0,0}, 0, -1, 0xFE2C, THREAT_SEVERE,          SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_TRANSMITTABLE},
    {"Eufy Tracker",            CAT_TRACKER, COMPANY_EUFY,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_SEVERE,               SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Pebblebee",               CAT_TRACKER, COMPANY_PEBBLEBEE,{0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_SEVERE,               SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Cube Tracker",            CAT_TRACKER, COMPANY_CUBE,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_SEVERE,               SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    // Smart Glasses
    {"Meta Ray-Ban",            CAT_GLASSES, COMPANY_META,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Meta Ray-Ban (Tech)",     CAT_GLASSES, COMPANY_META_TECH, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Meta Ray-Ban (Luxottica)",CAT_GLASSES, COMPANY_LUXOTTICA, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Snap Spectacles",         CAT_GLASSES, COMPANY_SNAP,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Amazon Echo Frames",      CAT_GLASSES, COMPANY_AMAZON,    {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_HIGH,     SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Bose Frames",             CAT_GLASSES, COMPANY_BOSE,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_MEDIUM,   SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Vuzix Blade",             CAT_GLASSES, COMPANY_VUZIX,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"XREAL Air",               CAT_GLASSES, COMPANY_XREAL,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_HIGH,     SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"TCL RayNeo",              CAT_GLASSES, COMPANY_TCLTV,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_HIGH,     SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    // Medical - Diabetes
    {"Dexcom G6/G7",            CAT_MEDICAL, COMPANY_DEXCOM,    {0,0,0,0,0,0,0,0}, 0, -1, 0xFEBC, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Medtronic Pump",          CAT_MEDICAL, COMPANY_MEDTRONIC, {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Omnipod",                 CAT_MEDICAL, COMPANY_INSULET,   {0,0,0,0,0,0,0,0}, 0, -1, 0x1830, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Abbott FreeStyle",        CAT_MEDICAL, COMPANY_ABBOTT,    {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Tandem t:slim",           CAT_MEDICAL, COMPANY_TANDEM,    {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Senseonics Eversense",    CAT_MEDICAL, COMPANY_SENSEONICS,{0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Ascensia Contour",        CAT_MEDICAL, COMPANY_ASCENSIA,  {0,0,0,0,0,0,0,0}, 0, -1, 0x1808, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Roche Accu-Chek",         CAT_MEDICAL, COMPANY_ROCHE,     {0,0,0,0,0,0,0,0}, 0, -1, 0x1808, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Ypsomed mylife",          CAT_MEDICAL, COMPANY_YPSOMED,   {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Bigfoot Unity",           CAT_MEDICAL, COMPANY_BIGFOOT,   {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Beta Bionics iLet",       CAT_MEDICAL, COMPANY_BETA_BIONICS,{0,0,0,0,0,0,0,0}, 0, -1, 0,    THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"LifeScan OneTouch",       CAT_MEDICAL, COMPANY_LIFESCAN,  {0,0,0,0,0,0,0,0}, 0, -1, 0x1808, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    // Medical - Cardiac
    {"Biotronik Cardiac",       CAT_MEDICAL, COMPANY_BIOTRONIK, {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Boston Scientific",       CAT_MEDICAL, COMPANY_BOSTON_SCI,{0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"AliveCor Kardia",         CAT_MEDICAL, COMPANY_ALIVECOR,  {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Zoll LifeVest",           CAT_MEDICAL, COMPANY_ZOLL,      {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    // Medical - Respiratory/Other
    {"ResMed CPAP",             CAT_MEDICAL, COMPANY_RESMED,    {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Philips CPAP",            CAT_MEDICAL, COMPANY_PHILIPS_MED,{0,0,0,0,0,0,0,0}, 0, -1, 0,     THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Withings Health",         CAT_MEDICAL, COMPANY_WITHINGS,  {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Omron BP Monitor",        CAT_MEDICAL, COMPANY_OMRON,     {0,0,0,0,0,0,0,0}, 0, -1, 0x1810, THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Qardio Heart Health",     CAT_MEDICAL, COMPANY_QARDIO,    {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"iHealth Devices",         CAT_MEDICAL, COMPANY_IHEALTH,   {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    // Wearables
    {"Fitbit",                  CAT_WEARABLE, COMPANY_FITBIT,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Garmin Watch",            CAT_WEARABLE, COMPANY_GARMIN,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Whoop Band",              CAT_WEARABLE, COMPANY_WHOOP,    {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Oura Ring",               CAT_WEARABLE, COMPANY_OURA,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Polar Watch",             CAT_WEARABLE, COMPANY_POLAR,    {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Suunto Watch",            CAT_WEARABLE, COMPANY_SUUNTO,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Xiaomi Mi Band",          CAT_WEARABLE, COMPANY_XIAOMI,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Amazfit Watch",           CAT_WEARABLE, COMPANY_AMAZFIT,  {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Huawei Watch",            CAT_WEARABLE, COMPANY_HUAWEI,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    // Audio
    {"Sony Audio",              CAT_AUDIO, COMPANY_SONY,        {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Bose Audio",              CAT_AUDIO, COMPANY_BOSE,        {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Jabra Headset",           CAT_AUDIO, COMPANY_JABRA,       {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"JBL Audio",               CAT_AUDIO, COMPANY_JBL,         {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Plantronics",             CAT_AUDIO, COMPANY_PLANTRONICS, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Skullcandy",              CAT_AUDIO, COMPANY_SKULLCANDY,  {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Bang & Olufsen",          CAT_AUDIO, COMPANY_BANG_OLUFSEN,{0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
};

#define BUILTIN_SIGNATURE_COUNT (sizeof(BUILTIN_SIGNATURES) / sizeof(device_signature_t))

// =============================================================================
// TX SESSION STRUCTURE
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

// =============================================================================
// TX MANAGER CLASS
// =============================================================================
class TXManager {
public:
    TXManager();
    void init();
    int startTx(const char* deviceName, uint32_t intervalMs = TX_DEFAULT_INTERVAL_MS,
                int32_t count = -1, bool randomMac = true);
    int stopTx(const char* deviceName);
    void stopAll();
    int getActiveCount();
    tx_session_t* getSession(int index);
    tx_session_t* findSession(const char* deviceName);
    int confuseAdd(const char* deviceName, uint8_t instanceCount);
    int confuseRemove(const char* deviceName);
    void confuseClear();
    int confuseStart();
    void confuseStop();
    bool isConfusionActive() { return _confusionActive; }
    int getConfusionEntryCount();
    confusion_entry_t* getConfusionEntry(int index);
    int getTransmittableCount();
    const device_signature_t* getTransmittableSignature(int index);
    const device_signature_t* findSignatureByName(const char* name);
    void process();
    uint32_t getTotalPacketsSent() { return _totalPacketsSent; }

private:
    tx_session_t _sessions[TX_MAX_CONCURRENT];
    confusion_entry_t _confusionEntries[TX_CONFUSION_MAX_DEVICES];
    bool _confusionActive;
    uint32_t _totalPacketsSent;
    uint8_t _confusionIndex;
    void generateRandomMac(uint8_t* mac);
    bool buildAdvertisingData(const device_signature_t* sig, uint8_t* advData, uint8_t* advLen);
    void transmitPacket(tx_session_t* session);
    void transmitConfusionPacket();
    int findFreeSession();
};

// Global TX manager instance
TXManager txManager;

// =============================================================================
// TX MANAGER IMPLEMENTATION
// =============================================================================
TXManager::TXManager() {
    memset(_sessions, 0, sizeof(_sessions));
    memset(_confusionEntries, 0, sizeof(_confusionEntries));
    _confusionActive = false;
    _totalPacketsSent = 0;
    _confusionIndex = 0;
}

void TXManager::init() {
    Serial.println("[TX] TX Manager initialized");
}

int TXManager::getTransmittableCount() {
    int count = 0;
    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        if (BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) {
            count++;
        }
    }
    return count;
}

const device_signature_t* TXManager::getTransmittableSignature(int index) {
    int count = 0;
    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        if (BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) {
            if (count == index) {
                return &BUILTIN_SIGNATURES[i];
            }
            count++;
        }
    }
    return nullptr;
}

const device_signature_t* TXManager::findSignatureByName(const char* name) {
    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        if (strcasecmp(BUILTIN_SIGNATURES[i].name, name) == 0) {
            if (BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) {
                return &BUILTIN_SIGNATURES[i];
            }
        }
    }
    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        if (strcasestr(BUILTIN_SIGNATURES[i].name, name) != nullptr) {
            if (BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) {
                return &BUILTIN_SIGNATURES[i];
            }
        }
    }
    return nullptr;
}

int TXManager::findFreeSession() {
    for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
        if (!_sessions[i].active) {
            return i;
        }
    }
    return -1;
}

int TXManager::getActiveCount() {
    int count = 0;
    for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
        if (_sessions[i].active) {
            count++;
        }
    }
    return count;
}

tx_session_t* TXManager::getSession(int index) {
    if (index >= 0 && index < TX_MAX_CONCURRENT) {
        return &_sessions[index];
    }
    return nullptr;
}

tx_session_t* TXManager::findSession(const char* deviceName) {
    for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
        if (_sessions[i].active && strcasecmp(_sessions[i].deviceName, deviceName) == 0) {
            return &_sessions[i];
        }
    }
    return nullptr;
}

int TXManager::startTx(const char* deviceName, uint32_t intervalMs, int32_t count, bool randomMac) {
    const device_signature_t* sig = findSignatureByName(deviceName);
    if (sig == nullptr) {
        Serial.printf("[TX] Device not found: %s\n", deviceName);
        return -1;
    }
    tx_session_t* existing = findSession(deviceName);
    if (existing != nullptr) {
        return -2;
    }
    int slot = findFreeSession();
    if (slot < 0) {
        return -3;
    }
    tx_session_t* session = &_sessions[slot];
    strncpy(session->deviceName, sig->name, sizeof(session->deviceName) - 1);
    session->sig = sig;
    session->intervalMs = intervalMs;
    session->remainingCount = count;
    session->packetsSent = 0;
    session->lastTxTime = 0;
    session->randomMacPerPacket = randomMac;
    session->active = true;
    generateRandomMac(session->currentMac);
    Serial.printf("[TX] Started TX for %s (slot %d, interval %lums, count %ld)\n",
                  sig->name, slot, intervalMs, count);
    return slot;
}

int TXManager::stopTx(const char* deviceName) {
    tx_session_t* session = findSession(deviceName);
    if (session == nullptr) {
        return -1;
    }
    session->active = false;
    return 0;
}

void TXManager::stopAll() {
    for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
        _sessions[i].active = false;
    }
    _confusionActive = false;
}

int TXManager::getConfusionEntryCount() {
    int count = 0;
    for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
        if (_confusionEntries[i].enabled) {
            count++;
        }
    }
    return count;
}

confusion_entry_t* TXManager::getConfusionEntry(int index) {
    int count = 0;
    for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
        if (_confusionEntries[i].enabled) {
            if (count == index) {
                return &_confusionEntries[i];
            }
            count++;
        }
    }
    return nullptr;
}

int TXManager::confuseAdd(const char* deviceName, uint8_t instanceCount) {
    const device_signature_t* sig = findSignatureByName(deviceName);
    if (sig == nullptr) {
        return -1;
    }
    for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
        if (_confusionEntries[i].enabled &&
            strcasecmp(_confusionEntries[i].deviceName, sig->name) == 0) {
            _confusionEntries[i].instanceCount = instanceCount;
            return i;
        }
    }
    for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
        if (!_confusionEntries[i].enabled) {
            strncpy(_confusionEntries[i].deviceName, sig->name,
                    sizeof(_confusionEntries[i].deviceName) - 1);
            _confusionEntries[i].sig = sig;
            _confusionEntries[i].instanceCount = instanceCount;
            _confusionEntries[i].enabled = true;
            return i;
        }
    }
    return -2;
}

int TXManager::confuseRemove(const char* deviceName) {
    for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
        if (_confusionEntries[i].enabled &&
            strcasecmp(_confusionEntries[i].deviceName, deviceName) == 0) {
            _confusionEntries[i].enabled = false;
            return 0;
        }
    }
    return -1;
}

void TXManager::confuseClear() {
    for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
        _confusionEntries[i].enabled = false;
    }
    _confusionActive = false;
}

int TXManager::confuseStart() {
    int entryCount = getConfusionEntryCount();
    if (entryCount == 0) {
        return -1;
    }
    _confusionActive = true;
    _confusionIndex = 0;
    return entryCount;
}

void TXManager::confuseStop() {
    _confusionActive = false;
}

void TXManager::generateRandomMac(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = esp_random() & 0xFF;
    }
    mac[0] |= 0x02;
    mac[0] &= 0xFE;
}

bool TXManager::buildAdvertisingData(const device_signature_t* sig, uint8_t* advData, uint8_t* advLen) {
    uint8_t pos = 0;
    advData[pos++] = 0x02;
    advData[pos++] = 0x01;
    advData[pos++] = 0x06;
    if (sig->company_id != 0) {
        uint8_t mfgDataLen = 2;
        if (sig->pattern_length > 0 && sig->pattern_offset == 0) {
            mfgDataLen = sig->pattern_length;
            advData[pos++] = mfgDataLen + 1;
            advData[pos++] = 0xFF;
            memcpy(&advData[pos], sig->payload_pattern, sig->pattern_length);
            pos += sig->pattern_length;
        } else {
            uint8_t extraBytes = 4;
            mfgDataLen = 2 + extraBytes;
            advData[pos++] = mfgDataLen + 1;
            advData[pos++] = 0xFF;
            advData[pos++] = sig->company_id & 0xFF;
            advData[pos++] = (sig->company_id >> 8) & 0xFF;
            if (sig->pattern_length > 0 && sig->pattern_length <= extraBytes) {
                memcpy(&advData[pos], sig->payload_pattern, sig->pattern_length);
                pos += sig->pattern_length;
                for (int i = sig->pattern_length; i < extraBytes; i++) {
                    advData[pos++] = esp_random() & 0xFF;
                }
            } else {
                for (int i = 0; i < extraBytes; i++) {
                    advData[pos++] = esp_random() & 0xFF;
                }
            }
        }
    }
    if (sig->service_uuid != 0) {
        advData[pos++] = 0x03;
        advData[pos++] = 0x03;
        advData[pos++] = sig->service_uuid & 0xFF;
        advData[pos++] = (sig->service_uuid >> 8) & 0xFF;
    }
    *advLen = pos;
    return pos > 0;
}

void TXManager::transmitPacket(tx_session_t* session) {
    if (!session->active || session->sig == nullptr) {
        return;
    }
    uint8_t advData[31];
    uint8_t advLen = 0;
    if (!buildAdvertisingData(session->sig, advData, &advLen)) {
        return;
    }
    if (session->randomMacPerPacket) {
        generateRandomMac(session->currentMac);
    }
    esp_err_t err = esp_ble_gap_set_rand_addr(session->currentMac);
    if (err != ESP_OK) {
        return;
    }
    esp_ble_adv_params_t advParams = {
        .adv_int_min = 0x20,
        .adv_int_max = 0x20,
        .adv_type = ADV_TYPE_NONCONN_IND,
        .own_addr_type = BLE_ADDR_TYPE_RANDOM,
        .peer_addr = {0},
        .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
        .channel_map = ADV_CHNL_ALL,
        .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    };
    esp_ble_gap_config_adv_data_raw(advData, advLen);
    delay(10);
    esp_ble_gap_start_advertising(&advParams);
    delay(30);
    esp_ble_gap_stop_advertising();
    delay(5);
    session->packetsSent++;
    session->lastTxTime = millis();
    _totalPacketsSent++;
    if (session->remainingCount > 0) {
        session->remainingCount--;
        if (session->remainingCount == 0) {
            session->active = false;
        }
    }
}

void TXManager::transmitConfusionPacket() {
    if (!_confusionActive) {
        return;
    }
    int startIndex = _confusionIndex;
    do {
        if (_confusionEntries[_confusionIndex].enabled) {
            confusion_entry_t* entry = &_confusionEntries[_confusionIndex];
            uint8_t advData[31];
            uint8_t advLen = 0;
            if (buildAdvertisingData(entry->sig, advData, &advLen)) {
                uint8_t mac[6];
                generateRandomMac(mac);
                esp_ble_gap_set_rand_addr(mac);
                esp_ble_adv_params_t advParams = {
                    .adv_int_min = 0x20,
                    .adv_int_max = 0x20,
                    .adv_type = ADV_TYPE_NONCONN_IND,
                    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
                    .peer_addr = {0},
                    .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
                    .channel_map = ADV_CHNL_ALL,
                    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
                };
                esp_ble_gap_config_adv_data_raw(advData, advLen);
                delay(5);
                esp_ble_gap_start_advertising(&advParams);
                delay(25);
                esp_ble_gap_stop_advertising();
                delay(5);
                _totalPacketsSent++;
            }
            _confusionIndex = (_confusionIndex + 1) % TX_CONFUSION_MAX_DEVICES;
            return;
        }
        _confusionIndex = (_confusionIndex + 1) % TX_CONFUSION_MAX_DEVICES;
    } while (_confusionIndex != startIndex);
}

void TXManager::process() {
    uint32_t now = millis();
    for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
        tx_session_t* session = &_sessions[i];
        if (session->active) {
            if (now - session->lastTxTime >= session->intervalMs) {
                transmitPacket(session);
            }
        }
    }
    if (_confusionActive) {
        static uint32_t lastConfuseTime = 0;
        if (now - lastConfuseTime >= 20) {
            transmitConfusionPacket();
            lastConfuseTime = now;
        }
    }
}

// =============================================================================
// GLOBAL OBJECTS
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
bool jsonOutput = SERIAL_JSON_OUTPUT;

// TX screen layout constants
#define TX_LIST_START_Y     (STATUS_BAR_HEIGHT + 40)
#define TX_ITEM_HEIGHT      18
#define TX_ITEMS_PER_PAGE   8
#define TX_STOP_BTN_X       220
#define TX_STOP_BTN_Y       (STATUS_BAR_HEIGHT + 4)
#define TX_STOP_BTN_W       90
#define TX_STOP_BTN_H       28

static int txScrollOffset = 0;

// Touch calibration
#define TOUCH_X_MIN     300
#define TOUCH_X_MAX     3650
#define TOUCH_Y_MIN     400
#define TOUCH_Y_MAX     3750

// =============================================================================
// FORWARD DECLARATIONS
// =============================================================================
void initDisplay();
void initBLE();
void initSerial();
void drawStatusBar();
void drawNavBar();
void drawScanScreen();
void drawFilterScreen();
void drawTXScreen();
void drawSettingsScreen();
void drawDetailScreen();
void processSerialCommand(const char* cmd);
void outputDetection(const DetectedDevice* device);
const device_signature_t* matchSignature(BLEAdvertisedDevice* device);
void outputTxEvent(const char* event, const char* device, uint32_t intervalMs, int32_t count, uint32_t sent);
const char* getCategoryString(uint8_t category);
void initTouch();
void handleTouch();

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================
const char* getCategoryString(uint8_t category) {
    switch (category) {
        case CAT_TRACKER:  return "TRACKER";
        case CAT_GLASSES:  return "GLASSES";
        case CAT_MEDICAL:  return "MEDICAL";
        case CAT_WEARABLE: return "WEARABLE";
        case CAT_AUDIO:    return "AUDIO";
        default:           return "UNKNOWN";
    }
}

// =============================================================================
// SIGNATURE MATCHING
// =============================================================================
const device_signature_t* matchSignature(BLEAdvertisedDevice* device) {
    uint8_t* payload = device->getPayload();
    size_t payloadLen = device->getPayloadLength();
    uint16_t mfgCompanyId = 0;
    bool hasMfgData = false;
    size_t idx = 0;
    while (idx < payloadLen) {
        uint8_t len = payload[idx];
        if (len == 0 || idx + len >= payloadLen) break;
        uint8_t type = payload[idx + 1];
        if (type == 0xFF && len >= 3) {
            mfgCompanyId = payload[idx + 2] | (payload[idx + 3] << 8);
            hasMfgData = true;
            break;
        }
        idx += len + 1;
    }
    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        const device_signature_t* sig = &BUILTIN_SIGNATURES[i];
        bool matched = false;
        if ((sig->flags & SIG_FLAG_COMPANY_ID) && hasMfgData) {
            if (sig->company_id == mfgCompanyId) {
                matched = true;
            }
        }
        if ((sig->flags & SIG_FLAG_PAYLOAD) && sig->pattern_length > 0) {
            bool patternFound = false;
            if (sig->pattern_offset >= 0) {
                if ((size_t)(sig->pattern_offset + sig->pattern_length) <= payloadLen) {
                    if (memcmp(payload + sig->pattern_offset, sig->payload_pattern, sig->pattern_length) == 0) {
                        patternFound = true;
                    }
                }
            } else {
                for (size_t j = 0; j + sig->pattern_length <= payloadLen; j++) {
                    if (memcmp(payload + j, sig->payload_pattern, sig->pattern_length) == 0) {
                        patternFound = true;
                        break;
                    }
                }
            }
            if (sig->flags & SIG_FLAG_EXACT_MATCH) {
                matched = matched && patternFound;
            } else {
                matched = matched || patternFound;
            }
        }
        if (matched) {
            return sig;
        }
    }
    return nullptr;
}

// =============================================================================
// BLE SCAN CALLBACK
// =============================================================================
class ScanCallbacks : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) override {
        const device_signature_t* sig = matchSignature(&advertisedDevice);
        if (sig != nullptr) {
            if (!(sig->category & categoryFilter)) {
                return;
            }
            if (advertisedDevice.getRSSI() < rssiThreshold) {
                return;
            }
            uint8_t mac[6];
            memcpy(mac, advertisedDevice.getAddress().getNative(), 6);
            int existingIdx = -1;
            for (int i = 0; i < detectedCount; i++) {
                if (memcmp(detectedDevices[i].mac, mac, 6) == 0) {
                    existingIdx = i;
                    break;
                }
            }
            if (existingIdx >= 0) {
                detectedDevices[existingIdx].rssi = advertisedDevice.getRSSI();
                detectedDevices[existingIdx].lastSeen = millis();
                detectedDevices[existingIdx].detectionCount++;
                detectedDevices[existingIdx].active = true;
            } else if (detectedCount < DETECTED_DEVICES_MAX) {
                DetectedDevice* dev = &detectedDevices[detectedCount];
                strncpy(dev->name, sig->name, sizeof(dev->name) - 1);
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
                outputDetection(dev);
            }
        }
    }
};

// =============================================================================
// SERIAL OUTPUT
// =============================================================================
void outputDetection(const DetectedDevice* device) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             device->mac[0], device->mac[1], device->mac[2],
             device->mac[3], device->mac[4], device->mac[5]);
    const char* catStr = getCategoryString(device->category);
    if (jsonOutput) {
        Serial.printf("{\"event\":\"detect\",\"ts\":%lu,\"device\":\"%s\","
                      "\"mac\":\"%s\",\"rssi\":%d,\"category\":\"%s\","
                      "\"company_id\":\"0x%04X\"}\n",
                      millis(), device->name, macStr, device->rssi, catStr, device->companyId);
    } else {
        Serial.printf("[%lu] DETECT %s MAC=%s RSSI=%d CAT=%s\n",
                      millis(), device->name, macStr, device->rssi, catStr);
    }
}

void outputTxEvent(const char* event, const char* device, uint32_t intervalMs, int32_t count, uint32_t sent) {
    if (jsonOutput) {
        if (strcmp(event, "tx_start") == 0) {
            Serial.printf("{\"event\":\"%s\",\"ts\":%lu,\"device\":\"%s\",\"interval_ms\":%lu,\"count\":%ld}\n",
                          event, millis(), device, intervalMs, count);
        } else if (strcmp(event, "tx_stop") == 0) {
            Serial.printf("{\"event\":\"%s\",\"ts\":%lu,\"device\":\"%s\",\"packets_sent\":%lu}\n",
                          event, millis(), device, sent);
        } else {
            Serial.printf("{\"event\":\"%s\",\"ts\":%lu,\"device\":\"%s\"}\n", event, millis(), device);
        }
    } else {
        if (strcmp(event, "tx_start") == 0) {
            Serial.printf("[%lu] TX_START device=%s interval=%lums count=%ld\n", millis(), device, intervalMs, count);
        } else if (strcmp(event, "tx_stop") == 0) {
            Serial.printf("[%lu] TX_STOP device=%s sent=%lu\n", millis(), device, sent);
        } else {
            Serial.printf("[%lu] %s device=%s\n", millis(), event, device);
        }
    }
}

// =============================================================================
// SERIAL COMMAND PROCESSING
// =============================================================================
void processSerialCommand(const char* cmd) {
    String origCmd = String(cmd);
    origCmd.trim();
    String cmdStr = origCmd;
    cmdStr.toUpperCase();

    if (cmdStr == "HELP") {
        Serial.println("BLEPTD Commands:");
        Serial.println("  HELP, VERSION, STATUS");
        Serial.println("  SCAN START/STOP/CLEAR/LIST");
        Serial.println("  TX LIST/START <device>/STOP <device|ALL>/STATUS");
        Serial.println("  CONFUSE ADD/REMOVE/LIST/START/STOP/CLEAR");
        Serial.println("  JSON ON|OFF");
        Serial.println("OK");
    }
    else if (cmdStr == "VERSION") {
        Serial.printf("BLEPTD v%s\n", BLEPTD_VERSION);
        Serial.println("OK");
    }
    else if (cmdStr == "STATUS") {
        Serial.printf("Scanning: %s\n", scanning ? "ON" : "OFF");
        Serial.printf("TX Sessions: %d active\n", txManager.getActiveCount());
        Serial.printf("Confusion: %s (%d entries)\n",
                      txManager.isConfusionActive() ? "ON" : "OFF",
                      txManager.getConfusionEntryCount());
        Serial.printf("Total TX Packets: %lu\n", txManager.getTotalPacketsSent());
        Serial.printf("Detected: %d devices\n", detectedCount);
        Serial.println("OK");
    }
    else if (cmdStr == "SCAN START") {
        scanning = true;
        Serial.println("OK Scanning started");
    }
    else if (cmdStr == "SCAN STOP") {
        scanning = false;
        pBLEScan->stop();
        Serial.println("OK Scanning stopped");
    }
    else if (cmdStr == "SCAN CLEAR") {
        detectedCount = 0;
        memset(detectedDevices, 0, sizeof(detectedDevices));
        Serial.println("OK Devices cleared");
    }
    else if (cmdStr == "SCAN LIST") {
        for (int i = 0; i < detectedCount; i++) {
            outputDetection(&detectedDevices[i]);
        }
        Serial.printf("Total: %d devices\n", detectedCount);
        Serial.println("OK");
    }
    else if (cmdStr == "TX LIST") {
        Serial.println("Transmittable Devices:");
        int count = txManager.getTransmittableCount();
        for (int i = 0; i < count; i++) {
            const device_signature_t* sig = txManager.getTransmittableSignature(i);
            if (sig) {
                Serial.printf("  [%d] %s (0x%04X)\n", i, sig->name, sig->company_id);
            }
        }
        Serial.printf("Total: %d devices\n", count);
        Serial.println("OK");
    }
    else if (cmdStr.startsWith("TX START ")) {
        String deviceName = origCmd.substring(9);
        deviceName.trim();
        if (scanning) {
            pBLEScan->stop();
            delay(50);
        }
        int result = txManager.startTx(deviceName.c_str(), TX_DEFAULT_INTERVAL_MS, -1, false);
        if (result >= 0) {
            txActive = true;
            outputTxEvent("tx_start", deviceName.c_str(), TX_DEFAULT_INTERVAL_MS, -1, 0);
            Serial.println("OK TX started");
        } else {
            Serial.printf("ERROR Device not found: %s\n", deviceName.c_str());
        }
    }
    else if (cmdStr.startsWith("TX STOP ")) {
        String deviceName = origCmd.substring(8);
        deviceName.trim();
        if (deviceName.equalsIgnoreCase("ALL")) {
            txManager.stopAll();
            txActive = false;
            Serial.println("OK All TX stopped");
        } else {
            int result = txManager.stopTx(deviceName.c_str());
            if (result == 0) {
                txActive = txManager.getActiveCount() > 0;
                Serial.println("OK TX stopped");
            } else {
                Serial.println("ERROR Device not transmitting");
            }
        }
    }
    else if (cmdStr == "TX STATUS") {
        Serial.println("Active TX Sessions:");
        int activeCount = 0;
        for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
            tx_session_t* session = txManager.getSession(i);
            if (session && session->active) {
                Serial.printf("  [%d] %s - %lu pkts\n", i, session->deviceName, session->packetsSent);
                activeCount++;
            }
        }
        if (activeCount == 0) Serial.println("  (none)");
        Serial.println("OK");
    }
    else if (cmdStr.startsWith("CONFUSE ADD ")) {
        String deviceName = origCmd.substring(12);
        deviceName.trim();
        int result = txManager.confuseAdd(deviceName.c_str(), 1);
        if (result >= 0) {
            Serial.printf("OK Added %s to confusion list\n", deviceName.c_str());
        } else {
            Serial.printf("ERROR Device not found: %s\n", deviceName.c_str());
        }
    }
    else if (cmdStr == "CONFUSE LIST") {
        Serial.println("Confusion Entries:");
        int count = txManager.getConfusionEntryCount();
        for (int i = 0; i < count; i++) {
            confusion_entry_t* entry = txManager.getConfusionEntry(i);
            if (entry) {
                Serial.printf("  [%d] %s\n", i, entry->deviceName);
            }
        }
        Serial.printf("Total: %d entries\n", count);
        Serial.println("OK");
    }
    else if (cmdStr == "CONFUSE START") {
        if (scanning) {
            pBLEScan->stop();
            delay(50);
        }
        int result = txManager.confuseStart();
        if (result > 0) {
            txActive = true;
            Serial.printf("OK Confusion started with %d entries\n", result);
        } else {
            Serial.println("ERROR No confusion entries");
        }
    }
    else if (cmdStr == "CONFUSE STOP") {
        txManager.confuseStop();
        txActive = txManager.getActiveCount() > 0;
        Serial.println("OK Confusion stopped");
    }
    else if (cmdStr == "CONFUSE CLEAR") {
        txManager.confuseClear();
        txActive = txManager.getActiveCount() > 0;
        Serial.println("OK Confusion cleared");
    }
    else if (cmdStr == "JSON ON") {
        jsonOutput = true;
        Serial.println("OK JSON enabled");
    }
    else if (cmdStr == "JSON OFF") {
        jsonOutput = false;
        Serial.println("OK JSON disabled");
    }
    else {
        Serial.printf("ERROR Unknown command: %s\n", cmd);
    }
}

// =============================================================================
// DISPLAY FUNCTIONS
// =============================================================================
void initDisplay() {
    tft.init();
    tft.setRotation(SCREEN_ROTATION);
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextFont(1);
    pinMode(TFT_BL_PIN, OUTPUT);
    digitalWrite(TFT_BL_PIN, HIGH);
    drawStatusBar();
    drawNavBar();
}

void drawStatusBar() {
    tft.fillRect(0, 0, SCREEN_WIDTH, STATUS_BAR_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(1);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString("BLEPTD v" BLEPTD_VERSION, 4, 6, 1);
    String modeStr;
    uint16_t modeColor = TFT_WHITE;
    if (txManager.isConfusionActive()) {
        modeStr = "CONFUSE";
        modeColor = TFT_RED;
    } else if (txManager.getActiveCount() > 0) {
        modeStr = "TX:" + String(txManager.getActiveCount());
        modeColor = TFT_YELLOW;
    } else if (scanning) {
        modeStr = "SCANNING";
        modeColor = TFT_GREEN;
    } else {
        modeStr = "IDLE";
    }
    tft.setTextDatum(TR_DATUM);
    tft.setTextColor(modeColor, TFT_BLACK);
    tft.drawString(modeStr, SCREEN_WIDTH - 4, 6, 1);
}

void drawNavBar() {
    int y = SCREEN_HEIGHT - NAV_BAR_HEIGHT;
    tft.fillRect(0, y, SCREEN_WIDTH, NAV_BAR_HEIGHT, TFT_DARKGREY);
    const char* tabs[] = {"SCAN", "FILTER", "TX", "SETUP"};
    int tabWidth = SCREEN_WIDTH / 4;
    for (int i = 0; i < 4; i++) {
        int x = i * tabWidth;
        uint16_t color = (i == currentScreen) ? TFT_YELLOW : TFT_WHITE;
        tft.setTextColor(color, TFT_DARKGREY);
        tft.setTextDatum(MC_DATUM);
        tft.drawString(tabs[i], x + tabWidth / 2, y + NAV_BAR_HEIGHT / 2, 2);
    }
}

void drawScanScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    int filteredCount = 0;
    for (int i = 0; i < detectedCount; i++) {
        if (detectedDevices[i].category & categoryFilter) {
            filteredCount++;
        }
    }
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(2);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString("DETECTED DEVICES", 4, y, 2);
    char countStr[24];
    if (filteredCount > ITEMS_PER_PAGE) {
        snprintf(countStr, sizeof(countStr), "[%d-%d/%d]",
                 scrollOffset + 1, min(scrollOffset + ITEMS_PER_PAGE, filteredCount), filteredCount);
    } else {
        snprintf(countStr, sizeof(countStr), "[%d]", filteredCount);
    }
    tft.setTextDatum(TR_DATUM);
    tft.drawString(countStr, SCREEN_WIDTH - 4, y, 2);
    y += 20;
    tft.setTextFont(1);
    int displayed = 0;
    int skipped = 0;
    for (int deviceIdx = 0; deviceIdx < detectedCount && displayed < ITEMS_PER_PAGE; deviceIdx++) {
        DetectedDevice* dev = &detectedDevices[deviceIdx];
        if (!(dev->category & categoryFilter)) continue;
        if (skipped < scrollOffset) {
            skipped++;
            continue;
        }
        uint16_t catColor = TFT_WHITE;
        switch (dev->category) {
            case CAT_TRACKER:  catColor = TFT_RED;     break;
            case CAT_GLASSES:  catColor = TFT_ORANGE;  break;
            case CAT_MEDICAL:  catColor = TFT_YELLOW;  break;
            case CAT_WEARABLE: catColor = TFT_BLUE;    break;
            case CAT_AUDIO:    catColor = TFT_MAGENTA; break;
        }
        tft.fillCircle(SCREEN_WIDTH - 10, y + 7, 4, catColor);
        tft.setTextDatum(TL_DATUM);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        char nameWithMac[48];
        snprintf(nameWithMac, sizeof(nameWithMac), "%s %02X:%02X:%02X",
                 dev->name, dev->mac[3], dev->mac[4], dev->mac[5]);
        tft.drawString(nameWithMac, 4, y, 1);
        char rssiStr[16];
        snprintf(rssiStr, sizeof(rssiStr), "%d", dev->rssi);
        tft.setTextColor(TFT_YELLOW, TFT_BLACK);
        tft.drawString(rssiStr, 260, y, 1);
        y += ITEM_HEIGHT;
        displayed++;
    }
    if (filteredCount == 0) {
        tft.setTextDatum(MC_DATUM);
        tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
        tft.drawString("Scanning for devices...", SCREEN_WIDTH/2, SCREEN_HEIGHT/2, 2);
    }
}

void drawTXScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    int activeCount = txManager.getActiveCount();
    bool confusionActive = txManager.isConfusionActive();

    if (confusionActive) {
        tft.setTextColor(TFT_RED);
        tft.drawString("CONFUSION MODE", 4, y);
        tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_RED);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("STOP", TX_STOP_BTN_X + TX_STOP_BTN_W/2, TX_STOP_BTN_Y + TX_STOP_BTN_H/2, 2);
        tft.setTextDatum(TL_DATUM);
        y += 22;
        tft.setTextColor(TFT_WHITE);
        char statsStr[40];
        snprintf(statsStr, sizeof(statsStr), "Devices: %d  Pkts: %lu",
                 txManager.getConfusionEntryCount(), txManager.getTotalPacketsSent());
        tft.drawString(statsStr, 4, y);
    } else if (activeCount > 0) {
        tft.setTextColor(TFT_YELLOW);
        tft.drawString("TRANSMITTING", 4, y);
        tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_RED);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("STOP", TX_STOP_BTN_X + TX_STOP_BTN_W/2, TX_STOP_BTN_Y + TX_STOP_BTN_H/2, 2);
        tft.setTextDatum(TL_DATUM);
        y += 22;
        for (int i = 0; i < TX_MAX_CONCURRENT && y < SCREEN_HEIGHT - NAV_BAR_HEIGHT - 10; i++) {
            tx_session_t* session = txManager.getSession(i);
            if (session && session->active && session->sig) {
                tft.setTextColor(TFT_YELLOW);
                tft.drawString(session->deviceName, 20, y);
                y += 16;
                char macStr[24];
                snprintf(macStr, sizeof(macStr), "MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                         session->currentMac[0], session->currentMac[1], session->currentMac[2],
                         session->currentMac[3], session->currentMac[4], session->currentMac[5]);
                tft.setTextColor(TFT_WHITE);
                tft.drawString(macStr, 20, y);
                y += 14;
                char statsStr[32];
                snprintf(statsStr, sizeof(statsStr), "Packets: %lu", session->packetsSent);
                tft.setTextColor(TFT_GREEN);
                tft.drawString(statsStr, 20, y);
                y += 18;
            }
        }
    } else {
        tft.drawString("TAP TO TX", 4, y);
        tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_MAGENTA);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("CONFUSE", TX_STOP_BTN_X + TX_STOP_BTN_W/2, TX_STOP_BTN_Y + TX_STOP_BTN_H/2, 2);
        tft.setTextDatum(TL_DATUM);
        y = TX_LIST_START_Y;
        int txCount = txManager.getTransmittableCount();
        tft.setTextColor(TFT_WHITE);
        int displayed = 0;
        for (int i = txScrollOffset; i < txCount && displayed < TX_ITEMS_PER_PAGE; i++) {
            const device_signature_t* sig = txManager.getTransmittableSignature(i);
            if (sig) {
                uint16_t catColor = TFT_WHITE;
                switch (sig->category) {
                    case CAT_TRACKER:  catColor = TFT_RED;     break;
                    case CAT_GLASSES:  catColor = TFT_ORANGE;  break;
                }
                tft.fillCircle(12, y + 7, 5, catColor);
                tft.setTextColor(TFT_WHITE);
                tft.drawString(sig->name, 24, y);
                y += TX_ITEM_HEIGHT;
                displayed++;
            }
        }
    }
}

void drawFilterScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("DEVICE CATEGORIES", 4, y);
    y += 20;
    struct CatEntry { uint8_t cat; const char* name; uint16_t color; };
    CatEntry categories[] = {
        {CAT_TRACKER, "TRACKER - Tracking devices", TFT_RED},
        {CAT_GLASSES, "GLASSES - Smart glasses", TFT_ORANGE},
        {CAT_MEDICAL, "MEDICAL - Medical devices", TFT_YELLOW},
        {CAT_WEARABLE, "WEARABLE - Smartwatches", TFT_BLUE},
        {CAT_AUDIO, "AUDIO - Earbuds/headphones", TFT_MAGENTA},
    };
    for (int i = 0; i < 5; i++) {
        bool enabled = (categoryFilter & categories[i].cat) != 0;
        tft.drawRect(8, y, 14, 14, categories[i].color);
        if (enabled) {
            tft.fillRect(10, y + 2, 10, 10, categories[i].color);
        }
        tft.setTextColor(enabled ? TFT_WHITE : TFT_DARKGREY);
        tft.drawString(categories[i].name, 28, y + 2);
        y += 22;
    }
}

void drawSettingsScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("SETTINGS", 4, y);
    y += 20;
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Serial Baud:", 4, y);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("115200", 140, y);
    y += 18;
    tft.setTextColor(TFT_WHITE);
    tft.drawString("STATISTICS", 4, y);
    y += 18;
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Devices:", 4, y);
    char val[16];
    snprintf(val, sizeof(val), "%d", detectedCount);
    tft.setTextColor(TFT_WHITE);
    tft.drawString(val, 140, y);
    y += 18;
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("TX Packets:", 4, y);
    snprintf(val, sizeof(val), "%lu", txManager.getTotalPacketsSent());
    tft.setTextColor(TFT_WHITE);
    tft.drawString(val, 140, y);
}

void drawDetailScreen() {
    if (selectedDeviceIdx < 0 || selectedDeviceIdx >= detectedCount) {
        currentScreen = 0;
        drawScanScreen();
        return;
    }
    DetectedDevice* dev = &detectedDevices[selectedDeviceIdx];
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);
    int y = STATUS_BAR_HEIGHT + 4;
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString("DEVICE DETAIL", 4, y, 2);
    tft.setTextDatum(TR_DATUM);
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.drawString("[X]", SCREEN_WIDTH - 4, y, 2);
    y += 22;
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.drawString(dev->name, 4, y, 2);
    y += 20;
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             dev->mac[0], dev->mac[1], dev->mac[2],
             dev->mac[3], dev->mac[4], dev->mac[5]);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("MAC:", 4, y, 1);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(macStr, 80, y, 1);
    y += 14;
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("RSSI:", 4, y, 1);
    char rssiStr[16];
    snprintf(rssiStr, sizeof(rssiStr), "%d dBm", dev->rssi);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(rssiStr, 80, y, 1);
    tft.fillRect(0, SCREEN_HEIGHT - NAV_BAR_HEIGHT, SCREEN_WIDTH, NAV_BAR_HEIGHT, TFT_DARKGREY);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
    tft.drawString("Tap to return", SCREEN_WIDTH / 2, SCREEN_HEIGHT - NAV_BAR_HEIGHT / 2, 1);
}

// =============================================================================
// INITIALIZATION
// =============================================================================
void initBLE() {
    BLEDevice::init("BLEPTD");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new ScanCallbacks(), true);
    pBLEScan->setActiveScan(BLE_ACTIVE_SCAN);
    pBLEScan->setInterval(BLE_SCAN_INTERVAL_MS);
    pBLEScan->setWindow(BLE_SCAN_WINDOW_MS);
    txManager.init();
}

void initSerial() {
    Serial.begin(SERIAL_BAUD_RATE);
    Serial.println();
    Serial.println("=================================");
    Serial.printf("BLEPTD v%s\n", BLEPTD_VERSION);
    Serial.println("BLE Privacy Threat Detector");
    Serial.println("=================================");
    Serial.println("Type HELP for commands");
}

void initTouch() {
    pinMode(XPT2046_CS, OUTPUT);
    digitalWrite(XPT2046_CS, HIGH);
    touchSpi.begin(XPT2046_CLK, XPT2046_MISO, XPT2046_MOSI, XPT2046_CS);
    touchSpi.setFrequency(1000000);
    ts.begin(touchSpi);
    ts.setRotation(0);
    Serial.println("Touch initialized");
}

// =============================================================================
// TOUCH HANDLING
// =============================================================================
void handleTouch() {
    static uint32_t lastTouchTime = 0;
    const uint32_t TOUCH_DEBOUNCE_MS = 250;
    TS_Point p = ts.getPoint();
    if (p.z < 100) return;
    if (millis() - lastTouchTime < TOUCH_DEBOUNCE_MS) return;
    int16_t touchX = map(p.y, TOUCH_Y_MIN, TOUCH_Y_MAX, 0, SCREEN_WIDTH);
    int16_t touchY = map(p.x, TOUCH_X_MAX, TOUCH_X_MIN, 0, SCREEN_HEIGHT);
    touchX = constrain(touchX, 0, SCREEN_WIDTH - 1);
    touchY = constrain(touchY, 0, SCREEN_HEIGHT - 1);
    lastTouchTime = millis();

    if (currentScreen == 4) {
        currentScreen = 0;
        drawScanScreen();
        drawNavBar();
        return;
    }

    if (touchY >= SCREEN_HEIGHT - NAV_BAR_HEIGHT) {
        int tabWidth = SCREEN_WIDTH / 4;
        int newScreen = touchX / tabWidth;
        if (newScreen >= 0 && newScreen <= 3 && newScreen != currentScreen) {
            currentScreen = newScreen;
            scrollOffset = 0;
            drawNavBar();
            switch (currentScreen) {
                case 0: drawScanScreen(); break;
                case 1: drawFilterScreen(); break;
                case 2: drawTXScreen(); break;
                case 3: drawSettingsScreen(); break;
            }
        }
    }
    else if (currentScreen == 0 && touchY > STATUS_BAR_HEIGHT && detectedCount > 0) {
        int filteredCount = 0;
        for (int i = 0; i < detectedCount; i++) {
            if (detectedDevices[i].category & categoryFilter) filteredCount++;
        }
        int listStartY = STATUS_BAR_HEIGHT + 24;
        int listEndY = SCREEN_HEIGHT - NAV_BAR_HEIGHT;
        if (touchY < listStartY + 30 && scrollOffset > 0) {
            scrollOffset = max(0, scrollOffset - ITEMS_PER_PAGE);
            drawScanScreen();
        } else if (touchY > listEndY - 30 && scrollOffset + ITEMS_PER_PAGE < filteredCount) {
            scrollOffset = min(filteredCount - ITEMS_PER_PAGE, scrollOffset + ITEMS_PER_PAGE);
            if (scrollOffset < 0) scrollOffset = 0;
            drawScanScreen();
        } else if (touchY >= listStartY && touchY < listEndY - 10 && filteredCount > 0) {
            int itemIdx = (touchY - listStartY) / ITEM_HEIGHT;
            int targetFilteredIdx = scrollOffset + itemIdx;
            int filteredIdx = 0;
            for (int i = 0; i < detectedCount; i++) {
                if (detectedDevices[i].category & categoryFilter) {
                    if (filteredIdx == targetFilteredIdx) {
                        selectedDeviceIdx = i;
                        currentScreen = 4;
                        drawDetailScreen();
                        break;
                    }
                    filteredIdx++;
                }
            }
        }
    }
    else if (currentScreen == 1 && touchY > STATUS_BAR_HEIGHT + 24) {
        int filterY = STATUS_BAR_HEIGHT + 24;
        int categoryIdx = (touchY - filterY) / 22;
        if (categoryIdx >= 0 && categoryIdx < 5 && touchX < 180) {
            uint8_t categories[] = {CAT_TRACKER, CAT_GLASSES, CAT_MEDICAL, CAT_WEARABLE, CAT_AUDIO};
            categoryFilter ^= categories[categoryIdx];
            scrollOffset = 0;
            drawFilterScreen();
        }
    }
    else if (currentScreen == 2 && touchY > STATUS_BAR_HEIGHT) {
        int activeCount = txManager.getActiveCount();
        bool confusionActive = txManager.isConfusionActive();
        if ((activeCount > 0 || confusionActive) &&
            touchX >= TX_STOP_BTN_X && touchX <= TX_STOP_BTN_X + TX_STOP_BTN_W &&
            touchY >= TX_STOP_BTN_Y && touchY <= TX_STOP_BTN_Y + TX_STOP_BTN_H) {
            if (confusionActive) {
                txManager.confuseStop();
            } else {
                txManager.stopAll();
            }
            txActive = false;
            drawTXScreen();
        }
        else if (activeCount == 0 && !confusionActive &&
                 touchX >= TX_STOP_BTN_X && touchX <= TX_STOP_BTN_X + TX_STOP_BTN_W &&
                 touchY >= TX_STOP_BTN_Y && touchY <= TX_STOP_BTN_Y + TX_STOP_BTN_H) {
            if (scanning) {
                pBLEScan->stop();
                delay(50);
            }
            txManager.confuseClear();
            int txCount = txManager.getTransmittableCount();
            for (int i = 0; i < txCount; i++) {
                const device_signature_t* sig = txManager.getTransmittableSignature(i);
                if (sig) txManager.confuseAdd(sig->name, 1);
            }
            txManager.confuseStart();
            txActive = true;
            drawTXScreen();
        }
        else if (activeCount == 0 && !confusionActive && touchY >= TX_LIST_START_Y) {
            int txCount = txManager.getTransmittableCount();
            int itemIdx = (touchY - TX_LIST_START_Y) / TX_ITEM_HEIGHT;
            int deviceIdx = txScrollOffset + itemIdx;
            if (deviceIdx >= 0 && deviceIdx < txCount) {
                const device_signature_t* sig = txManager.getTransmittableSignature(deviceIdx);
                if (sig) {
                    if (scanning) {
                        pBLEScan->stop();
                        delay(50);
                    }
                    txManager.startTx(sig->name, TX_DEFAULT_INTERVAL_MS, -1, false);
                    txActive = true;
                    drawTXScreen();
                }
            }
        }
    }
}

// =============================================================================
// MAIN
// =============================================================================
void setup() {
    initSerial();
    initDisplay();
    initTouch();
    initBLE();
    drawScanScreen();
    Serial.println("Init complete. Scanning...");
    scanning = true;
}

void loop() {
    handleTouch();
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (cmdIndex > 0) {
                cmdBuffer[cmdIndex] = '\0';
                processSerialCommand(cmdBuffer);
                cmdIndex = 0;
            }
        } else if (cmdIndex < SERIAL_CMD_BUFFER_SIZE - 1) {
            cmdBuffer[cmdIndex++] = c;
        }
    }
    txManager.process();
    txActive = txManager.getActiveCount() > 0 || txManager.isConfusionActive();
    static uint32_t lastScanTime = 0;
    if (scanning && !txActive && (millis() - lastScanTime > 5000)) {
        lastScanTime = millis();
        BLEScanResults results = pBLEScan->start(BLE_SCAN_DURATION_SEC, false);
        pBLEScan->clearResults();
    }
    static uint8_t lastScreen = 255;
    static int lastDetectedCount = -1;
    static uint32_t lastStatusUpdate = 0;
    static uint32_t lastTxUpdate = 0;
    bool screenChanged = (lastScreen != currentScreen);
    bool contentChanged = (currentScreen == 0 && detectedCount != lastDetectedCount);
    bool txScreenNeedsUpdate = false;
    if (currentScreen == 2 && txActive && (millis() - lastTxUpdate > 500)) {
        txScreenNeedsUpdate = true;
        lastTxUpdate = millis();
    }
    if (millis() - lastStatusUpdate > 2000) {
        drawStatusBar();
        lastStatusUpdate = millis();
    }
    if (screenChanged || contentChanged || txScreenNeedsUpdate) {
        if (screenChanged) drawStatusBar();
        switch (currentScreen) {
            case 0: drawScanScreen(); break;
            case 1: drawFilterScreen(); break;
            case 2: drawTXScreen(); break;
            case 3: drawSettingsScreen(); break;
            case 4: drawDetailScreen(); break;
        }
        if (currentScreen != 4) drawNavBar();
        lastScreen = currentScreen;
        lastDetectedCount = detectedCount;
    }
    delay(10);
}
