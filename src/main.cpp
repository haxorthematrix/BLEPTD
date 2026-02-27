/**
 * BLEPTD - BLE Privacy Threat Detector
 * Main Entry Point
 *
 * ESP32 CYD firmware for detecting BLE devices that may compromise privacy
 * including trackers, smart glasses, and medical devices.
 *
 * See SPECIFICATION.md for full documentation.
 */

#include <Arduino.h>
#include <TFT_eSPI.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#include "config.h"
#include "detection/signatures.h"

// =============================================================================
// GLOBAL OBJECTS
// =============================================================================
TFT_eSPI tft = TFT_eSPI();
BLEScan* pBLEScan = nullptr;

// State
volatile bool scanning = false;
volatile bool txActive = false;
uint8_t currentScreen = 0; // 0=Scan, 1=Filter, 2=TX, 3=Settings
uint8_t categoryFilter = DEFAULT_CATEGORY_FILTER;
int8_t rssiThreshold = -80;

// Detected devices storage
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

// Serial command buffer
char cmdBuffer[SERIAL_CMD_BUFFER_SIZE];
int cmdIndex = 0;

// JSON output mode
bool jsonOutput = SERIAL_JSON_OUTPUT;

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
void processSerialCommand(const char* cmd);
void outputDetection(const DetectedDevice* device);
const device_signature_t* matchSignature(BLEAdvertisedDevice* device);

// =============================================================================
// BLE SCAN CALLBACK
// =============================================================================
class ScanCallbacks : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) override {
        // Get raw payload
        uint8_t* payload = advertisedDevice.getPayload();
        size_t payloadLen = advertisedDevice.getPayloadLength();

        // Try to match against known signatures
        const device_signature_t* sig = matchSignature(&advertisedDevice);

        if (sig != nullptr) {
            // Check category filter
            if (!(sig->category & categoryFilter)) {
                return;
            }

            // Check RSSI threshold
            if (advertisedDevice.getRSSI() < rssiThreshold) {
                return;
            }

            // Get MAC address
            uint8_t mac[6];
            memcpy(mac, advertisedDevice.getAddress().getNative(), 6);

            // Check if already detected
            int existingIdx = -1;
            for (int i = 0; i < detectedCount; i++) {
                if (memcmp(detectedDevices[i].mac, mac, 6) == 0) {
                    existingIdx = i;
                    break;
                }
            }

            if (existingIdx >= 0) {
                // Update existing
                detectedDevices[existingIdx].rssi = advertisedDevice.getRSSI();
                detectedDevices[existingIdx].lastSeen = millis();
                detectedDevices[existingIdx].detectionCount++;
                detectedDevices[existingIdx].active = true;
            } else if (detectedCount < DETECTED_DEVICES_MAX) {
                // Add new device
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

                // Output detection event
                outputDetection(dev);

                // Update display if on scan screen
                if (currentScreen == 0) {
                    // TODO: Update display
                }
            }
        }
    }
};

// =============================================================================
// SIGNATURE MATCHING
// =============================================================================
const device_signature_t* matchSignature(BLEAdvertisedDevice* device) {
    uint8_t* payload = device->getPayload();
    size_t payloadLen = device->getPayloadLength();

    // Extract company ID from manufacturer data if present
    uint16_t mfgCompanyId = 0;
    bool hasMfgData = false;

    // Parse advertisement data to find manufacturer specific data (type 0xFF)
    size_t idx = 0;
    while (idx < payloadLen) {
        uint8_t len = payload[idx];
        if (len == 0 || idx + len >= payloadLen) break;

        uint8_t type = payload[idx + 1];
        if (type == 0xFF && len >= 3) {
            // Manufacturer specific data
            mfgCompanyId = payload[idx + 2] | (payload[idx + 3] << 8);
            hasMfgData = true;
            break;
        }
        idx += len + 1;
    }

    // Match against signatures
    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        const device_signature_t* sig = &BUILTIN_SIGNATURES[i];
        bool matched = false;

        // Company ID matching
        if ((sig->flags & SIG_FLAG_COMPANY_ID) && hasMfgData) {
            if (sig->company_id == mfgCompanyId) {
                matched = true;
            }
        }

        // Payload pattern matching
        if ((sig->flags & SIG_FLAG_PAYLOAD) && sig->pattern_length > 0) {
            bool patternFound = false;

            if (sig->pattern_offset >= 0) {
                // Match at specific offset
                if ((size_t)(sig->pattern_offset + sig->pattern_length) <= payloadLen) {
                    if (memcmp(payload + sig->pattern_offset,
                              sig->payload_pattern,
                              sig->pattern_length) == 0) {
                        patternFound = true;
                    }
                }
            } else {
                // Search anywhere in payload
                for (size_t j = 0; j + sig->pattern_length <= payloadLen; j++) {
                    if (memcmp(payload + j,
                              sig->payload_pattern,
                              sig->pattern_length) == 0) {
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
// SERIAL OUTPUT
// =============================================================================
void outputDetection(const DetectedDevice* device) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             device->mac[0], device->mac[1], device->mac[2],
             device->mac[3], device->mac[4], device->mac[5]);

    const char* catStr = "UNKNOWN";
    switch (device->category) {
        case CAT_TRACKER:  catStr = "TRACKER";  break;
        case CAT_GLASSES:  catStr = "GLASSES";  break;
        case CAT_MEDICAL:  catStr = "MEDICAL";  break;
        case CAT_WEARABLE: catStr = "WEARABLE"; break;
        case CAT_AUDIO:    catStr = "AUDIO";    break;
    }

    if (jsonOutput) {
        Serial.printf("{\"event\":\"detect\",\"ts\":%lu,\"device\":\"%s\","
                      "\"mac\":\"%s\",\"rssi\":%d,\"category\":\"%s\","
                      "\"company_id\":\"0x%04X\"}\n",
                      millis(), device->name, macStr, device->rssi,
                      catStr, device->companyId);
    } else {
        Serial.printf("[%lu] DETECT %s MAC=%s RSSI=%d CAT=%s\n",
                      millis(), device->name, macStr, device->rssi, catStr);
    }
}

// =============================================================================
// SERIAL COMMAND PROCESSING
// =============================================================================
void processSerialCommand(const char* cmd) {
    // Convert to uppercase for comparison
    String cmdStr = String(cmd);
    cmdStr.trim();
    cmdStr.toUpperCase();

    if (cmdStr == "HELP") {
        Serial.println("BLEPTD Commands:");
        Serial.println("  HELP          - Show this help");
        Serial.println("  VERSION       - Show firmware version");
        Serial.println("  STATUS        - Current status");
        Serial.println("  SCAN START    - Begin BLE scanning");
        Serial.println("  SCAN STOP     - Stop BLE scanning");
        Serial.println("  SCAN CLEAR    - Clear detected devices");
        Serial.println("  SCAN LIST     - List detected devices");
        Serial.println("  FILTER SET <cat> <on|off>");
        Serial.println("  JSON <on|off> - Toggle JSON output");
        Serial.println("OK");
    }
    else if (cmdStr == "VERSION") {
        Serial.printf("BLEPTD v%s\n", BLEPTD_VERSION);
        Serial.println("OK");
    }
    else if (cmdStr == "STATUS") {
        Serial.printf("Scanning: %s\n", scanning ? "ON" : "OFF");
        Serial.printf("TX Active: %s\n", txActive ? "ON" : "OFF");
        Serial.printf("Detected: %d devices\n", detectedCount);
        Serial.printf("Filter: 0x%02X\n", categoryFilter);
        Serial.printf("RSSI Threshold: %d dBm\n", rssiThreshold);
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
    else if (cmdStr == "JSON ON") {
        jsonOutput = true;
        Serial.println("OK JSON output enabled");
    }
    else if (cmdStr == "JSON OFF") {
        jsonOutput = false;
        Serial.println("OK JSON output disabled");
    }
    else if (cmdStr.startsWith("DISPLAY MESSAGE ")) {
        String msg = String(cmd).substring(16);
        msg.trim();
        // TODO: Display overlay message
        Serial.println("OK");
    }
    else {
        Serial.printf("ERROR 100 Unknown command: %s\n", cmd);
    }
}

// =============================================================================
// DISPLAY FUNCTIONS
// =============================================================================
void initDisplay() {
    tft.init();
    tft.setRotation(SCREEN_ROTATION);
    tft.fillScreen(COLOR_BG);
    tft.setTextColor(COLOR_FG, COLOR_BG);

    // Set backlight
    pinMode(TFT_BL_PIN, OUTPUT);
    digitalWrite(TFT_BL_PIN, HIGH);

    drawStatusBar();
    drawNavBar();
}

void drawStatusBar() {
    tft.fillRect(0, 0, SCREEN_WIDTH, STATUS_BAR_HEIGHT, COLOR_BG);
    tft.setTextDatum(TL_DATUM);
    tft.setTextSize(1);
    tft.setTextColor(COLOR_FG);
    tft.drawString("BLEPTD v" BLEPTD_VERSION, 4, 4);

    // Mode indicator
    const char* modeStr = scanning ? "SCANNING" : "IDLE";
    tft.setTextDatum(TR_DATUM);
    tft.drawString(modeStr, SCREEN_WIDTH - 4, 4);
}

void drawNavBar() {
    int y = SCREEN_HEIGHT - NAV_BAR_HEIGHT;
    tft.fillRect(0, y, SCREEN_WIDTH, NAV_BAR_HEIGHT, 0x2104); // Dark gray

    const char* tabs[] = {"SCAN", "FILTER", "TX", "SETTINGS"};
    int tabWidth = SCREEN_WIDTH / 4;

    for (int i = 0; i < 4; i++) {
        int x = i * tabWidth;
        uint16_t color = (i == currentScreen) ? COLOR_ACCENT : COLOR_FG;
        tft.setTextColor(color);
        tft.setTextDatum(MC_DATUM);
        tft.drawString(tabs[i], x + tabWidth / 2, y + NAV_BAR_HEIGHT / 2);
    }
}

void drawScanScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, COLOR_BG);

    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(COLOR_FG);
    tft.drawString("DETECTED DEVICES", 4, y);

    char countStr[16];
    snprintf(countStr, sizeof(countStr), "[%d]", detectedCount);
    tft.setTextDatum(TR_DATUM);
    tft.drawString(countStr, SCREEN_WIDTH - 4, y);

    y += 16;

    // Draw device list
    for (int i = 0; i < min(detectedCount, 8); i++) {
        DetectedDevice* dev = &detectedDevices[i];

        // Category color indicator
        uint16_t catColor = COLOR_FG;
        switch (dev->category) {
            case CAT_TRACKER:  catColor = COLOR_CAT_TRACKER;  break;
            case CAT_GLASSES:  catColor = COLOR_CAT_GLASSES;  break;
            case CAT_MEDICAL:  catColor = COLOR_CAT_MEDICAL;  break;
            case CAT_WEARABLE: catColor = COLOR_CAT_WEARABLE; break;
            case CAT_AUDIO:    catColor = COLOR_CAT_AUDIO;    break;
        }

        tft.fillCircle(SCREEN_WIDTH - 10, y + 8, 4, catColor);

        // Device name and RSSI
        tft.setTextDatum(TL_DATUM);
        tft.setTextColor(COLOR_FG);
        tft.drawString(dev->name, 4, y);

        char rssiStr[16];
        snprintf(rssiStr, sizeof(rssiStr), "%d dBm", dev->rssi);
        tft.drawString(rssiStr, 180, y);

        y += 18;
    }
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

// =============================================================================
// MAIN
// =============================================================================
void setup() {
    initSerial();
    initDisplay();
    initBLE();

    drawScanScreen();

    Serial.println("Initialization complete. Starting scan...");
    scanning = true;
}

void loop() {
    // Process serial commands
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

    // BLE scanning
    if (scanning) {
        BLEScanResults results = pBLEScan->start(BLE_SCAN_DURATION_SEC, false);
        pBLEScan->clearResults();
    }

    // Update display periodically
    static uint32_t lastDisplayUpdate = 0;
    if (millis() - lastDisplayUpdate > 500) {
        drawStatusBar();
        if (currentScreen == 0) {
            drawScanScreen();
        }
        lastDisplayUpdate = millis();
    }

    delay(10);
}
