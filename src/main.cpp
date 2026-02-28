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
#include <SPI.h>
#include <XPT2046_Touchscreen.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#include "config.h"
#include "detection/signatures.h"
#include "packet/tx_mgr.h"

// =============================================================================
// TOUCH SCREEN PINS (CYD uses separate VSPI for touch)
// =============================================================================
#define XPT2046_IRQ   36
#define XPT2046_MOSI  32
#define XPT2046_MISO  39
#define XPT2046_CLK   25
#define XPT2046_CS    33

// =============================================================================
// GLOBAL OBJECTS
// =============================================================================
TFT_eSPI tft = TFT_eSPI();
SPIClass touchSpi(VSPI);
XPT2046_Touchscreen ts(XPT2046_CS);  // No IRQ, just poll
BLEScan* pBLEScan = nullptr;

// State
volatile bool scanning = false;
volatile bool txActive = false;
uint8_t currentScreen = 0; // 0=Scan, 1=Filter, 2=TX, 3=Settings, 4=Detail
uint8_t categoryFilter = DEFAULT_CATEGORY_FILTER;
int8_t rssiThreshold = -80;

// List scrolling and detail view
int scrollOffset = 0;           // Current scroll position in device list
int selectedDeviceIdx = -1;     // Index of device shown in detail view
const int ITEMS_PER_PAGE = 9;   // Number of devices visible on screen
const int ITEM_HEIGHT = 18;     // Height of each list item in pixels

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
void drawDetailScreen();
void processSerialCommand(const char* cmd);
void outputDetection(const DetectedDevice* device);
const device_signature_t* matchSignature(BLEAdvertisedDevice* device);
void outputTxEvent(const char* event, const char* device, uint32_t intervalMs, int32_t count, uint32_t sent);
const char* getCategoryString(uint8_t category);
void initTouch();
void handleTouch();

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
                      millis(), device->name, macStr, device->rssi,
                      catStr, device->companyId);
    } else {
        Serial.printf("[%lu] DETECT %s MAC=%s RSSI=%d CAT=%s\n",
                      millis(), device->name, macStr, device->rssi, catStr);
    }
}

void outputTxEvent(const char* event, const char* device, uint32_t intervalMs, int32_t count, uint32_t sent) {
    if (jsonOutput) {
        if (strcmp(event, "tx_start") == 0) {
            Serial.printf("{\"event\":\"%s\",\"ts\":%lu,\"device\":\"%s\","
                          "\"interval_ms\":%lu,\"count\":%ld}\n",
                          event, millis(), device, intervalMs, count);
        } else if (strcmp(event, "tx_stop") == 0) {
            Serial.printf("{\"event\":\"%s\",\"ts\":%lu,\"device\":\"%s\","
                          "\"packets_sent\":%lu}\n",
                          event, millis(), device, sent);
        } else {
            Serial.printf("{\"event\":\"%s\",\"ts\":%lu,\"device\":\"%s\"}\n",
                          event, millis(), device);
        }
    } else {
        if (strcmp(event, "tx_start") == 0) {
            Serial.printf("[%lu] TX_START device=%s interval=%lums count=%ld\n",
                          millis(), device, intervalMs, count);
        } else if (strcmp(event, "tx_stop") == 0) {
            Serial.printf("[%lu] TX_STOP device=%s sent=%lu\n",
                          millis(), device, sent);
        } else {
            Serial.printf("[%lu] %s device=%s\n", millis(), event, device);
        }
    }
}

// =============================================================================
// SERIAL COMMAND PROCESSING
// =============================================================================
void processSerialCommand(const char* cmd) {
    // Keep original for case-sensitive parsing
    String origCmd = String(cmd);
    origCmd.trim();

    // Convert to uppercase for command matching
    String cmdStr = origCmd;
    cmdStr.toUpperCase();

    // =========================================================================
    // HELP & INFO
    // =========================================================================
    if (cmdStr == "HELP") {
        Serial.println("BLEPTD Commands:");
        Serial.println("  HELP              - Show this help");
        Serial.println("  VERSION           - Show firmware version");
        Serial.println("  STATUS            - Current status");
        Serial.println("");
        Serial.println("Scanning:");
        Serial.println("  SCAN START        - Begin BLE scanning");
        Serial.println("  SCAN STOP         - Stop BLE scanning");
        Serial.println("  SCAN CLEAR        - Clear detected devices");
        Serial.println("  SCAN LIST         - List detected devices");
        Serial.println("");
        Serial.println("Transmission:");
        Serial.println("  TX LIST           - List transmittable devices");
        Serial.println("  TX START <device> [interval_ms] [count]");
        Serial.println("  TX STOP <device|ALL>");
        Serial.println("  TX STATUS         - Show active transmissions");
        Serial.println("");
        Serial.println("Confusion Mode:");
        Serial.println("  CONFUSE ADD <device> [count]");
        Serial.println("  CONFUSE REMOVE <device>");
        Serial.println("  CONFUSE LIST      - Show confusion entries");
        Serial.println("  CONFUSE START     - Start confusion broadcast");
        Serial.println("  CONFUSE STOP      - Stop confusion broadcast");
        Serial.println("  CONFUSE CLEAR     - Clear all entries");
        Serial.println("");
        Serial.println("Other:");
        Serial.println("  JSON <ON|OFF>     - Toggle JSON output");
        Serial.println("  DISPLAY SCREEN <N> - Switch screen (0-3)");
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
        Serial.printf("Filter: 0x%02X\n", categoryFilter);
        Serial.printf("RSSI Threshold: %d dBm\n", rssiThreshold);
        Serial.println("OK");
    }

    // =========================================================================
    // SCANNING COMMANDS
    // =========================================================================
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

    // =========================================================================
    // TX COMMANDS
    // =========================================================================
    else if (cmdStr == "TX LIST") {
        Serial.println("Transmittable Devices:");
        int count = txManager.getTransmittableCount();
        for (int i = 0; i < count; i++) {
            const device_signature_t* sig = txManager.getTransmittableSignature(i);
            if (sig) {
                Serial.printf("  [%d] %s (0x%04X) - %s\n",
                              i, sig->name, sig->company_id,
                              getCategoryString(sig->category));
            }
        }
        Serial.printf("Total: %d devices\n", count);
        Serial.println("OK");
    }
    else if (cmdStr.startsWith("TX START ")) {
        // Parse: TX START <device> [interval_ms] [count]
        String args = origCmd.substring(9);
        args.trim();

        // Parse arguments
        String deviceName;
        uint32_t interval = TX_DEFAULT_INTERVAL_MS;
        int32_t count = -1;

        // Find device name (may be quoted)
        int argStart = 0;
        if (args.charAt(0) == '"') {
            int endQuote = args.indexOf('"', 1);
            if (endQuote > 0) {
                deviceName = args.substring(1, endQuote);
                argStart = endQuote + 1;
            }
        } else {
            int space = args.indexOf(' ');
            if (space > 0) {
                deviceName = args.substring(0, space);
                argStart = space + 1;
            } else {
                deviceName = args;
                argStart = args.length();
            }
        }

        // Parse optional interval and count
        if (argStart < (int)args.length()) {
            String remaining = args.substring(argStart);
            remaining.trim();
            int space = remaining.indexOf(' ');
            if (space > 0) {
                interval = remaining.substring(0, space).toInt();
                count = remaining.substring(space + 1).toInt();
            } else if (remaining.length() > 0) {
                interval = remaining.toInt();
            }
        }

        if (deviceName.length() == 0) {
            Serial.println("ERROR 102 Missing device name");
        } else {
            // Stop any active scan before starting TX
            if (scanning) {
                pBLEScan->stop();
                delay(50);  // Give BLE stack time to stop scan
            }

            // Use consistent MAC for standard TX (randomMac=false)
            // MAC is generated once at session start, stays same until stop
            int result = txManager.startTx(deviceName.c_str(), interval, count, false);
            if (result >= 0) {
                txActive = true;
                outputTxEvent("tx_start", deviceName.c_str(), interval, count, 0);
                Serial.println("OK TX started");
            } else if (result == -1) {
                Serial.printf("ERROR 103 Device not found: %s\n", deviceName.c_str());
            } else if (result == -2) {
                Serial.printf("ERROR 105 Already transmitting: %s\n", deviceName.c_str());
            } else if (result == -3) {
                Serial.println("ERROR 105 No free TX slots");
            }
        }
    }
    else if (cmdStr.startsWith("TX STOP ")) {
        String deviceName = origCmd.substring(8);
        deviceName.trim();

        if (deviceName.equalsIgnoreCase("ALL")) {
            txManager.stopAll();
            txActive = false;
            outputTxEvent("tx_stop_all", "ALL", 0, 0, txManager.getTotalPacketsSent());
            Serial.println("OK All TX stopped");
        } else {
            tx_session_t* session = txManager.findSession(deviceName.c_str());
            uint32_t sent = session ? session->packetsSent : 0;

            int result = txManager.stopTx(deviceName.c_str());
            if (result == 0) {
                outputTxEvent("tx_stop", deviceName.c_str(), 0, 0, sent);
                txActive = txManager.getActiveCount() > 0;
                Serial.println("OK TX stopped");
            } else {
                Serial.printf("ERROR 103 Device not found or not transmitting: %s\n", deviceName.c_str());
            }
        }
    }
    else if (cmdStr == "TX STATUS") {
        Serial.println("Active TX Sessions:");
        int activeCount = 0;
        for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
            tx_session_t* session = txManager.getSession(i);
            if (session && session->active) {
                Serial.printf("  [%d] %s - %lu pkts @ %lums (remaining: %ld)\n",
                              i, session->deviceName, session->packetsSent,
                              session->intervalMs, session->remainingCount);
                activeCount++;
            }
        }
        if (activeCount == 0) {
            Serial.println("  (none)");
        }
        Serial.printf("Total packets sent: %lu\n", txManager.getTotalPacketsSent());
        Serial.println("OK");
    }

    // =========================================================================
    // CONFUSION MODE COMMANDS
    // =========================================================================
    else if (cmdStr.startsWith("CONFUSE ADD ")) {
        String args = origCmd.substring(12);
        args.trim();

        String deviceName;
        uint8_t instanceCount = 1;

        // Parse device name and optional count
        int space = args.lastIndexOf(' ');
        if (space > 0) {
            String lastPart = args.substring(space + 1);
            if (lastPart.toInt() > 0) {
                instanceCount = lastPart.toInt();
                deviceName = args.substring(0, space);
            } else {
                deviceName = args;
            }
        } else {
            deviceName = args;
        }

        deviceName.trim();

        int result = txManager.confuseAdd(deviceName.c_str(), instanceCount);
        if (result >= 0) {
            Serial.printf("OK Added %s x%d to confusion list\n", deviceName.c_str(), instanceCount);
        } else if (result == -1) {
            Serial.printf("ERROR 103 Device not found: %s\n", deviceName.c_str());
        } else {
            Serial.println("ERROR 105 Confusion list full");
        }
    }
    else if (cmdStr.startsWith("CONFUSE REMOVE ")) {
        String deviceName = origCmd.substring(15);
        deviceName.trim();

        int result = txManager.confuseRemove(deviceName.c_str());
        if (result == 0) {
            Serial.printf("OK Removed %s from confusion list\n", deviceName.c_str());
        } else {
            Serial.printf("ERROR 103 Device not in list: %s\n", deviceName.c_str());
        }
    }
    else if (cmdStr == "CONFUSE LIST") {
        Serial.println("Confusion Entries:");
        int count = txManager.getConfusionEntryCount();
        for (int i = 0; i < count; i++) {
            confusion_entry_t* entry = txManager.getConfusionEntry(i);
            if (entry) {
                Serial.printf("  [%d] %s x%d\n", i, entry->deviceName, entry->instanceCount);
            }
        }
        if (count == 0) {
            Serial.println("  (none)");
        }
        Serial.printf("Total: %d entries\n", count);
        Serial.println("OK");
    }
    else if (cmdStr == "CONFUSE START") {
        // Stop any active scan before starting confusion TX
        if (scanning) {
            pBLEScan->stop();
            delay(50);
        }

        int result = txManager.confuseStart();
        if (result > 0) {
            txActive = true;
            Serial.printf("OK Confusion started with %d entries\n", result);
        } else {
            Serial.println("ERROR 104 No confusion entries configured");
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
        Serial.println("OK Confusion list cleared");
    }

    // =========================================================================
    // DISPLAY & OUTPUT COMMANDS
    // =========================================================================
    else if (cmdStr == "JSON ON") {
        jsonOutput = true;
        Serial.println("OK JSON output enabled");
    }
    else if (cmdStr == "JSON OFF") {
        jsonOutput = false;
        Serial.println("OK JSON output disabled");
    }
    else if (cmdStr.startsWith("DISPLAY SCREEN ")) {
        int screen = cmdStr.substring(15).toInt();
        if (screen >= 0 && screen <= 3) {
            currentScreen = screen;
            Serial.printf("OK Switched to screen %d\n", screen);
        } else {
            Serial.println("ERROR 101 Invalid screen number (0-3)");
        }
    }
    else if (cmdStr.startsWith("DISPLAY MESSAGE ")) {
        String msg = origCmd.substring(16);
        msg.trim();
        // TODO: Display overlay message
        Serial.println("OK");
    }

    // =========================================================================
    // UNKNOWN COMMAND
    // =========================================================================
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
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextFont(1);

    // Set backlight
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

    // Mode indicator
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

    // Count filtered devices
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

    // Show count and scroll indicator
    char countStr[24];
    if (filteredCount > ITEMS_PER_PAGE) {
        snprintf(countStr, sizeof(countStr), "[%d-%d/%d]",
                 scrollOffset + 1,
                 min(scrollOffset + ITEMS_PER_PAGE, filteredCount),
                 filteredCount);
    } else {
        snprintf(countStr, sizeof(countStr), "[%d]", filteredCount);
    }
    tft.setTextDatum(TR_DATUM);
    tft.drawString(countStr, SCREEN_WIDTH - 4, y, 2);

    y += 20;

    // Draw scroll indicators if needed
    if (filteredCount > ITEMS_PER_PAGE) {
        if (scrollOffset > 0) {
            // Up arrow
            tft.fillTriangle(SCREEN_WIDTH - 15, y, SCREEN_WIDTH - 10, y - 6, SCREEN_WIDTH - 5, y, TFT_YELLOW);
        }
    }

    // Draw device list with scrolling (only show devices matching filter)
    tft.setTextFont(1);
    int displayed = 0;
    int skipped = 0;

    for (int deviceIdx = 0; deviceIdx < detectedCount && displayed < ITEMS_PER_PAGE; deviceIdx++) {
        DetectedDevice* dev = &detectedDevices[deviceIdx];

        // Apply category filter
        if (!(dev->category & categoryFilter)) {
            continue;
        }

        // Handle scroll offset
        if (skipped < scrollOffset) {
            skipped++;
            continue;
        }

        // Category color indicator
        uint16_t catColor = TFT_WHITE;
        switch (dev->category) {
            case CAT_TRACKER:  catColor = TFT_RED;     break;
            case CAT_GLASSES:  catColor = TFT_ORANGE;  break;
            case CAT_MEDICAL:  catColor = TFT_YELLOW;  break;
            case CAT_WEARABLE: catColor = TFT_BLUE;    break;
            case CAT_AUDIO:    catColor = TFT_MAGENTA; break;
        }

        tft.fillCircle(SCREEN_WIDTH - 10, y + 7, 4, catColor);

        // Device name with last 3 MAC octets for uniqueness
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

    // Draw down scroll indicator if more items below
    if (scrollOffset + ITEMS_PER_PAGE < filteredCount) {
        int arrowY = STATUS_BAR_HEIGHT + CONTENT_HEIGHT - 10;
        tft.fillTriangle(SCREEN_WIDTH - 15, arrowY, SCREEN_WIDTH - 10, arrowY + 6, SCREEN_WIDTH - 5, arrowY, TFT_YELLOW);
    }

    // Show message if no devices
    if (filteredCount == 0) {
        tft.setTextDatum(MC_DATUM);
        tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
        if (detectedCount > 0) {
            tft.drawString("No devices match filter", SCREEN_WIDTH/2, SCREEN_HEIGHT/2, 2);
        } else {
            tft.drawString("Scanning for devices...", SCREEN_WIDTH/2, SCREEN_HEIGHT/2, 2);
        }
    }
}

// TX screen layout constants
#define TX_LIST_START_Y     (STATUS_BAR_HEIGHT + 40)
#define TX_ITEM_HEIGHT      18
#define TX_ITEMS_PER_PAGE   8
#define TX_STOP_BTN_X       220
#define TX_STOP_BTN_Y       (STATUS_BAR_HEIGHT + 4)
#define TX_STOP_BTN_W       90
#define TX_STOP_BTN_H       28

// TX screen scroll offset
static int txScrollOffset = 0;

void drawTXScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);

    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);

    // Show active TX sessions
    int activeCount = txManager.getActiveCount();
    bool confusionActive = txManager.isConfusionActive();

    if (confusionActive) {
        tft.setTextColor(TFT_RED);
        tft.drawString("CONFUSION MODE", 4, y);

        // STOP button
        tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_RED);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("STOP", TX_STOP_BTN_X + TX_STOP_BTN_W/2, TX_STOP_BTN_Y + TX_STOP_BTN_H/2, 2);
        tft.setTextDatum(TL_DATUM);

        y += 22;

        // Stats
        tft.setTextColor(TFT_WHITE);
        char statsStr[40];
        snprintf(statsStr, sizeof(statsStr), "Devices: %d  Total Pkts: %lu",
                 txManager.getConfusionEntryCount(),
                 txManager.getTotalPacketsSent());
        tft.drawString(statsStr, 4, y);
        y += 16;

        tft.setTextColor(TFT_CYAN);
        tft.drawString("Broadcasting multiple device types", 4, y);
        y += 18;

        // List confusion entries with details
        int entryCount = txManager.getConfusionEntryCount();
        for (int i = 0; i < min(entryCount, 5) && y < SCREEN_HEIGHT - NAV_BAR_HEIGHT - 10; i++) {
            confusion_entry_t* entry = txManager.getConfusionEntry(i);
            if (entry && entry->sig) {
                // Category color
                uint16_t catColor = TFT_WHITE;
                switch (entry->sig->category) {
                    case CAT_TRACKER:  catColor = TFT_RED;     break;
                    case CAT_GLASSES:  catColor = TFT_ORANGE;  break;
                    case CAT_MEDICAL:  catColor = TFT_YELLOW;  break;
                    case CAT_WEARABLE: catColor = TFT_BLUE;    break;
                    case CAT_AUDIO:    catColor = TFT_MAGENTA; break;
                }
                tft.fillCircle(10, y + 6, 4, catColor);

                char entryStr[48];
                snprintf(entryStr, sizeof(entryStr), "%s (0x%04X)",
                         entry->deviceName, entry->sig->company_id);
                tft.setTextColor(TFT_WHITE);
                tft.drawString(entryStr, 20, y);
                y += 16;
            }
        }

    } else if (activeCount > 0) {
        tft.setTextColor(TFT_YELLOW);
        tft.drawString("TRANSMITTING", 4, y);

        // STOP ALL button
        tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_RED);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("STOP", TX_STOP_BTN_X + TX_STOP_BTN_W/2, TX_STOP_BTN_Y + TX_STOP_BTN_H/2, 2);
        tft.setTextDatum(TL_DATUM);

        y += 22;

        // Show detailed info for each active session
        for (int i = 0; i < TX_MAX_CONCURRENT && y < SCREEN_HEIGHT - NAV_BAR_HEIGHT - 10; i++) {
            tx_session_t* session = txManager.getSession(i);
            if (session && session->active && session->sig) {
                // Device name with category color
                uint16_t catColor = TFT_WHITE;
                switch (session->sig->category) {
                    case CAT_TRACKER:  catColor = TFT_RED;     break;
                    case CAT_GLASSES:  catColor = TFT_ORANGE;  break;
                    case CAT_MEDICAL:  catColor = TFT_YELLOW;  break;
                    case CAT_WEARABLE: catColor = TFT_BLUE;    break;
                    case CAT_AUDIO:    catColor = TFT_MAGENTA; break;
                }
                tft.fillCircle(10, y + 6, 5, catColor);
                tft.setTextColor(TFT_YELLOW);
                tft.drawString(session->deviceName, 20, y);
                y += 16;

                // MAC Address (BDADDR)
                char macStr[24];
                snprintf(macStr, sizeof(macStr), "MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                         session->currentMac[0], session->currentMac[1], session->currentMac[2],
                         session->currentMac[3], session->currentMac[4], session->currentMac[5]);
                tft.setTextColor(TFT_WHITE);
                tft.drawString(macStr, 20, y);
                y += 14;

                // Company ID and Category
                char infoStr[40];
                snprintf(infoStr, sizeof(infoStr), "Company: 0x%04X  Cat: %s",
                         session->sig->company_id, getCategoryString(session->sig->category));
                tft.setTextColor(TFT_DARKGREY);
                tft.drawString(infoStr, 20, y);
                y += 14;

                // Packet stats
                char statsStr[48];
                snprintf(statsStr, sizeof(statsStr), "Packets: %lu  Interval: %lums",
                         session->packetsSent, session->intervalMs);
                tft.setTextColor(TFT_GREEN);
                tft.drawString(statsStr, 20, y);
                y += 14;

                // MAC mode indicator
                if (session->randomMacPerPacket) {
                    tft.setTextColor(TFT_CYAN);
                    tft.drawString("Random MAC per packet", 20, y);
                } else {
                    tft.setTextColor(TFT_GREEN);
                    tft.drawString("Consistent MAC (session)", 20, y);
                }
                y += 18;  // Spacing after MAC mode indicator
            }
        }

    } else {
        // No active TX - show tappable device list
        tft.drawString("TAP TO TX", 4, y);

        // CONFUSE button (starts confusion mode with all trackers)
        tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_MAGENTA);
        tft.setTextColor(TFT_WHITE);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("CONFUSE", TX_STOP_BTN_X + TX_STOP_BTN_W/2, TX_STOP_BTN_Y + TX_STOP_BTN_H/2, 2);
        tft.setTextDatum(TL_DATUM);

        y += 16;

        int txCount = txManager.getTransmittableCount();

        // Show scroll indicator
        if (txCount > TX_ITEMS_PER_PAGE) {
            char scrollStr[16];
            snprintf(scrollStr, sizeof(scrollStr), "[%d-%d/%d]",
                     txScrollOffset + 1,
                     min(txScrollOffset + TX_ITEMS_PER_PAGE, txCount),
                     txCount);
            tft.setTextDatum(TR_DATUM);
            tft.setTextColor(TFT_DARKGREY);
            tft.drawString(scrollStr, SCREEN_WIDTH - 4, y - 16);
            tft.setTextDatum(TL_DATUM);
        }

        y = TX_LIST_START_Y;

        // Draw device list
        tft.setTextColor(TFT_WHITE);
        int displayed = 0;
        for (int i = txScrollOffset; i < txCount && displayed < TX_ITEMS_PER_PAGE; i++) {
            const device_signature_t* sig = txManager.getTransmittableSignature(i);
            if (sig) {
                // Category color indicator
                uint16_t catColor = TFT_WHITE;
                switch (sig->category) {
                    case CAT_TRACKER:  catColor = TFT_RED;     break;
                    case CAT_GLASSES:  catColor = TFT_ORANGE;  break;
                    case CAT_MEDICAL:  catColor = TFT_YELLOW;  break;
                    case CAT_WEARABLE: catColor = TFT_BLUE;    break;
                    case CAT_AUDIO:    catColor = TFT_MAGENTA; break;
                }
                tft.fillCircle(12, y + 7, 5, catColor);

                tft.setTextColor(TFT_WHITE);
                tft.drawString(sig->name, 24, y);

                y += TX_ITEM_HEIGHT;
                displayed++;
            }
        }

        // Scroll indicators
        if (txCount > TX_ITEMS_PER_PAGE) {
            if (txScrollOffset > 0) {
                tft.fillTriangle(SCREEN_WIDTH - 15, TX_LIST_START_Y,
                                SCREEN_WIDTH - 10, TX_LIST_START_Y - 6,
                                SCREEN_WIDTH - 5, TX_LIST_START_Y, TFT_YELLOW);
            }
            if (txScrollOffset + TX_ITEMS_PER_PAGE < txCount) {
                int arrowY = TX_LIST_START_Y + TX_ITEMS_PER_PAGE * TX_ITEM_HEIGHT - 5;
                tft.fillTriangle(SCREEN_WIDTH - 15, arrowY,
                                SCREEN_WIDTH - 10, arrowY + 6,
                                SCREEN_WIDTH - 5, arrowY, TFT_YELLOW);
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

    // Category checkboxes
    struct CatEntry {
        uint8_t cat;
        const char* name;
        uint16_t color;
    };
    CatEntry categories[] = {
        {CAT_TRACKER, "TRACKER - Tracking devices", TFT_RED},
        {CAT_GLASSES, "GLASSES - Smart glasses", TFT_ORANGE},
        {CAT_MEDICAL, "MEDICAL - Medical devices", TFT_YELLOW},
        {CAT_WEARABLE, "WEARABLE - Smartwatches", TFT_BLUE},
        {CAT_AUDIO, "AUDIO - Earbuds/headphones", TFT_MAGENTA},
    };

    for (int i = 0; i < 5; i++) {
        bool enabled = (categoryFilter & categories[i].cat) != 0;

        // Checkbox
        tft.drawRect(8, y, 14, 14, categories[i].color);
        if (enabled) {
            tft.fillRect(10, y + 2, 10, 10, categories[i].color);
        }

        // Label
        tft.setTextColor(enabled ? TFT_WHITE : TFT_DARKGREY);
        tft.drawString(categories[i].name, 28, y + 2);

        y += 22;
    }

    y += 10;
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("RSSI Threshold:", 4, y);
    char rssiStr[16];
    snprintf(rssiStr, sizeof(rssiStr), "%d dBm", rssiThreshold);
    tft.setTextColor(TFT_WHITE);
    tft.drawString(rssiStr, 120, y);
}

void drawSettingsScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);

    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE);
    tft.drawString("SETTINGS", 4, y);
    y += 20;

    // Settings display
    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Scan Duration:", 4, y);
    tft.setTextColor(TFT_WHITE);
    char val[16];
    snprintf(val, sizeof(val), "%d sec", BLE_SCAN_DURATION_SEC);
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Scan Interval:", 4, y);
    tft.setTextColor(TFT_WHITE);
    snprintf(val, sizeof(val), "%d ms", BLE_SCAN_INTERVAL_MS);
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("JSON Output:", 4, y);
    tft.setTextColor(jsonOutput ? TFT_GREEN : TFT_RED);
    tft.drawString(jsonOutput ? "ON" : "OFF", 140, y);
    y += 18;

    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Serial Baud:", 4, y);
    tft.setTextColor(TFT_WHITE);
    snprintf(val, sizeof(val), "%d", SERIAL_BAUD_RATE);
    tft.drawString(val, 140, y);
    y += 28;

    // Stats
    tft.setTextColor(TFT_WHITE);
    tft.drawString("STATISTICS", 4, y);
    y += 18;

    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Devices Detected:", 4, y);
    tft.setTextColor(TFT_WHITE);
    snprintf(val, sizeof(val), "%d", detectedCount);
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("TX Packets:", 4, y);
    tft.setTextColor(TFT_WHITE);
    snprintf(val, sizeof(val), "%lu", txManager.getTotalPacketsSent());
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(TFT_DARKGREY);
    tft.drawString("Uptime:", 4, y);
    tft.setTextColor(TFT_WHITE);
    uint32_t uptime = millis() / 1000;
    snprintf(val, sizeof(val), "%lu:%02lu:%02lu",
             uptime / 3600, (uptime % 3600) / 60, uptime % 60);
    tft.drawString(val, 140, y);
}

void drawDetailScreen() {
    if (selectedDeviceIdx < 0 || selectedDeviceIdx >= detectedCount) {
        currentScreen = 0;  // Return to scan screen if invalid
        drawScanScreen();
        return;
    }

    DetectedDevice* dev = &detectedDevices[selectedDeviceIdx];

    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, TFT_BLACK);

    int y = STATUS_BAR_HEIGHT + 4;

    // Header with close button
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString("DEVICE DETAIL", 4, y, 2);

    // Close button [X]
    tft.setTextDatum(TR_DATUM);
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.drawString("[X]", SCREEN_WIDTH - 4, y, 2);

    y += 22;

    // Device name
    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(TFT_YELLOW, TFT_BLACK);
    tft.drawString(dev->name, 4, y, 2);
    y += 20;

    // Category with color
    uint16_t catColor = TFT_WHITE;
    const char* catName = getCategoryString(dev->category);
    switch (dev->category) {
        case CAT_TRACKER:  catColor = TFT_RED;     break;
        case CAT_GLASSES:  catColor = TFT_ORANGE;  break;
        case CAT_MEDICAL:  catColor = TFT_YELLOW;  break;
        case CAT_WEARABLE: catColor = TFT_BLUE;    break;
        case CAT_AUDIO:    catColor = TFT_MAGENTA; break;
    }
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("Category:", 4, y, 1);
    tft.setTextColor(catColor, TFT_BLACK);
    tft.drawString(catName, 80, y, 1);
    y += 14;

    // Threat level
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("Threat:", 4, y, 1);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    char threatStr[16];
    snprintf(threatStr, sizeof(threatStr), "%d/5", dev->threatLevel);
    tft.drawString(threatStr, 80, y, 1);
    // Draw threat dots
    for (int i = 0; i < 5; i++) {
        uint16_t dotColor = (i < dev->threatLevel) ? TFT_RED : TFT_DARKGREY;
        tft.fillCircle(130 + i * 12, y + 4, 4, dotColor);
    }
    y += 16;

    // MAC address
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             dev->mac[0], dev->mac[1], dev->mac[2],
             dev->mac[3], dev->mac[4], dev->mac[5]);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("MAC:", 4, y, 1);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(macStr, 80, y, 1);
    y += 14;

    // Company ID
    char companyStr[12];
    snprintf(companyStr, sizeof(companyStr), "0x%04X", dev->companyId);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("Company ID:", 4, y, 1);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(companyStr, 80, y, 1);
    y += 14;

    // RSSI with signal strength indicator
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("RSSI:", 4, y, 1);
    char rssiStr[16];
    snprintf(rssiStr, sizeof(rssiStr), "%d dBm", dev->rssi);
    uint16_t rssiColor = TFT_GREEN;
    if (dev->rssi < -70) rssiColor = TFT_YELLOW;
    if (dev->rssi < -85) rssiColor = TFT_RED;
    tft.setTextColor(rssiColor, TFT_BLACK);
    tft.drawString(rssiStr, 80, y, 1);
    y += 14;

    // Detection count
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("Detections:", 4, y, 1);
    char countStr[16];
    snprintf(countStr, sizeof(countStr), "%d", dev->detectionCount);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(countStr, 80, y, 1);
    y += 14;

    // First/Last seen times
    uint32_t now = millis();
    uint32_t firstAgo = (now - dev->firstSeen) / 1000;
    uint32_t lastAgo = (now - dev->lastSeen) / 1000;

    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("First seen:", 4, y, 1);
    char timeStr[16];
    snprintf(timeStr, sizeof(timeStr), "%lus ago", firstAgo);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(timeStr, 80, y, 1);
    y += 14;

    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("Last seen:", 4, y, 1);
    snprintf(timeStr, sizeof(timeStr), "%lus ago", lastAgo);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawString(timeStr, 80, y, 1);

    // No nav bar in detail view - just show back hint
    tft.fillRect(0, SCREEN_HEIGHT - NAV_BAR_HEIGHT, SCREEN_WIDTH, NAV_BAR_HEIGHT, TFT_DARKGREY);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
    tft.drawString("Tap [X] or anywhere to return", SCREEN_WIDTH / 2, SCREEN_HEIGHT - NAV_BAR_HEIGHT / 2, 1);
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

    // Initialize TX manager
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
    // Set up touch CS pin first
    pinMode(XPT2046_CS, OUTPUT);
    digitalWrite(XPT2046_CS, HIGH);

    // Initialize touch SPI with explicit pins for CYD
    // CYD touch uses: CLK=25, MISO=39, MOSI=32, CS=33
    touchSpi.begin(XPT2046_CLK, XPT2046_MISO, XPT2046_MOSI, XPT2046_CS);
    touchSpi.setFrequency(1000000);  // 1MHz for touch

    // Initialize touchscreen
    ts.begin(touchSpi);
    ts.setRotation(0);  // Handle rotation in software mapping

    Serial.println("Touch screen initialized");
}

// =============================================================================
// TOUCH HANDLING
// =============================================================================
// Touch calibration values for CYD ESP32-2432S028R
// Raw ranges observed: X=330-3621, Y=424-3740
#define TOUCH_X_MIN     300
#define TOUCH_X_MAX     3650
#define TOUCH_Y_MIN     400
#define TOUCH_Y_MAX     3750

void handleTouch() {
    static uint32_t lastTouchTime = 0;
    const uint32_t TOUCH_DEBOUNCE_MS = 250;

    // Read the touch point
    TS_Point p = ts.getPoint();

    // Check for valid touch based on pressure (z) value
    if (p.z < 100) {
        return;
    }

    if (millis() - lastTouchTime < TOUCH_DEBOUNCE_MS) {
        return;
    }

    // Map raw touch coordinates to screen coordinates for LANDSCAPE mode
    int16_t touchX = map(p.y, TOUCH_Y_MIN, TOUCH_Y_MAX, 0, SCREEN_WIDTH);
    int16_t touchY = map(p.x, TOUCH_X_MAX, TOUCH_X_MIN, 0, SCREEN_HEIGHT);

    // Clamp to screen bounds
    touchX = constrain(touchX, 0, SCREEN_WIDTH - 1);
    touchY = constrain(touchY, 0, SCREEN_HEIGHT - 1);

    lastTouchTime = millis();

    // Handle detail view - any touch closes it
    if (currentScreen == 4) {
        currentScreen = 0;
        drawScanScreen();
        drawNavBar();
        return;
    }

    // Check if touch is in navigation bar area
    if (touchY >= SCREEN_HEIGHT - NAV_BAR_HEIGHT) {
        int tabWidth = SCREEN_WIDTH / 4;
        int newScreen = touchX / tabWidth;

        if (newScreen >= 0 && newScreen <= 3 && newScreen != currentScreen) {
            currentScreen = newScreen;
            scrollOffset = 0;  // Reset scroll when changing screens

            // Visual feedback - brief highlight
            int tabX = newScreen * tabWidth;
            tft.fillRect(tabX + 2, SCREEN_HEIGHT - NAV_BAR_HEIGHT + 2,
                         tabWidth - 4, NAV_BAR_HEIGHT - 4, TFT_YELLOW);
            delay(50);

            // Force redraw
            drawNavBar();
            switch (currentScreen) {
                case 0: drawScanScreen(); break;
                case 1: drawFilterScreen(); break;
                case 2: drawTXScreen(); break;
                case 3: drawSettingsScreen(); break;
            }
        }
    }
    // Handle scan screen - device selection and scrolling
    else if (currentScreen == 0 && touchY > STATUS_BAR_HEIGHT && detectedCount > 0) {
        // Count filtered devices for scroll bounds
        int filteredCount = 0;
        for (int i = 0; i < detectedCount; i++) {
            if (detectedDevices[i].category & categoryFilter) {
                filteredCount++;
            }
        }

        int listStartY = STATUS_BAR_HEIGHT + 24;
        int listEndY = SCREEN_HEIGHT - NAV_BAR_HEIGHT;

        // Check for scroll up (top 30 pixels of list area)
        if (touchY < listStartY + 30 && scrollOffset > 0) {
            scrollOffset = max(0, scrollOffset - ITEMS_PER_PAGE);
            drawScanScreen();
        }
        // Check for scroll down (bottom 30 pixels of list area)
        else if (touchY > listEndY - 30 && scrollOffset + ITEMS_PER_PAGE < filteredCount) {
            scrollOffset = min(filteredCount - ITEMS_PER_PAGE, scrollOffset + ITEMS_PER_PAGE);
            if (scrollOffset < 0) scrollOffset = 0;
            drawScanScreen();
        }
        // Check for device selection (middle area)
        else if (touchY >= listStartY && touchY < listEndY - 10 && filteredCount > 0) {
            int itemIdx = (touchY - listStartY) / ITEM_HEIGHT;
            int targetFilteredIdx = scrollOffset + itemIdx;

            // Find the actual device index that matches this filtered position
            int filteredIdx = 0;
            for (int i = 0; i < detectedCount; i++) {
                if (detectedDevices[i].category & categoryFilter) {
                    if (filteredIdx == targetFilteredIdx) {
                        selectedDeviceIdx = i;
                        currentScreen = 4;  // Switch to detail view
                        drawDetailScreen();
                        break;
                    }
                    filteredIdx++;
                }
            }
        }
    }
    // Handle filter screen category toggles
    else if (currentScreen == 1 && touchY > STATUS_BAR_HEIGHT + 24) {
        int filterY = STATUS_BAR_HEIGHT + 24;
        int categoryIdx = (touchY - filterY) / 22;

        if (categoryIdx >= 0 && categoryIdx < 5 && touchX < 180) {
            uint8_t categories[] = {CAT_TRACKER, CAT_GLASSES, CAT_MEDICAL, CAT_WEARABLE, CAT_AUDIO};
            if (categoryIdx < 5) {
                categoryFilter ^= categories[categoryIdx];  // Toggle bit
                scrollOffset = 0;  // Reset scroll when filter changes
                drawFilterScreen();
            }
        }
    }
    // Handle TX screen touches
    else if (currentScreen == 2 && touchY > STATUS_BAR_HEIGHT) {
        int activeCount = txManager.getActiveCount();
        bool confusionActive = txManager.isConfusionActive();

        // Check STOP button (when TX or confusion is active)
        if ((activeCount > 0 || confusionActive) &&
            touchX >= TX_STOP_BTN_X && touchX <= TX_STOP_BTN_X + TX_STOP_BTN_W &&
            touchY >= TX_STOP_BTN_Y && touchY <= TX_STOP_BTN_Y + TX_STOP_BTN_H) {

            // Visual feedback
            tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_WHITE);
            delay(50);

            if (confusionActive) {
                txManager.confuseStop();
                Serial.println("[TX] Confusion stopped via touch");
            } else {
                txManager.stopAll();
                Serial.println("[TX] All TX stopped via touch");
            }
            txActive = false;
            drawTXScreen();
        }
        // Check CONFUSE button (when idle)
        else if (activeCount == 0 && !confusionActive &&
                 touchX >= TX_STOP_BTN_X && touchX <= TX_STOP_BTN_X + TX_STOP_BTN_W &&
                 touchY >= TX_STOP_BTN_Y && touchY <= TX_STOP_BTN_Y + TX_STOP_BTN_H) {

            // Visual feedback
            tft.fillRoundRect(TX_STOP_BTN_X, TX_STOP_BTN_Y, TX_STOP_BTN_W, TX_STOP_BTN_H, 4, TFT_WHITE);
            delay(50);

            // Stop any active scan
            if (scanning) {
                pBLEScan->stop();
                delay(50);
            }

            // Clear any existing confusion entries and add ALL transmittable devices
            txManager.confuseClear();

            // Add all transmittable devices to confusion mode (trackers, glasses, etc.)
            int added = 0;
            int txCount = txManager.getTransmittableCount();
            for (int i = 0; i < txCount; i++) {
                const device_signature_t* sig = txManager.getTransmittableSignature(i);
                if (sig) {
                    txManager.confuseAdd(sig->name, 1);
                    added++;
                }
            }

            if (added > 0) {
                int result = txManager.confuseStart();
                if (result > 0) {
                    txActive = true;
                    Serial.printf("[TX] Confusion started via touch with %d trackers\n", added);
                }
            }
            drawTXScreen();
        }
        // Handle device selection (when idle)
        else if (activeCount == 0 && !confusionActive && touchY >= TX_LIST_START_Y) {
            int txCount = txManager.getTransmittableCount();
            int listEndY = TX_LIST_START_Y + TX_ITEMS_PER_PAGE * TX_ITEM_HEIGHT;

            // Check for scroll up
            if (touchY < TX_LIST_START_Y + 25 && txScrollOffset > 0) {
                txScrollOffset = max(0, txScrollOffset - TX_ITEMS_PER_PAGE);
                drawTXScreen();
            }
            // Check for scroll down
            else if (touchY > listEndY - 25 && txScrollOffset + TX_ITEMS_PER_PAGE < txCount) {
                txScrollOffset = min(txCount - TX_ITEMS_PER_PAGE, txScrollOffset + TX_ITEMS_PER_PAGE);
                if (txScrollOffset < 0) txScrollOffset = 0;
                drawTXScreen();
            }
            // Check for device selection
            else if (touchY < listEndY) {
                int itemIdx = (touchY - TX_LIST_START_Y) / TX_ITEM_HEIGHT;
                int deviceIdx = txScrollOffset + itemIdx;

                if (deviceIdx >= 0 && deviceIdx < txCount) {
                    const device_signature_t* sig = txManager.getTransmittableSignature(deviceIdx);
                    if (sig) {
                        // Visual feedback - highlight selected item
                        int highlightY = TX_LIST_START_Y + itemIdx * TX_ITEM_HEIGHT;
                        tft.fillRect(0, highlightY, SCREEN_WIDTH, TX_ITEM_HEIGHT, TFT_DARKGREY);
                        delay(100);

                        // Stop any active scan
                        if (scanning) {
                            pBLEScan->stop();
                            delay(50);
                        }

                        // Start TX for selected device (consistent MAC per session)
                        int result = txManager.startTx(sig->name, TX_DEFAULT_INTERVAL_MS, -1, false);
                        if (result >= 0) {
                            txActive = true;
                            Serial.printf("[TX] Started %s via touch\n", sig->name);
                        } else {
                            Serial.printf("[TX] Failed to start %s: %d\n", sig->name, result);
                        }
                        drawTXScreen();
                    }
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

    Serial.println("Initialization complete. Starting scan...");
    scanning = true;
}

void loop() {
    // Process touch input
    handleTouch();

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

    // Process TX manager (handles timing and packet transmission)
    txManager.process();

    // Update txActive state
    txActive = txManager.getActiveCount() > 0 || txManager.isConfusionActive();

    // BLE scanning (skip if TX is active to avoid conflicts)
    // Only scan every 5 seconds to allow touch polling between scans
    static uint32_t lastScanTime = 0;
    if (scanning && !txActive && (millis() - lastScanTime > 5000)) {
        lastScanTime = millis();
        BLEScanResults results = pBLEScan->start(BLE_SCAN_DURATION_SEC, false);
        pBLEScan->clearResults();
    }

    // Update display only when needed
    static uint8_t lastScreen = 255;
    static int lastDetectedCount = -1;
    static uint32_t lastStatusUpdate = 0;
    static uint32_t lastTxUpdate = 0;

    bool screenChanged = (lastScreen != currentScreen);
    bool contentChanged = (currentScreen == 0 && detectedCount != lastDetectedCount);

    // Update TX screen every 500ms when TX is active
    bool txScreenNeedsUpdate = false;
    if (currentScreen == 2 && txActive && (millis() - lastTxUpdate > 500)) {
        txScreenNeedsUpdate = true;
        lastTxUpdate = millis();
    }

    // Redraw status bar every 2 seconds (for mode indicator updates)
    if (millis() - lastStatusUpdate > 2000) {
        drawStatusBar();
        lastStatusUpdate = millis();
    }

    // Redraw content only when screen changes or content updates
    if (screenChanged || contentChanged || txScreenNeedsUpdate) {
        if (screenChanged) {
            drawStatusBar();
        }
        switch (currentScreen) {
            case 0: drawScanScreen(); break;
            case 1: drawFilterScreen(); break;
            case 2: drawTXScreen(); break;
            case 3: drawSettingsScreen(); break;
            case 4: drawDetailScreen(); break;
        }
        if (currentScreen != 4) {
            drawNavBar();
        }

        lastScreen = currentScreen;
        lastDetectedCount = detectedCount;
    }

    delay(10);
}
