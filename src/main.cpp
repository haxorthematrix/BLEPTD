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
#include "packet/tx_mgr.h"

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
void outputTxEvent(const char* event, const char* device, uint32_t intervalMs, int32_t count, uint32_t sent);
const char* getCategoryString(uint8_t category);

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
            int result = txManager.startTx(deviceName.c_str(), interval, count, true);
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
    String modeStr;
    uint16_t modeColor = COLOR_FG;

    if (txManager.isConfusionActive()) {
        modeStr = "CONFUSE";
        modeColor = COLOR_ERROR;
    } else if (txManager.getActiveCount() > 0) {
        modeStr = "TX:" + String(txManager.getActiveCount());
        modeColor = COLOR_WARNING;
    } else if (scanning) {
        modeStr = "SCANNING";
        modeColor = COLOR_SUCCESS;
    } else {
        modeStr = "IDLE";
    }

    tft.setTextDatum(TR_DATUM);
    tft.setTextColor(modeColor);
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

void drawTXScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, COLOR_BG);

    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(COLOR_FG);

    // Show active TX sessions
    int activeCount = txManager.getActiveCount();
    bool confusionActive = txManager.isConfusionActive();

    if (confusionActive) {
        tft.setTextColor(COLOR_ERROR);
        tft.drawString("CONFUSION MODE ACTIVE", 4, y);
        y += 16;

        tft.setTextColor(COLOR_FG);
        char statsStr[32];
        snprintf(statsStr, sizeof(statsStr), "Entries: %d  Pkts: %lu",
                 txManager.getConfusionEntryCount(),
                 txManager.getTotalPacketsSent());
        tft.drawString(statsStr, 4, y);
        y += 20;

        // List confusion entries
        tft.drawString("Active Devices:", 4, y);
        y += 14;

        int entryCount = txManager.getConfusionEntryCount();
        for (int i = 0; i < min(entryCount, 6); i++) {
            confusion_entry_t* entry = txManager.getConfusionEntry(i);
            if (entry) {
                char entryStr[48];
                snprintf(entryStr, sizeof(entryStr), "  %s x%d",
                         entry->deviceName, entry->instanceCount);
                tft.drawString(entryStr, 4, y);
                y += 14;
            }
        }

    } else if (activeCount > 0) {
        tft.setTextColor(COLOR_WARNING);
        tft.drawString("ACTIVE TRANSMISSIONS", 4, y);
        y += 16;

        tft.setTextColor(COLOR_FG);
        char statsStr[32];
        snprintf(statsStr, sizeof(statsStr), "Sessions: %d  Pkts: %lu",
                 activeCount, txManager.getTotalPacketsSent());
        tft.drawString(statsStr, 4, y);
        y += 20;

        // List active sessions
        for (int i = 0; i < TX_MAX_CONCURRENT && y < SCREEN_HEIGHT - NAV_BAR_HEIGHT - 20; i++) {
            tx_session_t* session = txManager.getSession(i);
            if (session && session->active) {
                // Device name
                tft.setTextColor(COLOR_ACCENT);
                tft.drawString(session->deviceName, 4, y);

                // Stats on same line
                tft.setTextColor(COLOR_FG);
                char statsLine[32];
                snprintf(statsLine, sizeof(statsLine), "%lu @ %lums",
                         session->packetsSent, session->intervalMs);
                tft.drawString(statsLine, 180, y);
                y += 16;

                // Remaining count if not infinite
                if (session->remainingCount > 0) {
                    char remStr[24];
                    snprintf(remStr, sizeof(remStr), "  Remaining: %ld", session->remainingCount);
                    tft.drawString(remStr, 4, y);
                    y += 14;
                }
            }
        }

    } else {
        // No active TX - show available devices
        tft.drawString("AVAILABLE DEVICES", 4, y);
        y += 16;

        tft.setTextColor(0x8410);  // Gray
        tft.drawString("Use serial: TX START <device>", 4, y);
        y += 20;

        tft.setTextColor(COLOR_FG);
        int txCount = txManager.getTransmittableCount();
        for (int i = 0; i < min(txCount, 8); i++) {
            const device_signature_t* sig = txManager.getTransmittableSignature(i);
            if (sig) {
                // Category color indicator
                uint16_t catColor = COLOR_FG;
                switch (sig->category) {
                    case CAT_TRACKER:  catColor = COLOR_CAT_TRACKER;  break;
                    case CAT_GLASSES:  catColor = COLOR_CAT_GLASSES;  break;
                    case CAT_MEDICAL:  catColor = COLOR_CAT_MEDICAL;  break;
                    case CAT_WEARABLE: catColor = COLOR_CAT_WEARABLE; break;
                    case CAT_AUDIO:    catColor = COLOR_CAT_AUDIO;    break;
                }
                tft.fillCircle(12, y + 6, 4, catColor);

                tft.setTextColor(COLOR_FG);
                tft.drawString(sig->name, 22, y);

                char idStr[12];
                snprintf(idStr, sizeof(idStr), "0x%04X", sig->company_id);
                tft.setTextColor(0x8410);
                tft.drawString(idStr, 260, y);

                y += 16;
            }
        }
    }
}

void drawFilterScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, COLOR_BG);

    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(COLOR_FG);
    tft.drawString("DEVICE CATEGORIES", 4, y);
    y += 20;

    // Category checkboxes
    struct CatEntry {
        uint8_t cat;
        const char* name;
        uint16_t color;
    };
    CatEntry categories[] = {
        {CAT_TRACKER, "TRACKER - Tracking devices", COLOR_CAT_TRACKER},
        {CAT_GLASSES, "GLASSES - Smart glasses", COLOR_CAT_GLASSES},
        {CAT_MEDICAL, "MEDICAL - Medical devices", COLOR_CAT_MEDICAL},
        {CAT_WEARABLE, "WEARABLE - Smartwatches", COLOR_CAT_WEARABLE},
        {CAT_AUDIO, "AUDIO - Earbuds/headphones", COLOR_CAT_AUDIO},
    };

    for (int i = 0; i < 5; i++) {
        bool enabled = (categoryFilter & categories[i].cat) != 0;

        // Checkbox
        tft.drawRect(8, y, 14, 14, categories[i].color);
        if (enabled) {
            tft.fillRect(10, y + 2, 10, 10, categories[i].color);
        }

        // Label
        tft.setTextColor(enabled ? COLOR_FG : 0x8410);
        tft.drawString(categories[i].name, 28, y + 2);

        y += 22;
    }

    y += 10;
    tft.setTextColor(0x8410);
    tft.drawString("RSSI Threshold:", 4, y);
    char rssiStr[16];
    snprintf(rssiStr, sizeof(rssiStr), "%d dBm", rssiThreshold);
    tft.setTextColor(COLOR_FG);
    tft.drawString(rssiStr, 120, y);
}

void drawSettingsScreen() {
    int y = STATUS_BAR_HEIGHT + 4;
    tft.fillRect(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH, CONTENT_HEIGHT, COLOR_BG);

    tft.setTextDatum(TL_DATUM);
    tft.setTextColor(COLOR_FG);
    tft.drawString("SETTINGS", 4, y);
    y += 20;

    // Settings display
    tft.setTextColor(0x8410);
    tft.drawString("Scan Duration:", 4, y);
    tft.setTextColor(COLOR_FG);
    char val[16];
    snprintf(val, sizeof(val), "%d sec", BLE_SCAN_DURATION_SEC);
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(0x8410);
    tft.drawString("Scan Interval:", 4, y);
    tft.setTextColor(COLOR_FG);
    snprintf(val, sizeof(val), "%d ms", BLE_SCAN_INTERVAL_MS);
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(0x8410);
    tft.drawString("JSON Output:", 4, y);
    tft.setTextColor(jsonOutput ? COLOR_SUCCESS : COLOR_ERROR);
    tft.drawString(jsonOutput ? "ON" : "OFF", 140, y);
    y += 18;

    tft.setTextColor(0x8410);
    tft.drawString("Serial Baud:", 4, y);
    tft.setTextColor(COLOR_FG);
    snprintf(val, sizeof(val), "%d", SERIAL_BAUD_RATE);
    tft.drawString(val, 140, y);
    y += 28;

    // Stats
    tft.setTextColor(COLOR_FG);
    tft.drawString("STATISTICS", 4, y);
    y += 18;

    tft.setTextColor(0x8410);
    tft.drawString("Devices Detected:", 4, y);
    tft.setTextColor(COLOR_FG);
    snprintf(val, sizeof(val), "%d", detectedCount);
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(0x8410);
    tft.drawString("TX Packets:", 4, y);
    tft.setTextColor(COLOR_FG);
    snprintf(val, sizeof(val), "%lu", txManager.getTotalPacketsSent());
    tft.drawString(val, 140, y);
    y += 18;

    tft.setTextColor(0x8410);
    tft.drawString("Uptime:", 4, y);
    tft.setTextColor(COLOR_FG);
    uint32_t uptime = millis() / 1000;
    snprintf(val, sizeof(val), "%lu:%02lu:%02lu",
             uptime / 3600, (uptime % 3600) / 60, uptime % 60);
    tft.drawString(val, 140, y);
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

    // Process TX manager (handles timing and packet transmission)
    txManager.process();

    // Update txActive state
    txActive = txManager.getActiveCount() > 0 || txManager.isConfusionActive();

    // BLE scanning (skip if TX is active to avoid conflicts)
    if (scanning && !txActive) {
        BLEScanResults results = pBLEScan->start(BLE_SCAN_DURATION_SEC, false);
        pBLEScan->clearResults();
    }

    // Update display periodically
    static uint32_t lastDisplayUpdate = 0;
    static uint8_t lastScreen = 255;
    bool forceRedraw = (lastScreen != currentScreen);

    if (forceRedraw || millis() - lastDisplayUpdate > 500) {
        drawStatusBar();

        // Only redraw content if screen changed or periodic update
        if (forceRedraw || millis() - lastDisplayUpdate > 500) {
            switch (currentScreen) {
                case 0: drawScanScreen(); break;
                case 1: drawFilterScreen(); break;
                case 2: drawTXScreen(); break;
                case 3: drawSettingsScreen(); break;
            }
            drawNavBar();
        }

        lastDisplayUpdate = millis();
        lastScreen = currentScreen;
    }

    delay(10);
}
