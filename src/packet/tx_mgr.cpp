/**
 * BLEPTD - BLE Privacy Threat Detector
 * TX Manager Implementation
 */

#include "tx_mgr.h"
#include <BLEDevice.h>
#include <BLEAdvertising.h>
#include <esp_bt.h>
#include <esp_gap_ble_api.h>

// Global instance
TXManager txManager;

// =============================================================================
// CONSTRUCTOR
// =============================================================================
TXManager::TXManager() {
    memset(_sessions, 0, sizeof(_sessions));
    memset(_confusionEntries, 0, sizeof(_confusionEntries));
    _confusionActive = false;
    _totalPacketsSent = 0;
    _confusionIndex = 0;
}

// =============================================================================
// INITIALIZATION
// =============================================================================
void TXManager::init() {
    // BLE should already be initialized by main
    // Nothing specific needed here for now
}

// =============================================================================
// TRANSMITTABLE DEVICE QUERIES
// =============================================================================
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
    // Also try partial match
    for (size_t i = 0; i < BUILTIN_SIGNATURE_COUNT; i++) {
        if (strcasestr(BUILTIN_SIGNATURES[i].name, name) != nullptr) {
            if (BUILTIN_SIGNATURES[i].flags & SIG_FLAG_TRANSMITTABLE) {
                return &BUILTIN_SIGNATURES[i];
            }
        }
    }
    return nullptr;
}

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================
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

// =============================================================================
// START/STOP TRANSMISSION
// =============================================================================
int TXManager::startTx(const char* deviceName, uint32_t intervalMs, int32_t count, bool randomMac) {
    // Find signature
    const device_signature_t* sig = findSignatureByName(deviceName);
    if (sig == nullptr) {
        return -1;  // Device not found
    }

    // Check if already transmitting this device
    tx_session_t* existing = findSession(deviceName);
    if (existing != nullptr) {
        return -2;  // Already active
    }

    // Find free session slot
    int slot = findFreeSession();
    if (slot < 0) {
        return -3;  // No free slots
    }

    // Initialize session
    tx_session_t* session = &_sessions[slot];
    strncpy(session->deviceName, sig->name, sizeof(session->deviceName) - 1);
    session->sig = sig;
    session->intervalMs = intervalMs;
    session->remainingCount = count;
    session->packetsSent = 0;
    session->lastTxTime = 0;
    session->randomMacPerPacket = randomMac;
    session->active = true;

    // Generate initial MAC
    generateRandomMac(session->currentMac);

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

// =============================================================================
// CONFUSION MODE
// =============================================================================
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
        return -1;  // Device not found
    }

    // Check if already in confusion list
    for (int i = 0; i < TX_CONFUSION_MAX_DEVICES; i++) {
        if (_confusionEntries[i].enabled &&
            strcasecmp(_confusionEntries[i].deviceName, sig->name) == 0) {
            // Update instance count
            _confusionEntries[i].instanceCount = instanceCount;
            return i;
        }
    }

    // Find free slot
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

    return -2;  // No free slots
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
        return -1;  // No entries configured
    }
    _confusionActive = true;
    _confusionIndex = 0;
    return entryCount;
}

void TXManager::confuseStop() {
    _confusionActive = false;
}

// =============================================================================
// MAC ADDRESS GENERATION
// =============================================================================
void TXManager::generateRandomMac(uint8_t* mac) {
    // Generate random MAC with locally administered bit set
    for (int i = 0; i < 6; i++) {
        mac[i] = esp_random() & 0xFF;
    }
    // Set locally administered bit (bit 1 of first byte)
    mac[0] |= 0x02;
    // Clear multicast bit (bit 0 of first byte)
    mac[0] &= 0xFE;
}

// =============================================================================
// ADVERTISING DATA CONSTRUCTION
// =============================================================================
bool TXManager::buildAdvertisingData(const device_signature_t* sig, uint8_t* advData, uint8_t* advLen) {
    uint8_t pos = 0;

    // Flags (required for discoverable devices)
    advData[pos++] = 0x02;  // Length
    advData[pos++] = 0x01;  // Type: Flags
    advData[pos++] = 0x06;  // LE General Discoverable, BR/EDR Not Supported

    // Manufacturer Specific Data
    if (sig->company_id != 0) {
        uint8_t mfgDataLen = 2;  // Company ID

        // Add payload pattern if present
        if (sig->pattern_length > 0 && sig->pattern_offset == 0) {
            // Pattern includes company ID at start, use as-is
            mfgDataLen = sig->pattern_length;
            advData[pos++] = mfgDataLen + 1;  // Length (data + type)
            advData[pos++] = 0xFF;  // Type: Manufacturer Specific Data
            memcpy(&advData[pos], sig->payload_pattern, sig->pattern_length);
            pos += sig->pattern_length;
        } else {
            // Build manufacturer data with company ID + optional extra bytes
            uint8_t extraBytes = 4;  // Add some random payload data
            mfgDataLen = 2 + extraBytes;

            advData[pos++] = mfgDataLen + 1;  // Length
            advData[pos++] = 0xFF;  // Type: Manufacturer Specific Data
            // Company ID (little-endian)
            advData[pos++] = sig->company_id & 0xFF;
            advData[pos++] = (sig->company_id >> 8) & 0xFF;

            // Add pattern if exists and not at offset 0
            if (sig->pattern_length > 0 && sig->pattern_length <= extraBytes) {
                memcpy(&advData[pos], sig->payload_pattern, sig->pattern_length);
                pos += sig->pattern_length;
                // Fill remaining with random
                for (int i = sig->pattern_length; i < extraBytes; i++) {
                    advData[pos++] = esp_random() & 0xFF;
                }
            } else {
                // Random payload
                for (int i = 0; i < extraBytes; i++) {
                    advData[pos++] = esp_random() & 0xFF;
                }
            }
        }
    }

    // Service UUID if specified
    if (sig->service_uuid != 0) {
        advData[pos++] = 0x03;  // Length
        advData[pos++] = 0x03;  // Type: Complete List of 16-bit Service UUIDs
        advData[pos++] = sig->service_uuid & 0xFF;
        advData[pos++] = (sig->service_uuid >> 8) & 0xFF;
    }

    *advLen = pos;
    return pos > 0;
}

// =============================================================================
// PACKET TRANSMISSION
// =============================================================================
void TXManager::transmitPacket(tx_session_t* session) {
    if (!session->active || session->sig == nullptr) {
        return;
    }

    // Build advertising data
    uint8_t advData[31];
    uint8_t advLen = 0;

    if (!buildAdvertisingData(session->sig, advData, &advLen)) {
        return;
    }

    // Generate new MAC if needed
    if (session->randomMacPerPacket) {
        generateRandomMac(session->currentMac);
    }

    // Set the random address
    esp_ble_gap_set_rand_addr(session->currentMac);

    // Configure advertising parameters
    esp_ble_adv_params_t advParams = {
        .adv_int_min = 0x20,   // 20ms
        .adv_int_max = 0x40,   // 40ms
        .adv_type = ADV_TYPE_NONCONN_IND,  // Non-connectable
        .own_addr_type = BLE_ADDR_TYPE_RANDOM,
        .peer_addr = {0},
        .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
        .channel_map = ADV_CHNL_ALL,
        .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    };

    // Configure raw advertising data
    esp_ble_gap_config_adv_data_raw(advData, advLen);

    // Start advertising briefly
    esp_ble_gap_start_advertising(&advParams);

    // Small delay to ensure packet is sent
    delay(5);

    // Stop advertising
    esp_ble_gap_stop_advertising();

    // Update counters
    session->packetsSent++;
    session->lastTxTime = millis();
    _totalPacketsSent++;

    // Check if we've reached the count limit
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

    // Find next enabled entry (round-robin)
    int startIndex = _confusionIndex;
    do {
        if (_confusionEntries[_confusionIndex].enabled) {
            confusion_entry_t* entry = &_confusionEntries[_confusionIndex];

            // Build and transmit for each instance
            uint8_t advData[31];
            uint8_t advLen = 0;

            if (buildAdvertisingData(entry->sig, advData, &advLen)) {
                // Generate random MAC
                uint8_t mac[6];
                generateRandomMac(mac);
                esp_ble_gap_set_rand_addr(mac);

                // Configure advertising
                esp_ble_adv_params_t advParams = {
                    .adv_int_min = 0x20,
                    .adv_int_max = 0x40,
                    .adv_type = ADV_TYPE_NONCONN_IND,
                    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
                    .peer_addr = {0},
                    .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
                    .channel_map = ADV_CHNL_ALL,
                    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
                };

                esp_ble_gap_config_adv_data_raw(advData, advLen);
                esp_ble_gap_start_advertising(&advParams);
                delay(3);
                esp_ble_gap_stop_advertising();

                _totalPacketsSent++;
            }

            // Move to next
            _confusionIndex = (_confusionIndex + 1) % TX_CONFUSION_MAX_DEVICES;
            return;
        }
        _confusionIndex = (_confusionIndex + 1) % TX_CONFUSION_MAX_DEVICES;
    } while (_confusionIndex != startIndex);
}

// =============================================================================
// MAIN PROCESSING LOOP
// =============================================================================
void TXManager::process() {
    uint32_t now = millis();

    // Process individual TX sessions
    for (int i = 0; i < TX_MAX_CONCURRENT; i++) {
        tx_session_t* session = &_sessions[i];
        if (session->active) {
            if (now - session->lastTxTime >= session->intervalMs) {
                transmitPacket(session);
            }
        }
    }

    // Process confusion mode
    if (_confusionActive) {
        // Transmit at high rate for confusion effect
        static uint32_t lastConfuseTime = 0;
        if (now - lastConfuseTime >= 20) {  // 50 packets/sec max
            transmitConfusionPacket();
            lastConfuseTime = now;
        }
    }
}
