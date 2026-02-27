/**
 * BLEPTD - BLE Privacy Threat Detector
 * TX Manager - BLE Advertisement Transmission
 *
 * Handles simulating BLE advertising packets for testing and countermeasures.
 */

#ifndef TX_MGR_H
#define TX_MGR_H

#include <Arduino.h>
#include "../config.h"
#include "../detection/signatures.h"

// =============================================================================
// TX SESSION STRUCTURE
// =============================================================================
typedef struct {
    char deviceName[32];                // Name of device being simulated
    const device_signature_t* sig;      // Pointer to signature
    uint32_t intervalMs;                // Interval between packets
    int32_t remainingCount;             // Packets remaining (-1 = infinite)
    uint32_t packetsSent;               // Total packets sent
    uint32_t lastTxTime;                // Last transmission timestamp
    uint8_t currentMac[6];              // Current MAC address
    bool randomMacPerPacket;            // Randomize MAC each packet
    bool active;                        // Session is active
} tx_session_t;

// =============================================================================
// CONFUSION MODE ENTRY
// =============================================================================
typedef struct {
    char deviceName[32];                // Device name
    const device_signature_t* sig;      // Signature pointer
    uint8_t instanceCount;              // Number of instances to simulate
    bool enabled;                       // Entry is enabled
} confusion_entry_t;

// =============================================================================
// TX MANAGER CLASS
// =============================================================================
class TXManager {
public:
    TXManager();

    // Initialization
    void init();

    // Single device transmission
    int startTx(const char* deviceName, uint32_t intervalMs = TX_DEFAULT_INTERVAL_MS,
                int32_t count = -1, bool randomMac = true);
    int stopTx(const char* deviceName);
    void stopAll();

    // Session management
    int getActiveCount();
    tx_session_t* getSession(int index);
    tx_session_t* findSession(const char* deviceName);

    // Confusion mode
    int confuseAdd(const char* deviceName, uint8_t instanceCount);
    int confuseRemove(const char* deviceName);
    void confuseClear();
    int confuseStart();
    void confuseStop();
    bool isConfusionActive() { return _confusionActive; }
    int getConfusionEntryCount();
    confusion_entry_t* getConfusionEntry(int index);

    // Get transmittable devices list
    int getTransmittableCount();
    const device_signature_t* getTransmittableSignature(int index);
    const device_signature_t* findSignatureByName(const char* name);

    // Processing (call from loop)
    void process();

    // Statistics
    uint32_t getTotalPacketsSent() { return _totalPacketsSent; }

private:
    tx_session_t _sessions[TX_MAX_CONCURRENT];
    confusion_entry_t _confusionEntries[TX_CONFUSION_MAX_DEVICES];
    bool _confusionActive;
    uint32_t _totalPacketsSent;
    uint8_t _confusionIndex;  // Round-robin index for confusion mode

    // Internal methods
    void generateRandomMac(uint8_t* mac);
    bool buildAdvertisingData(const device_signature_t* sig, uint8_t* advData, uint8_t* advLen);
    void transmitPacket(tx_session_t* session);
    void transmitConfusionPacket();
    int findFreeSession();
};

// Global TX manager instance
extern TXManager txManager;

#endif // TX_MGR_H
