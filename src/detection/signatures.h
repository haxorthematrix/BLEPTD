/**
 * BLEPTD - BLE Privacy Threat Detector
 * Built-in Device Signatures
 *
 * This file contains the default signature database for known BLE devices
 * that may pose privacy or security concerns.
 */

#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <Arduino.h>
#include "../config.h"

// =============================================================================
// SIGNATURE FLAGS
// =============================================================================
#define SIG_FLAG_COMPANY_ID     0x0001  // Match on company ID
#define SIG_FLAG_PAYLOAD        0x0002  // Match on payload pattern
#define SIG_FLAG_SERVICE_UUID   0x0004  // Match on service UUID
#define SIG_FLAG_NAME_PATTERN   0x0008  // Match on device name
#define SIG_FLAG_EXACT_MATCH    0x0010  // All specified fields must match
#define SIG_FLAG_TRANSMITTABLE  0x0020  // Can simulate this device
#define SIG_FLAG_MEDICAL        0x0040  // Medical device (special handling)

// =============================================================================
// SIGNATURE STRUCTURE
// =============================================================================
// Order: name, category, company_id, payload_pattern[8], pattern_length,
//        pattern_offset, service_uuid, threat_level, flags
typedef struct {
    char name[32];                  // Human-readable device name
    uint8_t category;               // Device category (CAT_*)
    uint16_t company_id;            // Bluetooth SIG Company ID (0 if not used)
    uint8_t payload_pattern[8];     // Byte pattern to match
    uint8_t pattern_length;         // Length of pattern (0 if not used)
    int8_t pattern_offset;          // Offset in payload (-1 for any position)
    uint16_t service_uuid;          // 16-bit Service UUID (0 if not used)
    uint8_t threat_level;           // 1-5 severity rating
    uint32_t flags;                 // Detection flags
} device_signature_t;

// =============================================================================
// BLUETOOTH SIG COMPANY IDENTIFIERS
// =============================================================================
#define COMPANY_APPLE           0x004C
#define COMPANY_SAMSUNG         0x0075
#define COMPANY_MICROSOFT       0x0006
#define COMPANY_GOOGLE          0x00E0
#define COMPANY_GARMIN          0x0087
#define COMPANY_BOSE            0x009E
#define COMPANY_DEXCOM          0x00D1
#define COMPANY_SONY            0x012D
#define COMPANY_AMAZON          0x0171
#define COMPANY_META            0x01AB
#define COMPANY_FITBIT          0x0224
#define COMPANY_MEDTRONIC       0x02A5
#define COMPANY_SNAP            0x03C2
#define COMPANY_RAZER           0x0532
#define COMPANY_META_TECH       0x058E
#define COMPANY_ABBOTT          0x0618
#define COMPANY_INSULET         0x0822
#define COMPANY_LUXOTTICA       0x0D53
#define COMPANY_TILE            0xFEEC
#define COMPANY_TILE_ALT        0xFEED
#define COMPANY_CHIPOLO         0xFE65

// =============================================================================
// BUILT-IN SIGNATURES
// Format: {name, category, company_id, {pattern[8]}, pattern_len, offset, svc_uuid, threat, flags}
// =============================================================================
static const device_signature_t BUILTIN_SIGNATURES[] = {
    // TRACKERS
    {"AirTag (Registered)",     CAT_TRACKER, COMPANY_APPLE,    {0x4C,0x00,0x07,0x19,0,0,0,0}, 4,  0, 0, THREAT_SEVERE,   SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"AirTag (Unregistered)",   CAT_TRACKER, COMPANY_APPLE,    {0x4C,0x00,0x12,0x19,0,0,0,0}, 4,  0, 0, THREAT_SEVERE,   SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Samsung SmartTag",        CAT_TRACKER, COMPANY_SAMSUNG,  {0x75,0x00,0x42,0x09,0x01,0,0,0}, 5, 0, 0, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Samsung SmartTag2",       CAT_TRACKER, COMPANY_SAMSUNG,  {0x75,0x00,0x42,0x09,0x02,0,0,0}, 5, 0, 0, THREAT_SEVERE, SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Tile",                    CAT_TRACKER, COMPANY_TILE,     {0xEC,0xFE,0,0,0,0,0,0}, 2, -1, 0, THREAT_SEVERE,         SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Tile (Alt)",              CAT_TRACKER, COMPANY_TILE_ALT, {0xED,0xFE,0,0,0,0,0,0}, 2, -1, 0, THREAT_SEVERE,         SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},
    {"Chipolo",                 CAT_TRACKER, COMPANY_CHIPOLO,  {0x65,0xFE,0,0,0,0,0,0}, 2, -1, 0, THREAT_SEVERE,         SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE},

    // SMART GLASSES
    {"Meta Ray-Ban",            CAT_GLASSES, COMPANY_META,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Meta Ray-Ban (Tech)",     CAT_GLASSES, COMPANY_META_TECH, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Meta Ray-Ban (Luxottica)",CAT_GLASSES, COMPANY_LUXOTTICA, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Snap Spectacles",         CAT_GLASSES, COMPANY_SNAP,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Amazon Echo Frames",      CAT_GLASSES, COMPANY_AMAZON,    {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_HIGH,     SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Bose Frames",             CAT_GLASSES, COMPANY_BOSE,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_MEDIUM,   SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},

    // MEDICAL DEVICES
    {"Dexcom CGM",              CAT_MEDICAL, COMPANY_DEXCOM,    {0,0,0,0,0,0,0,0}, 0, -1, 0xFEBC, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Medtronic Device",        CAT_MEDICAL, COMPANY_MEDTRONIC, {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Omnipod",                 CAT_MEDICAL, COMPANY_INSULET,   {0,0,0,0,0,0,0,0}, 0, -1, 0x1830, THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Abbott FreeStyle",        CAT_MEDICAL, COMPANY_ABBOTT,    {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},

    // WEARABLES
    {"Fitbit",                  CAT_WEARABLE, COMPANY_FITBIT,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Garmin",                  CAT_WEARABLE, COMPANY_GARMIN,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},

    // AUDIO DEVICES
    {"Sony Audio",              CAT_AUDIO, COMPANY_SONY,        {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Bose Audio",              CAT_AUDIO, COMPANY_BOSE,        {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
};

#define BUILTIN_SIGNATURE_COUNT (sizeof(BUILTIN_SIGNATURES) / sizeof(device_signature_t))

#endif // SIGNATURES_H
