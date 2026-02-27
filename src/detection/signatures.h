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
// BUILT-IN SIGNATURES
// =============================================================================

// Bluetooth SIG Company Identifiers
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
#define COMPANY_TILE            0xFEEC  // Also 0xFEED
#define COMPANY_TILE_ALT        0xFEED
#define COMPANY_CHIPOLO         0xFE65

// Built-in signature definitions
static const device_signature_t BUILTIN_SIGNATURES[] = {
    // =========================================================================
    // TRACKERS
    // =========================================================================
    {
        .name = "AirTag (Registered)",
        .category = CAT_TRACKER,
        .company_id = COMPANY_APPLE,
        .payload_pattern = {0x4C, 0x00, 0x07, 0x19},
        .pattern_length = 4,
        .pattern_offset = 0,
        .service_uuid = 0,
        .threat_level = THREAT_SEVERE,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "AirTag (Unregistered)",
        .category = CAT_TRACKER,
        .company_id = COMPANY_APPLE,
        .payload_pattern = {0x4C, 0x00, 0x12, 0x19},
        .pattern_length = 4,
        .pattern_offset = 0,
        .service_uuid = 0,
        .threat_level = THREAT_SEVERE,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Samsung SmartTag",
        .category = CAT_TRACKER,
        .company_id = COMPANY_SAMSUNG,
        .payload_pattern = {0x75, 0x00, 0x42, 0x09, 0x01},
        .pattern_length = 5,
        .pattern_offset = 0,
        .service_uuid = 0,
        .threat_level = THREAT_SEVERE,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Samsung SmartTag2",
        .category = CAT_TRACKER,
        .company_id = COMPANY_SAMSUNG,
        .payload_pattern = {0x75, 0x00, 0x42, 0x09, 0x02},
        .pattern_length = 5,
        .pattern_offset = 0,
        .service_uuid = 0,
        .threat_level = THREAT_SEVERE,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Tile",
        .category = CAT_TRACKER,
        .company_id = COMPANY_TILE,
        .payload_pattern = {0xEC, 0xFE},
        .pattern_length = 2,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_SEVERE,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Tile (Alt)",
        .category = CAT_TRACKER,
        .company_id = COMPANY_TILE_ALT,
        .payload_pattern = {0xED, 0xFE},
        .pattern_length = 2,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_SEVERE,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Chipolo",
        .category = CAT_TRACKER,
        .company_id = COMPANY_CHIPOLO,
        .payload_pattern = {0x65, 0xFE},
        .pattern_length = 2,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_SEVERE,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_PAYLOAD | SIG_FLAG_TRANSMITTABLE
    },

    // =========================================================================
    // SMART GLASSES
    // =========================================================================
    {
        .name = "Meta Ray-Ban",
        .category = CAT_GLASSES,
        .company_id = COMPANY_META,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_CRITICAL,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Meta Ray-Ban (Tech)",
        .category = CAT_GLASSES,
        .company_id = COMPANY_META_TECH,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_CRITICAL,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Meta Ray-Ban (Luxottica)",
        .category = CAT_GLASSES,
        .company_id = COMPANY_LUXOTTICA,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_CRITICAL,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Snap Spectacles",
        .category = CAT_GLASSES,
        .company_id = COMPANY_SNAP,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_CRITICAL,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Amazon Echo Frames",
        .category = CAT_GLASSES,
        .company_id = COMPANY_AMAZON,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_HIGH,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE
    },
    {
        .name = "Bose Frames",
        .category = CAT_GLASSES,
        .company_id = COMPANY_BOSE,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_MEDIUM,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE
    },

    // =========================================================================
    // MEDICAL DEVICES
    // =========================================================================
    {
        .name = "Dexcom CGM",
        .category = CAT_MEDICAL,
        .company_id = COMPANY_DEXCOM,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0xFEBC,
        .threat_level = THREAT_MEDIUM,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL
    },
    {
        .name = "Medtronic Device",
        .category = CAT_MEDICAL,
        .company_id = COMPANY_MEDTRONIC,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_MEDIUM,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL
    },
    {
        .name = "Omnipod",
        .category = CAT_MEDICAL,
        .company_id = COMPANY_INSULET,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0x1830,
        .threat_level = THREAT_MEDIUM,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL
    },
    {
        .name = "Abbott FreeStyle",
        .category = CAT_MEDICAL,
        .company_id = COMPANY_ABBOTT,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_MEDIUM,
        .flags = SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL
    },

    // =========================================================================
    // WEARABLES
    // =========================================================================
    {
        .name = "Fitbit",
        .category = CAT_WEARABLE,
        .company_id = COMPANY_FITBIT,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_LOW,
        .flags = SIG_FLAG_COMPANY_ID
    },
    {
        .name = "Garmin",
        .category = CAT_WEARABLE,
        .company_id = COMPANY_GARMIN,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_LOW,
        .flags = SIG_FLAG_COMPANY_ID
    },

    // =========================================================================
    // AUDIO DEVICES
    // =========================================================================
    {
        .name = "Sony Audio",
        .category = CAT_AUDIO,
        .company_id = COMPANY_SONY,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_LOW,
        .flags = SIG_FLAG_COMPANY_ID
    },
    {
        .name = "Bose Audio",
        .category = CAT_AUDIO,
        .company_id = COMPANY_BOSE,
        .payload_pattern = {0},
        .pattern_length = 0,
        .pattern_offset = -1,
        .service_uuid = 0,
        .threat_level = THREAT_LOW,
        .flags = SIG_FLAG_COMPANY_ID
    },
};

#define BUILTIN_SIGNATURE_COUNT (sizeof(BUILTIN_SIGNATURES) / sizeof(device_signature_t))

#endif // SIGNATURES_H
