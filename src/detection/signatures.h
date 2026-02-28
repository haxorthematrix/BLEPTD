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
// Source: https://www.bluetooth.com/specifications/assigned-numbers/
// =============================================================================
// Major Tech Companies
#define COMPANY_APPLE           0x004C
#define COMPANY_SAMSUNG         0x0075
#define COMPANY_MICROSOFT       0x0006
#define COMPANY_GOOGLE          0x00E0
#define COMPANY_AMAZON          0x0171
#define COMPANY_META            0x01AB
#define COMPANY_META_TECH       0x058E
#define COMPANY_SONY            0x012D
#define COMPANY_HUAWEI          0x027D

// Tracker Companies
#define COMPANY_TILE            0xFEEC
#define COMPANY_TILE_ALT        0xFEED
#define COMPANY_CHIPOLO         0xFE65
#define COMPANY_PEBBLEBEE       0x0822  // Note: shares with Insulet
#define COMPANY_EUFY            0x0757
#define COMPANY_CUBE            0x0843

// Smart Glasses / AR
#define COMPANY_SNAP            0x03C2
#define COMPANY_LUXOTTICA       0x0D53
#define COMPANY_VUZIX           0x077A
#define COMPANY_NORTH           0x0810  // Focals by North (Google)
#define COMPANY_NREAL           0x0A14
#define COMPANY_XREAL           0x0A14  // Formerly Nreal
#define COMPANY_TCLTV           0x0992  // TCL RayNeo

// Audio
#define COMPANY_BOSE            0x009E
#define COMPANY_JABRA           0x0067
#define COMPANY_PLANTRONICS     0x0055
#define COMPANY_BEATS           0x004C  // Uses Apple's ID
#define COMPANY_JBL             0x0057
#define COMPANY_SKULLCANDY      0x02A0
#define COMPANY_BANG_OLUFSEN    0x0059

// Wearables
#define COMPANY_FITBIT          0x0224
#define COMPANY_GARMIN          0x0087
#define COMPANY_WHOOP           0x0643
#define COMPANY_OURA            0x0781
#define COMPANY_POLAR           0x006B
#define COMPANY_SUUNTO          0x0068
#define COMPANY_XIAOMI          0x038F
#define COMPANY_AMAZFIT         0x0157

// Medical - Diabetes (CGM & Pumps)
#define COMPANY_DEXCOM          0x00D1
#define COMPANY_MEDTRONIC       0x02A5
#define COMPANY_ABBOTT          0x0618
#define COMPANY_INSULET         0x0822  // Omnipod
#define COMPANY_TANDEM          0x0801  // t:slim insulin pumps
#define COMPANY_SENSEONICS      0x07E1  // Eversense CGM
#define COMPANY_ASCENSIA        0x0702  // Contour glucose meters
#define COMPANY_ROCHE           0x0077  // Accu-Chek
#define COMPANY_YPSOMED         0x08B4  // YpsoPump
#define COMPANY_BIGFOOT         0x093B  // Bigfoot Biomedical
#define COMPANY_BETA_BIONICS    0x0964  // iLet Bionic Pancreas
#define COMPANY_LIFESCAN        0x03F0  // OneTouch

// Medical - Cardiac
#define COMPANY_BIOTRONIK       0x00A3
#define COMPANY_BOSTON_SCI      0x0149  // Boston Scientific
#define COMPANY_ST_JUDE         0x0102  // Abbott (formerly St. Jude)
#define COMPANY_ZOLL            0x0571
#define COMPANY_ALIVECOR        0x041B  // KardiaMobile

// Medical - Respiratory / Sleep
#define COMPANY_RESMED          0x02B5
#define COMPANY_PHILIPS_MED     0x0030
#define COMPANY_WITHINGS        0x05E3

// Medical - Other
#define COMPANY_OMRON           0x020E
#define COMPANY_QARDIO          0x0415
#define COMPANY_IHEALTH         0x02C1

// Other / Misc
#define COMPANY_RAZER           0x0532
#define COMPANY_LOGITECH        0x0046
#define COMPANY_GOPRO           0x0301

// =============================================================================
// BUILT-IN SIGNATURES
// Format: {name, category, company_id, {pattern[8]}, pattern_len, offset, svc_uuid, threat, flags}
// =============================================================================
static const device_signature_t BUILTIN_SIGNATURES[] = {
    // =========================================================================
    // TRACKERS - High privacy threat, can be used for stalking
    // =========================================================================
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

    // =========================================================================
    // SMART GLASSES - Critical privacy threat, cameras/microphones
    // =========================================================================
    {"Meta Ray-Ban",            CAT_GLASSES, COMPANY_META,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Meta Ray-Ban (Tech)",     CAT_GLASSES, COMPANY_META_TECH, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Meta Ray-Ban (Luxottica)",CAT_GLASSES, COMPANY_LUXOTTICA, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Snap Spectacles",         CAT_GLASSES, COMPANY_SNAP,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Amazon Echo Frames",      CAT_GLASSES, COMPANY_AMAZON,    {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_HIGH,     SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Bose Frames",             CAT_GLASSES, COMPANY_BOSE,      {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_MEDIUM,   SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"Vuzix Blade",             CAT_GLASSES, COMPANY_VUZIX,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_CRITICAL, SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"XREAL Air",               CAT_GLASSES, COMPANY_XREAL,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_HIGH,     SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},
    {"TCL RayNeo",              CAT_GLASSES, COMPANY_TCLTV,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_HIGH,     SIG_FLAG_COMPANY_ID | SIG_FLAG_TRANSMITTABLE},

    // =========================================================================
    // MEDICAL DEVICES - Diabetes (CGM, Insulin Pumps)
    // =========================================================================
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

    // =========================================================================
    // MEDICAL DEVICES - Cardiac
    // =========================================================================
    {"Biotronik Cardiac",       CAT_MEDICAL, COMPANY_BIOTRONIK, {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Boston Scientific",       CAT_MEDICAL, COMPANY_BOSTON_SCI,{0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"AliveCor Kardia",         CAT_MEDICAL, COMPANY_ALIVECOR,  {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Zoll LifeVest",           CAT_MEDICAL, COMPANY_ZOLL,      {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},

    // =========================================================================
    // MEDICAL DEVICES - Respiratory / Sleep / Other
    // =========================================================================
    {"ResMed CPAP",             CAT_MEDICAL, COMPANY_RESMED,    {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Philips CPAP",            CAT_MEDICAL, COMPANY_PHILIPS_MED,{0,0,0,0,0,0,0,0}, 0, -1, 0,     THREAT_MEDIUM, SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Withings Health",         CAT_MEDICAL, COMPANY_WITHINGS,  {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"Omron BP Monitor",        CAT_MEDICAL, COMPANY_OMRON,     {0,0,0,0,0,0,0,0}, 0, -1, 0x1810, THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_SERVICE_UUID | SIG_FLAG_MEDICAL},
    {"Qardio Heart Health",     CAT_MEDICAL, COMPANY_QARDIO,    {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},
    {"iHealth Devices",         CAT_MEDICAL, COMPANY_IHEALTH,   {0,0,0,0,0,0,0,0}, 0, -1, 0,      THREAT_LOW,    SIG_FLAG_COMPANY_ID | SIG_FLAG_MEDICAL},

    // =========================================================================
    // WEARABLES - Fitness trackers and smartwatches
    // =========================================================================
    {"Fitbit",                  CAT_WEARABLE, COMPANY_FITBIT,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Garmin Watch",            CAT_WEARABLE, COMPANY_GARMIN,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Whoop Band",              CAT_WEARABLE, COMPANY_WHOOP,    {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Oura Ring",               CAT_WEARABLE, COMPANY_OURA,     {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Polar Watch",             CAT_WEARABLE, COMPANY_POLAR,    {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Suunto Watch",            CAT_WEARABLE, COMPANY_SUUNTO,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Xiaomi Mi Band",          CAT_WEARABLE, COMPANY_XIAOMI,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Amazfit Watch",           CAT_WEARABLE, COMPANY_AMAZFIT,  {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Huawei Watch",            CAT_WEARABLE, COMPANY_HUAWEI,   {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},

    // =========================================================================
    // AUDIO DEVICES
    // =========================================================================
    {"Sony Audio",              CAT_AUDIO, COMPANY_SONY,        {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Bose Audio",              CAT_AUDIO, COMPANY_BOSE,        {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Jabra Headset",           CAT_AUDIO, COMPANY_JABRA,       {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"JBL Audio",               CAT_AUDIO, COMPANY_JBL,         {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Plantronics",             CAT_AUDIO, COMPANY_PLANTRONICS, {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Skullcandy",              CAT_AUDIO, COMPANY_SKULLCANDY,  {0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
    {"Bang & Olufsen",          CAT_AUDIO, COMPANY_BANG_OLUFSEN,{0,0,0,0,0,0,0,0}, 0, -1, 0, THREAT_LOW, SIG_FLAG_COMPANY_ID},
};

#define BUILTIN_SIGNATURE_COUNT (sizeof(BUILTIN_SIGNATURES) / sizeof(device_signature_t))

#endif // SIGNATURES_H
