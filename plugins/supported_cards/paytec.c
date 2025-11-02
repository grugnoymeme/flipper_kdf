#include "nfc_supported_card_plugin.h"
#include <flipper_application.h>
#include <nfc/protocols/mf_classic/mf_classic_poller_sync.h>
#include <bit_lib.h>

#define TAG "PayTec"
#define KEY_LENGTH 6
#define UID_LENGTH 4

typedef struct {
    uint64_t a;
    uint64_t b;
} MfClassicKeyPair;

static MfClassicKeyPair paytec_1k_keys[] = {
    {.a = 0xA0A1A2A3A4A5, .b = 0xDA95DEF51953}, // 000
    {.a = 0xA0A1A2A3A4A5, .b = 0xDA95DEF51953}, // 001
    {.a = 0xFFFF55FFFFAA, .b = 0xABD4557BB1AA}, // 002
    {.a = 0xFFFF55FFFFAA, .b = 0xABD4557BB1AA}, // 003
    {.a = 0xFFFF55FFFFAA, .b = 0x635255FFFFAA}, // 004
    {.a = 0xFFFF55FFFFAA, .b = 0x635255FFFFAA}, // 005
    {.a = 0xFFFF55FFFFAA, .b = 0xCA7D55FFFFAA}, // 006
    {.a = 0xFFFF55FFFFAA, .b = 0xCA7D55FFFFAA}, // 007
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 008
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 009
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 010
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 011
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 012
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 013
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 014
    {.a = 0xffffffffffff, .b = 0xffffffffffff}, // 015
};

const uint8_t verify_sector = 2;

static uint8_t paytec_calculate_crc(uint16_t value, bool is_left_position) {
    static const char* table[16] = {
        "541", "540", "532", "531", "530", "521", "520", "510",
        "432", "431", "430", "421", "420", "410", "321", "320"
    };
    
    char concatenated[256] = {0};
    int concat_len = 0;
    
    for(int i = 0; i < 16; i++) {
        if(value & (1 << i)) {
            const char* table_value = table[i];
            int table_len = strlen(table_value);
            
            memmove(concatenated + table_len, concatenated, concat_len);
            memcpy(concatenated, table_value, table_len);
            concat_len += table_len;
        }
    }
    
    int digit_count[6] = {0};
    for(int i = 0; i < concat_len; i++) {
        int digit = concatenated[i] - '0';
        if(digit >= 0 && digit <= 5) {
            digit_count[digit]++;
        }
    }
    
    uint8_t result_bits = 0;
    for(int digit = 0; digit <= 5; digit++) {
        if(digit_count[digit] % 2 == 1) {
            result_bits |= (1 << digit);
        }
    }
    
    uint8_t direction_bits = is_left_position ? 0x01 : 0x02;
    uint8_t crc = (direction_bits << 6) | result_bits;
    
    return crc;
}

static bool paytec_get_credit_position(const uint8_t* block8_data, bool* is_left) {
    uint16_t left_value = (block8_data[0] << 8) | block8_data[1];
    uint16_t right_value = (block8_data[2] << 8) | block8_data[3];
    uint8_t stored_crc = block8_data[4];
    
    uint8_t crc_left = paytec_calculate_crc(left_value, true);
    uint8_t crc_right = paytec_calculate_crc(right_value, false);
    
    if(stored_crc == crc_left) {
        *is_left = true;
        return true;
    } else if(stored_crc == crc_right) {
        *is_left = false;
        return true;
    }
    
    return false;
}

static bool paytec_read(Nfc* nfc, NfcDevice* device) {
    FURI_LOG_D(TAG, "Entering PayTec MFC read");

    furi_assert(nfc);
    furi_assert(device);

    bool is_read = false;

    MfClassicData* data = mf_classic_alloc();
    nfc_device_copy_data(device, NfcProtocolMfClassic, data);

    do {
        MfClassicType type = MfClassicType1k;
        MfClassicError error = mf_classic_poller_sync_detect_type(nfc, &type);
        if(error != MfClassicErrorNone) break;

        size_t uid_len;
        const uint8_t* uid = mf_classic_get_uid(data, &uid_len);
        FURI_LOG_D(TAG, "UID identified: %02X%02X%02X%02X", uid[0], uid[1], uid[2], uid[3]);
        if(uid_len != UID_LENGTH) break;

        MfClassicKey key = {0};
        bit_lib_num_to_bytes_be(
            paytec_1k_keys[verify_sector].a, COUNT_OF(key.data), key.data);
        const uint8_t block_num = mf_classic_get_first_block_num_of_sector(verify_sector);
        MfClassicAuthContext auth_context;
        error = mf_classic_poller_sync_auth(nfc, block_num, &key, MfClassicKeyTypeA, &auth_context);
        if(error != MfClassicErrorNone) {
            FURI_LOG_D(TAG, "Not a PayTec tag - auth failed");
            break;
        }

        MfClassicDeviceKeys keys = {};
        for(size_t i = 0; i < mf_classic_get_total_sectors_num(data->type); i++) {
            bit_lib_num_to_bytes_be(
                paytec_1k_keys[i].a, sizeof(MfClassicKey), keys.key_a[i].data);
            FURI_BIT_SET(keys.key_a_mask, i);
            bit_lib_num_to_bytes_be(
                paytec_1k_keys[i].b, sizeof(MfClassicKey), keys.key_b[i].data);
            FURI_BIT_SET(keys.key_b_mask, i);
        }

        error = mf_classic_poller_sync_read(nfc, &keys, data);
        if(error == MfClassicErrorNotPresent) {
            FURI_LOG_W(TAG, "Failed to read data");
            break;
        }

        nfc_device_set_data(device, NfcProtocolMfClassic, data);
        is_read = (error == MfClassicErrorNone);
        
    } while(false);

    mf_classic_free(data);
    return is_read;
}

static bool paytec_parse(const NfcDevice* device, FuriString* parsed_data) {
    furi_assert(device);
    furi_assert(parsed_data);

    const MfClassicData* data = nfc_device_get_data(device, NfcProtocolMfClassic);
    bool parsed = false;

    do {
        size_t uid_len;
        const uint8_t* uid = mf_classic_get_uid(data, &uid_len);
        if(uid_len != UID_LENGTH) break;

        MfClassicSectorTrailer* sec_tr = mf_classic_get_sector_trailer_by_sector(data, verify_sector);
        uint64_t key = bit_lib_bytes_to_num_be(sec_tr->key_a.data, 6);
        if(key != paytec_1k_keys[verify_sector].a) break;

        furi_string_cat_printf(parsed_data, "\e#PayTec MFC\n");
        furi_string_cat_printf(parsed_data, "(Mifare Classic 1k)\n");
        furi_string_cat_printf(parsed_data, "====================\n");

        furi_string_cat_printf(parsed_data, "UID:");
        for(size_t i = 0; i < UID_LENGTH; i++) {
            furi_string_cat_printf(parsed_data, " %02X", uid[i]);
        }
        furi_string_cat_printf(parsed_data, "\n");

        uint8_t atqa_lsb = data->block[0].data[6];
        uint8_t atqa_msb = data->block[0].data[7];
        uint8_t sak = data->block[0].data[5];
        furi_string_cat_printf(parsed_data, "ATQA: %02X %02X ~ SAK: %02X\n", atqa_msb, atqa_lsb, sak);
        
        furi_string_cat_printf(parsed_data, "--------------------\n");

        const uint8_t* block8_data = data->block[8].data;
        
        bool is_current_left = false;
        if(!paytec_get_credit_position(block8_data, &is_current_left)) {
            furi_string_cat_printf(parsed_data, "Error: Invalid CRC\n");
            break;
        }

        uint16_t current_credit, previous_credit;
        if(is_current_left) {
            current_credit = (block8_data[0] << 8) | block8_data[1];
            previous_credit = (block8_data[2] << 8) | block8_data[3];
        } else {
            current_credit = (block8_data[2] << 8) | block8_data[3];
            previous_credit = (block8_data[0] << 8) | block8_data[1];
        }

        const uint8_t* block14_data = data->block[14].data;
        uint16_t second_previous_credit;
        if(is_current_left) {
            second_previous_credit = (block14_data[0] << 8) | block14_data[1];
        } else {
            second_previous_credit = (block14_data[2] << 8) | block14_data[3];
        }

        furi_string_cat_printf(
            parsed_data, 
            "-> Available Credit: %d.%02d\n", 
            current_credit / 100, 
            current_credit % 100);
        
        furi_string_cat_printf(
            parsed_data, 
            "-> Previous Credit: %d.%02d\n", 
            previous_credit / 100, 
            previous_credit % 100);
        
        furi_string_cat_printf(
            parsed_data, 
            "-> 2nd Previous Credit: %d.%02d\n", 
            second_previous_credit / 100, 
            second_previous_credit % 100);

        furi_string_cat_printf(parsed_data, "--------------------\n");

        uint8_t stored_crc = block8_data[4];
        furi_string_cat_printf(
            parsed_data, 
            "CRC: 0x%02X (pos: %s)\n", 
            stored_crc, 
            is_current_left ? "Left" : "Right");

        parsed = true;
    } while(false);

    return parsed;
}

static const NfcSupportedCardsPlugin paytec_plugin = {
    .protocol = NfcProtocolMfClassic,
    .verify = NULL,
    .read = paytec_read,
    .parse = paytec_parse,
};

static const FlipperAppPluginDescriptor paytec_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &paytec_plugin,
};

const FlipperAppPluginDescriptor* paytec_plugin_ep(void) {
    return &paytec_plugin_descriptor;
}
