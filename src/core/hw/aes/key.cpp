// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <exception>
#include <sstream>
#include <boost/optional.hpp>
#include "common/common_paths.h"
#include "common/file_util.h"
#include "common/logging/log.h"
#include "common/string_util.h"
#include "core/hw/aes/arithmetic128.h"
#include "core/hw/aes/key.h"

namespace HW {
namespace AES {

namespace {

boost::optional<AESKey> generator_constant;

struct KeySlot {
    boost::optional<AESKey> x;
    boost::optional<AESKey> y;
    boost::optional<AESKey> normal;

    void SetKeyX(const AESKey& key) {
        x = key;
        if (y && generator_constant) {
            GenerateNormalKey();
        }
    }

    void SetKeyY(const AESKey& key) {
        y = key;
        if (x && generator_constant) {
            GenerateNormalKey();
        }
    }

    void SetNormalKey(const AESKey& key) {
        normal = key;
    }

    void GenerateNormalKey() {
        normal = Lrot128(Add128(Xor128(Lrot128(*x, 2), *y), *generator_constant), 87);
    }

    void Clear() {
        x.reset();
        y.reset();
        normal.reset();
    }
};

std::array<KeySlot, KeySlotID::MaxKeySlotID> key_slots;

void ClearAllKeys() {
    for (KeySlot& slot : key_slots) {
        slot.Clear();
    }
    generator_constant.reset();
}

AESKey HexToKey(const std::string& hex) {
    if (hex.size() < 32) {
        throw std::invalid_argument("hex string is too short");
    }

    AESKey key;
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<u8>(std::stoi(hex.substr(i * 2, 2), 0, 16));
    }

    return key;
}

void SetKeySlot(const AESKey& key, size_t slot_id, char key_type) {
    switch (key_type) {
    case 'X':
        if (!key_slots.at(slot_id).x.is_initialized()) {
            SetKeyX(slot_id, key);
        }
        break;
    case 'Y':
        if (!key_slots.at(slot_id).y.is_initialized()) {
            SetKeyY(slot_id, key);
        }
        break;
    case 'N':
        if (!key_slots.at(slot_id).normal.is_initialized()) {
            SetNormalKey(slot_id, key);
        }
        break;
    default:
        LOG_ERROR(HW_AES, "Invalid key type %c", key_type);
        break;
    }
}

void LoadKeysFromText() {
    const std::string filepath = FileUtil::GetUserPath(D_SYSDATA_IDX) + AES_KEYS;
    FileUtil::CreateFullPath(filepath); // Create path if not already created
    std::ifstream file;
    OpenFStream(file, filepath, std::ios_base::in);
    if (!file) {
        return;
    }

    while (!file.eof()) {
        std::string line;
        std::getline(file, line);
        std::vector<std::string> parts;
        Common::SplitString(line, '=', parts);
        if (parts.size() != 2) {
            LOG_ERROR(HW_AES, "Failed to parse %s", line.c_str());
            continue;
        }

        const std::string& name = parts[0];
        AESKey key;
        try {
            key = HexToKey(parts[1]);
        } catch (const std::logic_error& e) {
            LOG_ERROR(HW_AES, "Invalid key %s: %s", parts[1].c_str(), e.what());
            continue;
        }

        if (name == "generator") {
            generator_constant = key;
            continue;
        }

        size_t slot_id;
        char key_type;
        if (std::sscanf(name.c_str(), "slot0x%zXKey%c", &slot_id, &key_type) != 2) {
            LOG_ERROR(HW_AES, "Invalid key name %s", name.c_str());
            continue;
        }

        if (slot_id >= MaxKeySlotID) {
            LOG_ERROR(HW_AES, "Out of range slot ID 0x%zX", slot_id);
            continue;
        }

        SetKeySlot(key, slot_id, key_type);
    }
}
/**
 * This is used to load the aeskeydb.bin file from the sysdata directory.
 * This file comes from Decrypt9 and can be built using the Build Key Database option.
 * It requires bin files containing the key data following the format slot0x??key?.bin.
 * The wiki describes that this database can be encrypted or decrypted however as of right now only
 * the decrypted format is supported.
 */
void LoadKeysFromDB() {
    // aeskeydb.bin struct taken from https://git.io/vyzHF
    struct AesKeyInfo {
        u8 slot;                 // keyslot, 0x00...0x3F
        char type;               // type 'X' / 'Y' / 'N' for normalKey
        std::array<char, 10> id; // key ID for special keys, all zero for standard keys
        u8 reserved[2];          // reserved space
        u8 is_devkitkey;         // 0 for retail units / 1 for DevKit units
        u8 is_encrypted;         // 0 if not / anything else if it is
        AESKey key;
    };

    const std::string filepath = FileUtil::GetUserPath(D_SYSDATA_IDX) + AES_KEYS_DB;
    // Create path if not already created
    FileUtil::CreateFullPath(filepath);
    auto file = FileUtil::IOFile(filepath, "r");

    if (!file) {
        return;
    }
    AesKeyInfo key_info;
    while (file.IsGood()) {
        file.ReadArray(&key_info, 1);

        if (key_info.slot >= MaxKeySlotID) {
            LOG_ERROR(HW_AES, "Out of range slot ID 0x%zX", key_info.slot);
            continue;
        }
        if (key_info.is_encrypted) {
            LOG_ERROR(HW_AES, "Key with slot ID 0x%zX is encrypted", key_info.slot);
            continue;
        }
        if (key_info.id[0] != 0x00) {
            LOG_WARNING(HW_AES, "Key with slot ID 0x%zX is a special key, ignoring", key_info.slot);
            continue;
        }
        SetKeySlot(key_info.key, key_info.slot, key_info.type);
    }
}
void LoadPresetKeys() {
    LoadKeysFromText();
    LoadKeysFromDB();
}

} // namespace

void InitKeys() {
    ClearAllKeys();
    LoadPresetKeys();
}

void SetGeneratorConstant(const AESKey& key) {
    generator_constant = key;
}

void SetKeyX(size_t slot_id, const AESKey& key) {
    key_slots.at(slot_id).SetKeyX(key);
}

void SetKeyY(size_t slot_id, const AESKey& key) {
    key_slots.at(slot_id).SetKeyY(key);
}

void SetNormalKey(size_t slot_id, const AESKey& key) {
    key_slots.at(slot_id).SetNormalKey(key);
}

bool IsNormalKeyAvailable(size_t slot_id) {
    return key_slots.at(slot_id).normal.is_initialized();
}

AESKey GetNormalKey(size_t slot_id) {
    return key_slots.at(slot_id).normal.value_or(AESKey{});
}

} // namespace AES
} // namespace HW
