// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "core/hle/service/gsp_lcd.h"

namespace Service {
namespace GSP {

const Interface::FunctionInfo FunctionTable[] = {
    // clang-format off
    {0x000A0080, nullptr, "SetBrightnessRaw"},
    {0x000B0080, nullptr, "SetBrightness"},
    {0x000F0000, nullptr, "PowerOnAllBacklights"},
    {0x00100000, nullptr, "PowerOffAllBacklights"},
    {0x00110040, nullptr, "PowerOnBacklight"},
    {0x00120040, nullptr, "PowerOffBacklight"},
    {0x00130040, nullptr, "SetLedForceOff"},
    {0x00140000, nullptr, "GetVendor"},
    {0x00150040, nullptr, "GetBrightness"},
    // clang-format on
};

GSP_LCD::GSP_LCD() {
    Register(FunctionTable);
}

} // namespace GSP
} // namespace Service
