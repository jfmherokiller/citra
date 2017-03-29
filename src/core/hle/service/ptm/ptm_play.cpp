// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "core/hle/service/ptm/ptm.h"
#include "core/hle/service/ptm/ptm_play.h"

namespace Service {
namespace PTM {

const Interface::FunctionInfo FunctionTable[] = {
    // ptm:u common commands
    {0x00010002, nullptr, "RegisterAlarmClient"},
    {0x00020080, nullptr, "SetRtcAlarm"},
    {0x00030000, nullptr, "GetRtcAlarm"},
    {0x00040000, nullptr, "CancelRtcAlarm"},
    {0x00050000, GetAdapterState, "GetAdapterState"},
    {0x00060000, GetShellState, "GetShellState"},
    {0x00070000, GetBatteryLevel, "GetBatteryLevel"},
    {0x00080000, GetBatteryChargeState, "GetBatteryChargeState"},
    {0x00090000, nullptr, "GetPedometerState"},
    {0x000A0042, nullptr, "GetStepHistoryEntry"},
    {0x000B00C2, nullptr, "GetStepHistory"},
    {0x000C0000, GetTotalStepCount, "GetTotalStepCount"},
    {0x000D0040, nullptr, "SetPedometerRecordingMode"},
    {0x000E0000, nullptr, "GetPedometerRecordingMode"},
    {0x000F0084, nullptr, "GetStepHistoryAll"},
    // ptm:play
    {0x08070082, nullptr, "GetPlayHistory"},
    {0x08080000, nullptr, "GetPlayHistoryStart"},
    {0x08090000, nullptr, "GetPlayHistoryLength"},
    {0x080B0080, nullptr, "CalcPlayHistoryStart"},
};

PTM_Play::PTM_Play() {
    Register(FunctionTable);
}

} // namespace PTM
} // namespace Service