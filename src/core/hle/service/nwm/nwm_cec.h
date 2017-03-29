// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include "core/hle/service/service.h"

namespace Service {
namespace NWM {

class NWM_CEC final : public Interface {
public:
    NWM_CEC();

    std::string GetPortName() const override {
        return "nwm::CEC";
    }
};

} // namespace NWM
} // namespace Service
