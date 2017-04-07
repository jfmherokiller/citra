// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included..

#pragma once

#include "core/hle/service/service.h"

namespace Service {
namespace NIM {

class NIM_AOC_Interface : public Service::Interface {
public:
    NIM_AOC_Interface();

    std::string GetPortName() const override {
        return "nim:aoc";
    }
};

} // namespace NIM
} // namespace Service
