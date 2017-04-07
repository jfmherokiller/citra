// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included..

#pragma once

#include "core/hle/service/service.h"

namespace Service {
namespace AM {

class AM_APP_Interface : public Service::Interface {
public:
    AM_APP_Interface();

    std::string GetPortName() const override {
        return "am:app";
    }
};

} // namespace AM
} // namespace Service
