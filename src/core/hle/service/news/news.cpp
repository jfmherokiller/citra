// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "common/logging/log.h"
#include "core/hle/service/news/news.h"
#include "core/hle/service/news/news_s.h"
#include "core/hle/service/news/news_u.h"
#include "core/hle/service/service.h"

namespace Service {
namespace NEWS {

void Init() {
    using namespace Kernel;

    AddService(new NEWS_S_Interface);
    AddService(new NEWS_U_Interface);
}

void Shutdown() {}

} // namespace NEWS

} // namespace Service
