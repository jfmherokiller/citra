// Copyright 2014 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <common/logging/log.h>
#include "ncsd.h"
namespace Loader {
FileType AppLoader_NCSD::IdentifyType(FileUtil::IOFile& file) {
    u32 magic;
    file.Seek(0x100, SEEK_SET);
    if (file.ReadArray<u32>(&magic, 1) != 1)
        return FileType::Error;

    if (MakeMagic('N', 'C', 'S', 'D') == magic)
        return FileType::CCI;

    return FileType::Error;
}
ResultStatus AppLoader_NCSD::LoadExeFS() {
    // Reset read pointer in case this file has been read before.
    file.Seek(0, SEEK_SET);

    if (file.ReadBytes(&ncch_header, sizeof(NCCH_Header)) != sizeof(NCCH_Header))
        return ResultStatus::Error;

    // Skip NCSD header and load first NCCH (NCSD is just a container of NCCH files)...
    if (ncch_header.magic == MakeMagic('N', 'C', 'S', 'D')) {
        LOG_DEBUG(Loader, "Only loading the first (bootable) NCCH within the NCSD file!");
        ncch_offset = 0x4000;
        file.Seek(ncch_offset, SEEK_SET);
        file.ReadBytes(&ncch_header, sizeof(NCCH_Header));
    }
    return AppLoader_NCCH::LoadExeFS();
}
}