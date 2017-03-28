// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <common/logging/log.h>
#include "core/loader/ncsd.h"

namespace Loader {
FileType AppLoader_NCSD::IdentifyType(FileUtil::IOFile& file) {
    u32 magic;
    file.Seek(0x100, SEEK_SET);
    if (file.ReadArray<u32>(&magic, 1) != 1)
        return FileType::Error;

    if (magic == MakeMagic('N', 'C', 'S', 'D'))
        return FileType::CCI;

    return FileType::Error;
}
ResultStatus AppLoader_NCSD::TryGetNCCHOffset(u32& offset) {
    // Reset read pointer in case this file has been read before.
    file.Seek(0, SEEK_SET);

    NCSD_Header ncsd_header;
    if (file.ReadBytes(&ncsd_header, sizeof(NCSD_Header)) != sizeof(NCSD_Header))
        return ResultStatus::Error;
    LOG_DEBUG(Loader, "Only loading the first (bootable) NCCH within the NCSD file!");
    offset = ncsd_header.partition_table[0].partition_offset * 0x200;
    return ResultStatus::Success;
}

ResultStatus AppLoader_NCSD::Load() {
    return ncch_loader->Load();
}
boost::optional<u32> AppLoader_NCSD::LoadKernelSystemMode() {
    return ncch_loader->LoadKernelSystemMode();
}
ResultStatus AppLoader_NCSD::ReadCode(std::vector<u8>& buffer) {
    return ncch_loader->ReadCode(buffer);
}
ResultStatus AppLoader_NCSD::ReadBanner(std::vector<u8>& buffer) {
    return ncch_loader->ReadBanner(buffer);
}
ResultStatus AppLoader_NCSD::ReadLogo(std::vector<u8>& buffer) {
    return ncch_loader->ReadLogo(buffer);
}
ResultStatus AppLoader_NCSD::ReadIcon(std::vector<u8>& buffer) {
    return ncch_loader->ReadIcon(buffer);
}
ResultStatus AppLoader_NCSD::ReadProgramId(u64& out_program_id) {
    return ncch_loader->ReadProgramId(out_program_id);
}
ResultStatus AppLoader_NCSD::ReadRomFS(std::shared_ptr<FileUtil::IOFile>& romfs_file, u64& offset,
                                       u64& size) {
    return ncch_loader->ReadRomFS(romfs_file, offset, size);
}
AppLoader_NCSD::AppLoader_NCSD(FileUtil::IOFile&& file, const std::string& filepath)
    : AppLoader(std::move(file)), filepath(filepath) {
    u32 tempoffset;
    if (TryGetNCCHOffset(tempoffset) == ResultStatus::Success) {
        ncch_loader =
            new AppLoader_NCCH(std::move(FileUtil::IOFile(filepath, "rb")), filepath, tempoffset);
    } else {
        ncch_loader = new AppLoader_NCCH(std::move(FileUtil::IOFile(filepath, "rb")), filepath, 0);
    }
}

} // namespace Loader
