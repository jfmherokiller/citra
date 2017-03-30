// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <common/alignment.h>
#include <common/logging/log.h>
#include "cia.h"
#include "loader.h"

namespace Loader {
static u32 FindNCCHOffsetInCIA(FileUtil::IOFile& file) {
    // Reset read pointer in case this file has been read before.
    file.Seek(0, SEEK_SET);
    CIAHeader cia_header;

    file.ReadBytes(&cia_header, sizeof(CIAHeader));
    u32 certs_offset = Common::AlignUp(cia_header.header_size, 64);
    u32 tik_offset = Common::AlignUp(certs_offset + cia_header.cert_size, 64);
    u32 tmd_offset = Common::AlignUp(tik_offset + cia_header.ticket_size, 64);
    u32 content_offset = Common::AlignUp(tmd_offset + cia_header.tmd_size, 64);
    return content_offset;
}
static bool IsValidCia(FileUtil::IOFile& file) {
    // Reset read pointer in case this file has been read before.
    file.Seek(0, SEEK_SET);
    NCCH_Header ncch_header;
    bool is_valid = false;
    u32 offset = FindNCCHOffsetInCIA(file);
    file.Seek(offset, SEEK_SET);
    file.ReadBytes(&ncch_header, sizeof(NCCH_Header));
    if (MakeMagic('N', 'C', 'C', 'H') == ncch_header.magic) {
        is_valid = true;
    }

    return is_valid;
}
ResultStatus AppLoader_CIA::TryGetNCCHOffset(u32& offset) {
    if (IsValidCia(file)) {
        offset = FindNCCHOffsetInCIA(file);
        return ResultStatus::Success;
    }
    return ResultStatus::Error;
}
ResultStatus AppLoader_CIA::Load() {
    return ncch_loader->Load();
}
boost::optional<u32> AppLoader_CIA::LoadKernelSystemMode() {
    return ncch_loader->LoadKernelSystemMode();
}
ResultStatus AppLoader_CIA::ReadCode(std::vector<u8>& buffer) {
    return ncch_loader->ReadCode(buffer);
}
ResultStatus AppLoader_CIA::ReadBanner(std::vector<u8>& buffer) {
    return ncch_loader->ReadBanner(buffer);
}
ResultStatus AppLoader_CIA::ReadLogo(std::vector<u8>& buffer) {
    return ncch_loader->ReadLogo(buffer);
}
ResultStatus AppLoader_CIA::ReadIcon(std::vector<u8>& buffer) {
    return ncch_loader->ReadIcon(buffer);
}
ResultStatus AppLoader_CIA::ReadProgramId(u64& out_program_id) {
    return ncch_loader->ReadProgramId(out_program_id);
}
ResultStatus AppLoader_CIA::ReadRomFS(std::shared_ptr<FileUtil::IOFile>& romfs_file, u64& offset,
                                      u64& size) {
    return ncch_loader->ReadRomFS(romfs_file, offset, size);
}
FileType AppLoader_CIA::IdentifyType(FileUtil::IOFile& file) {
    if (IsValidCia(file)) {
        return FileType::CIA;
    }
    return FileType::Error;
}
AppLoader_CIA::AppLoader_CIA(FileUtil::IOFile&& file, const std::string& filepath)
    : AppLoader(std::move(file)) {
    u32 tempoffset;
    if (TryGetNCCHOffset(tempoffset) == ResultStatus::Success) {
        ncch_loader =
            new AppLoader_NCCH(std::move(FileUtil::IOFile(filepath, "rb")), filepath, tempoffset);
    } else {
        ncch_loader = new AppLoader_NCCH(std::move(FileUtil::IOFile(filepath, "rb")), filepath, 0);
    }
}
} // namespace Loader
