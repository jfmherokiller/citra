// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <common/alignment.h>
#include "cia.h"

namespace Loader {
FileType AppLoader_CIA::IdentifyType(FileUtil::IOFile& file) {
    if (IsValidCia(file))
        return FileType::CIA;

    return FileType::Error;
}

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

ResultStatus AppLoader_CIA::Load() {
    return ncch_loader->Load();
}

std::pair<boost::optional<u32>, ResultStatus> AppLoader_CIA::LoadKernelSystemMode() {
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

AppLoader_CIA::AppLoader_CIA(FileUtil::IOFile&& file, const std::string& filepath)
    : AppLoader(std::move(file)) {
    if (IsValidCia(file)) {
        ncch_loader = new AppLoader_NCCH(std::move(FileUtil::IOFile(filepath, "rb")), filepath,
                                         FindNCCHOffsetInCIA(file));
    } else {
        ncch_loader = new AppLoader_NCCH(std::move(FileUtil::IOFile(filepath, "rb")), filepath, 0);
    }
}

bool AppLoader_CIA::IsValidCia(FileUtil::IOFile& file) {
    // Reset read pointer in case this file has been read before.
    file.Seek(0, SEEK_SET);

    bool is_valid = false;
    u32 magic;
    u32 offset = FindNCCHOffsetInCIA(file);
    file.Seek(offset, SEEK_SET);
    file.ReadArray<u32>(&magic, 1);
    if (MakeMagic('N', 'C', 'C', 'H') != magic) {
        // this additional if check was made to account for the possible
        // padding which always seems to exist as 256 extra bytes
        // TODO: see if the padding can be other sizes as well as 256
        file.Seek(offset + 256, SEEK_SET);
        file.ReadArray<u32>(&magic, 1);
        if (MakeMagic('N', 'C', 'C', 'H') == magic) {
            is_valid = true;
        }
    } else {
        is_valid = true;
    }

    return is_valid;
}
}
