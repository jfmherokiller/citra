// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include "core/loader/ncch.h"

struct CIAHeader {
    u32_le header_size;
    u8 type[2];
    u8 version[2];
    u32_le cert_size;
    u32_le ticket_size;
    u32_le tmd_size;
    u32_le meta_size;
    u64_le content_size;
    u8 content_index[0x2000];
};

namespace Loader {

class AppLoader_CIA final : public AppLoader {
public:
    AppLoader_CIA(FileUtil::IOFile&& file, const std::string& filepath);

    FileType GetFileType() override {
        return IdentifyType(file);
    }
    /**
     * Returns the type of the file
     * @param file FileUtil::IOFile open file
     * @return FileType found, or FileType::Error if this loader doesn't know it
     */
    static FileType IdentifyType(FileUtil::IOFile& file);
    ResultStatus Load() override;
    /**
     * Loads the Exheader and returns the system mode for this application.
     * @return Optional with the kernel system mode
     */
    boost::optional<u32> LoadKernelSystemMode() override;

    ResultStatus ReadCode(std::vector<u8>& buffer) override;

    ResultStatus ReadIcon(std::vector<u8>& buffer) override;

    ResultStatus ReadBanner(std::vector<u8>& buffer) override;

    ResultStatus ReadLogo(std::vector<u8>& buffer) override;

    /**
     * Get the program id of the application
     * @param out_program_id Reference to store program id into
     * @return ResultStatus result of function
     */
    ResultStatus ReadProgramId(u64& out_program_id) override;

    /**
     * Get the RomFS of the application
     * @param romfs_file Reference to buffer to store data
     * @param offset     Offset in the file to the RomFS
     * @param size       Size of the RomFS in bytes
     * @return ResultStatus result of function
     */
    ResultStatus ReadRomFS(std::shared_ptr<FileUtil::IOFile>& romfs_file, u64& offset,
                           u64& size) override;

private:
    AppLoader_NCCH* ncch_loader;
    ResultStatus TryGetNCCHOffset(u32& offset);
};
} // namespace Loader
