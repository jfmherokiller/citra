// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include "core/loader/ncch.h"

// Offset & Length of partition in media units
struct Partition_Table_Entry {
    u32_le partition_offset;
    u32_le partition_size;
};

struct NCSD_Header {
    std::array<u8, 0x100> signature; ///<RSA-2048 SHA-256 signature of the NCSD header
    u32_le magic;
    u32_le image_size; ///< Size of the NCSD image, in media units (1 media unit = 0x200 bytes)
    u64_le media_id;
    std::array<u8, 8>
        partitions_fs_type; //< Partitions FS type (0=None, 1=Normal, 3=FIRM, 4=AGB_FIRM save)
    std::array<u8, 8> partitions_crypt_type; //< Partitions crypt type (each byte corresponds to a
                                             // partition in the partition table)
    std::array<Partition_Table_Entry, 8> partition_table;
};

namespace Loader {

class AppLoader_NCSD final : public AppLoader {
public:
    AppLoader_NCSD(FileUtil::IOFile&& file, const std::string& filepath);

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
    std::pair<boost::optional<u32>, ResultStatus> LoadKernelSystemMode() override;

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

protected:
    ResultStatus TryGetNCCHOffset(u32& offset);

private:
    AppLoader_NCCH* ncch_loader;
};
} // namespace Loader
