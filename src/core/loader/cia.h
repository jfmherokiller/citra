// Copyright 2014 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once
#include <string>
#include <common/common_paths.h>
#include "common/swap.h"
#include "core/loader/loader.h"

namespace Loader {
/// Loads an CIA file
// File header
struct CIA_Header {
    u32_le headersize;
    u8 type[2];
    u8 version[2];
    u32_le certsize;
    u32_le ticketsize;
    u32_le tmdsize;
    u32_le metasize;
    u64_le contentsize;
    u8 contentindex[0x2000];
};

#define MAGIC_NCCH 0x4843434E
#define MAGIC_NCSD 0x4453434E
#define MAGIC_FIRM 0x4D524946
#define MAGIC_CWAV 0x56415743
#define MAGIC_IVFC 0x43465649

#define SIZE_128MB (128 * 1024 * 1024)

typedef enum {
    CIATYPE_CERTS,
    CIATYPE_TMD,
    CIATYPE_TIK,
    CIATYPE_CONTENT,
    CIATYPE_META,
} cia_types;

#define TMD_MAX_CONTENTS 64

typedef enum {
    TMD_RSA_2048_SHA256 = 0x00010004,
    TMD_RSA_4096_SHA256 = 0x00010003,
    TMD_RSA_2048_SHA1 = 0x00010001,
    TMD_RSA_4096_SHA1 = 0x00010000
} ctr_tmdtype;

typedef enum {
    FILETYPE_UNKNOWN = 0,
    FILETYPE_CCI,
    FILETYPE_CXI,
    FILETYPE_CIA,
    FILETYPE_EXHEADER,
    FILETYPE_TMD,
    FILETYPE_LZSS,
    FILETYPE_FIRM,
    FILETYPE_CWAV,
    FILETYPE_EXEFS,
    FILETYPE_ROMFS
} ctr_filetypes;

typedef struct {
    unsigned char padding[60];
    unsigned char issuer[64];
    unsigned char version;
    unsigned char ca_crl_version;
    unsigned char signer_crl_version;
    unsigned char padding2;
    unsigned char systemversion[8];
    unsigned char titleid[8];
    unsigned char titletype[4];
    unsigned char groupid[2];
    unsigned char savedatasize[4];
    unsigned char privsavedatasize[4];
    unsigned char padding3[4];
    unsigned char twlflag;
    unsigned char padding4[0x31];
    unsigned char accessrights[4];
    unsigned char titleversion[2];
    unsigned char contentcount[2];
    unsigned char bootcontent[2];
    unsigned char padding5[2];
    unsigned char hash[32];
    unsigned char contentinfo[36 * 64];
} ctr_tmd_body;

typedef struct {
    unsigned char index[2];
    unsigned char commandcount[2];
    unsigned char unk[32];
} ctr_tmd_contentinfo;

typedef struct {
    unsigned char id[4];
    unsigned char index[2];
    unsigned char type[2];
    unsigned char size[8];
    unsigned char hash[32];
} ctr_tmd_contentchunk;

typedef struct {
    unsigned char signaturetype[4];
    unsigned char signature[256];
} ctr_tmd_header_2048;

typedef struct {
    unsigned char signaturetype[4];
    unsigned char signature[512];
} ctr_tmd_header_4096;

typedef struct {
    u8 enable_timelimit[4];
    u8 timelimit_seconds[4];
} timelimit_entry;

typedef struct {
    u8 sig_type[4];
    u8 signature[0x100];
    u8 padding1[0x3c];
    u8 issuer[0x40];
    u8 ecdsa[0x3c];
    u8 padding2[0x03];
    u8 encrypted_title_key[0x10];
    u8 unknown;
    u8 ticket_id[8];
    u8 console_id[4];
    std::array<u8, 8> title_id;
    u8 sys_access[2];
    u8 ticket_version[2];
    u8 time_mask[4];
    u8 permit_mask[4];
    u8 title_export;
    u8 commonkey_idx;
    u8 unknown_buf[0x30];
    u8 content_permissions[0x40];
    u8 padding0[2];

    timelimit_entry timelimits[8];
} eticket;

typedef struct {
    char pathname[MAX_PATH];
    int valid;
} filepath;

struct tik_context {
    u64 offset;
    u32 size;
    u8 titlekey[16];
    eticket tik;
};

typedef struct {
    u64 offset;
    u32 size;
    u8* buffer;
    u8 content_hash_stat[64];
} tmd_context;

struct cia_context {
    u64 offset;
    u64 size;
    u8 titlekey[16];
    u8 iv[16];
    CIA_Header header;

    tik_context tik_feild;
    tmd_context tmd;

    u32 sizeheader;
    u32 sizecert;
    u32 sizetik;
    u32 sizetmd;
    u64 sizecontent;
    u32 sizemeta;

    u64 offsetcerts;
    u64 offsettik;
    u64 offsettmd;
    u64 offsetcontent;
    u64 offsetmeta;
};

class AppLoader_CIA final : public AppLoader {
public:
    AppLoader_CIA(FileUtil::IOFile&& file, std::string filename)
        : AppLoader(std::move(file)), filename(std::move(filename)) {}

    /**
     * Returns the type of the file
     * @param file FileUtil::IOFile open file
     * @return FileType found, or FileType::Error if this loader doesn't know it
     */
    static FileType IdentifyType(FileUtil::IOFile& file);

    FileType GetFileType() override {
        return IdentifyType(file);
    }

    ResultStatus Load() override;
    /**
   * Get the program id of the application
   * @param out_program_id Reference to store program id into
   * @return ResultStatus result of function
   */
    // ResultStatus ReadProgramId(u64& out_program_id) override;

private:
    std::string filename;
    void ReadCiaFile(cia_context& returnme);
};

} // namespace Loader
