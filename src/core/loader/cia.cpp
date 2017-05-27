// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <cstring>
#include <memory>
#include <string>
#include "cia.h"
#include "common/common_types.h"
#include "common/file_util.h"
#include "common/logging/log.h"
#include "common/symbols.h"
#include "core/hle/kernel/process.h"
#include "core/hle/kernel/resource_limit.h"
#include "core/loader/cia.h"
#include "core/memory.h"
namespace Loader {
/*
 * This is the current version of the CIA format, it was finalised in late 2010. (Older versions of
the CIA format can be viewed on the Talk page)

*The CIA format has a similar structure to the WAD format.

*The file is represented in little-endian.

*The data is aligned in 64 byte blocks (if a content ends at the middle of the block, the next
content will begin from a new block).
 * CIA Header[edit]
*START SIZE    DESCRIPTION
*0x00 0x04 Archive Header Size (Usually = 0x2020 bytes)
*0x04 0x02 Type
*0x06 0x02 Version
*0x08 0x04 Certificate chain size
*0x0C 0x04 Ticket size
*0x10 0x04 TMD file size
*0x14 0x04 Meta size (0 if no Meta data is present)
*0x18 0x08 Content size
*0x20 0x2000 Content Index
*The order of the sections in the CIA file:

*certificate chain
*Ticket
*TMD file data
*Content file data
*Meta file data (Not a necessary component)
*The contents (NCCH/SRL) are encrypted using 128-bit AES-CBC. The encryption uses the decrypted
titlekey from the ticket, and the content index from the TMD padded with zeros as the IV.

*Certificate Chain[edit]
*There are three certificates in this chain:

*CERTIFICATE SIGNATURE TYPE RETAIL CERT NAME DEBUG CERT NAME DESCRIPTION
*CA RSA-4096 CA00000003 CA00000004 Used to verify the Ticket/TMD Certificates
*Ticket RSA-2048 XS0000000c XS00000009 Used to verify the Ticket signature
*TMD RSA-2048 CP0000000b CP0000000a Used to verify the TMD signature
*The CA certificate is issued by 'Root', the public key for which is stored in NATIVE_FIRM.

*Meta[edit]
*The structure of this data is as follows:

*START SIZE DESCRIPTION
*0x00 0x180 Title ID dependency list - Taken from the application's ExHeader
*0x180 0x180 Reserved
*0x300 0x4 Core Version
*0x304 0xFC Reserved
*0x400 0x36C0 Icon Data(.ICN) - Taken from the application's ExeFS
 */
void AppLoader_CIA::ReadCiaFile(cia_context& returnme) {
    // Reset read pointer in case this file has been read before.
    file.Seek(0, SEEK_SET);
    cia_context* ctx = new cia_context;
    memset(ctx, 0, sizeof(cia_context));

    file.ReadBytes(&ctx->header, sizeof(CIA_Header));

    ctx->sizeheader = ctx->header.headersize;
    ctx->sizecert = ctx->header.certsize;
    ctx->sizetik = ctx->header.ticketsize;
    ctx->sizetmd = ctx->header.tmdsize;
    ctx->sizecontent = ctx->header.contentsize;
    ctx->sizemeta = ctx->header.metasize;
    returnme = *ctx;
};

ResultStatus AppLoader_CIA::Load() {
    if (is_loaded)
        return ResultStatus::ErrorAlreadyLoaded;
    cia_context ctx;
    ReadCiaFile(ctx);
    is_loaded = true;

    return ResultStatus::Success;
}
FileType AppLoader_CIA::IdentifyType(FileUtil::IOFile& file) {
    u32 magic;
    // reset file pointer just in case
    file.Seek(0, SEEK_SET);
    if (4 != file.ReadBytes(&magic, 4))
        return FileType::Error;

    if (0x2020 == magic)
        return FileType::CIA;

    return FileType::Error;
}
void AppLoader_CIA::ReadCiaFile(cia_context& returnme) {
    // Reset read pointer in case this file has been read before.
    file.Seek(0, SEEK_SET);
    cia_context* ctx = new cia_context;
    memset(ctx, 0, sizeof(cia_context));

    file.ReadBytes(&ctx->header, sizeof(CIA_Header));

    ctx->sizeheader = ctx->header.headersize;
    ctx->sizecert = ctx->header.certsize;
    ctx->sizetik = ctx->header.ticketsize;
    ctx->sizetmd = ctx->header.tmdsize;
    ctx->sizecontent = ctx->header.contentsize;
    ctx->sizemeta = ctx->header.metasize;
    ctx->offsetcerts = align(ctx->sizeheader, 64);
    ctx->offsettik = align(ctx->offsetcerts + ctx->sizecert, 64);
    ctx->offsettmd = align(ctx->offsettik + ctx->sizetik, 64);
    ctx->offsetcontent = align(ctx->offsettmd + ctx->sizetmd, 64);
    returnme = *ctx;
};
}