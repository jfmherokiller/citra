// Copyright 2014 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "ncch.h"
namespace Loader {

class AppLoader_NCSD final : public AppLoader_NCCH {
public:
    AppLoader_NCSD(FileUtil::IOFile&& file, const std::string& filepath)
        : AppLoader_NCCH(std::move(file), filepath) {}
    /**
   * Ensure ExeFS is loaded and ready for reading sections
   * @return ResultStatus result of function
   */
    ResultStatus LoadExeFS() override;

    FileType GetFileType() override {
        return IdentifyType(file);
    }
    /**
  * Returns the type of the file
  * @param file FileUtil::IOFile open file
  * @return FileType found, or FileType::Error if this loader doesn't know it
  */
    static FileType IdentifyType(FileUtil::IOFile& file);
};
}
