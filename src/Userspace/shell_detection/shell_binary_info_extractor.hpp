#pragma once

#include "shell_binary_info.hpp"

#include <string>
#include <optional>

namespace owlsm
{

class ShellBinaryInfoExtractor
{
public:
    ShellBinaryInfoExtractor() = delete;

    static std::optional<ShellBinaryInfo> getShellInfo(const std::string& path);
    static ShellType getShellType(const std::string& path);

private:
    static bool statxInfo(const std::string& path, ShellBinaryInfo& info);
    static bool isBinary(const std::string& path);
    static bool getBuildId(const std::string& path, ShellBinaryInfo& info);
    static bool getOffsets(const std::string& path, ShellBinaryInfo& info);

    friend class ShellBinaryInfoExtractorTest;
};

}
