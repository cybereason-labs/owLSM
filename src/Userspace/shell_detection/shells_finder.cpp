#include "shells_finder.hpp"
#include "shell_binary_info_extractor.hpp"
#include "logger.hpp"

#include <unistd.h>
#include <filesystem>

namespace owlsm
{

std::unordered_set<ShellBinaryInfo, ShellBinaryInfoHash> ShellsFinder::getUniqueShellsFromEtcShells()
{
    const auto shell_paths = getShellPathsFromSystem();
    if (shell_paths.empty())
    {
        return {};
    }

    const auto resolved_paths = resolveLinks(shell_paths);
    if (resolved_paths.empty())
    {
        return {};
    }

    return filterToValidShells(resolved_paths);
}

std::unordered_set<std::string> ShellsFinder::getShellPathsFromSystem()
{
    std::unordered_set<std::string> result;

    setusershell();
    const char* shell = nullptr;
    while ((shell = getusershell()) != nullptr)
    {
        result.insert(shell);
    }
    endusershell();

    return result;
}

std::unordered_set<std::string> ShellsFinder::resolveLinks(const std::unordered_set<std::string>& paths)
{
    std::unordered_set<std::string> result;

    for (const auto& path : paths)
    {
        std::error_code ec;
        const auto resolved = std::filesystem::canonical(path, ec);
        if (ec)
        {
            LOG_WARN("Failed to resolve path " << path << ": " << ec.message());
            continue;
        }

        result.insert(resolved.string());
    }

    return result;
}

std::unordered_set<ShellBinaryInfo, ShellBinaryInfoHash> ShellsFinder::filterToValidShells(const std::unordered_set<std::string>& paths)
{
    std::unordered_set<ShellBinaryInfo, ShellBinaryInfoHash> result;

    for (const auto& path : paths)
    {
        const auto info = ShellBinaryInfoExtractor::getShellInfo(path);
        if (info.has_value())
        {
            result.insert(info.value());
        }
    }

    return result;
}

}

