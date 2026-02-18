#pragma once

#include "shell_binary_info.hpp"

#include <string>
#include <unordered_set>

namespace owlsm
{

struct ShellBinaryInfoHash
{
    std::size_t operator()(const ShellBinaryInfo& info) const
    {
        return FileKeyHash{}(info.toFileKey());
    }
};

class ShellsFinder
{
public:
    static std::unordered_set<ShellBinaryInfo, ShellBinaryInfoHash> getUniqueShellsFromEtcShells();

private:
    static std::unordered_set<std::string> getShellPathsFromSystem();
    static std::unordered_set<std::string> resolveLinks(const std::unordered_set<std::string>& paths);
    static std::unordered_set<ShellBinaryInfo, ShellBinaryInfoHash> filterToValidShells(const std::unordered_set<std::string>& paths);

    friend class ShellsFinderTest;
};

}
