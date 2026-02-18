#pragma once

#include <magic_enum/magic_enum.hpp>

#include <string>
#include <string_view>
#include <unordered_set>

namespace owlsm
{

enum class ShellType
{
    BASH,
    DASH,
    ZSH,
    FISH,
    KSH,
    UNKNOWN
};

inline std::string_view shellTypeToString(ShellType type)
{
    return magic_enum::enum_name(type);
}

inline const std::unordered_set<std::string>& getKnownShellNames()
{
    static const std::unordered_set<std::string> KNOWN_SHELL_NAMES = {
        "bash",
        "dash",
        "zsh",
        "fish",
        "ksh"
    };
    return KNOWN_SHELL_NAMES;
}

inline ShellType shellNameToType(const std::string& name)
{
    const auto result = magic_enum::enum_cast<ShellType>(name, magic_enum::case_insensitive);
    if (result.has_value())
    {
        return result.value();
    }
    return ShellType::UNKNOWN;
}

struct ShellFunctionNames
{
    std::string start_function;
    std::string end_function;
};

inline ShellFunctionNames getShellFunctionNames(ShellType type)
{
    switch (type)
    {
        case ShellType::BASH:
            return {"readline", "readline"};
        case ShellType::DASH:
            return {"list", "setprompt"};
        case ShellType::ZSH:
            return {"zleentry", "parse_event"}; // TODO: this is incorrect. zsh uses 3 hooks. After adding dash, we need to understrand what is the correct way to get the shell function names.
        case ShellType::FISH:
        case ShellType::KSH:
        case ShellType::UNKNOWN:
        default:
            return {"", ""};
    }
}

}

