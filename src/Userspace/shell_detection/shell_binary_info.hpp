#pragma once

#include "shell_types.hpp"

#include <string>
#include <cstdint>
#include <functional>

namespace owlsm
{

struct FileKey
{
    unsigned long inode = 0;
    unsigned int dev = 0;
    unsigned long long last_modified_time = 0;

    FileKey() = default;
    FileKey(unsigned long i, unsigned int d, unsigned long long m)
        : inode(i), dev(d), last_modified_time(m) {}

    bool operator==(const FileKey& other) const = default;
};

struct FileKeyHash
{
    std::size_t operator()(const FileKey& key) const
    {
        std::size_t h1 = std::hash<unsigned long>{}(key.inode);
        std::size_t h2 = std::hash<unsigned int>{}(key.dev);
        std::size_t h3 = std::hash<unsigned long long>{}(key.last_modified_time);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

struct ShellBinaryInfo
{
    unsigned long inode = 0;
    unsigned int dev = 0;
    unsigned long long last_modified_time = 0;
    std::string path;
    std::string build_id;
    unsigned long shell_start_function_offset = 0;
    unsigned long shell_end_function_offset = 0;
    bool is_shell_start_function_symbol_present = false;
    bool is_shell_end_function_symbol_present = false;
    ShellType shell_type = ShellType::UNKNOWN;

    FileKey toFileKey() const { return FileKey{inode, dev, last_modified_time}; }

    bool operator==(const ShellBinaryInfo& other) const
    {
        return toFileKey() == other.toFileKey();
    }
};

}

