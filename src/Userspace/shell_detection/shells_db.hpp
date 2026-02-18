#pragma once

#include "shell_binary_info_extractor.hpp"

#include <mutex>
#include <sqlite3.h>

namespace owlsm
{

class ShellsDB
{
public:
    ShellsDB() = default;
    ~ShellsDB();

    ShellsDB(const ShellsDB&) = delete;
    ShellsDB& operator=(const ShellsDB&) = delete;
    ShellsDB(ShellsDB&&) = delete;
    ShellsDB& operator=(ShellsDB&&) = delete;

    void init(const std::string& db_path);
    bool isInitialized() const { return m_db != nullptr; }

    std::optional<ShellBinaryInfo> get(const std::string& path);
    bool set(const ShellBinaryInfo& info);
    bool find(const std::string& path);
    bool find(const ShellBinaryInfo& info);
    std::vector<ShellBinaryInfo> getAll();

private:
    void createTable();
    void loadCacheFromDb();
    bool insertOrUpdate(const ShellBinaryInfo& info);
    void fillMissingOffsetsFromOffsetsTable(ShellBinaryInfo& info);
    void tryFillOffsetFromDb(const ShellBinaryInfo& info, const std::string& func_name, unsigned long& offset);
    std::optional<unsigned long> queryOffsetFromOffsetsTable(const std::string& build_id, const std::string& func_name);

    sqlite3* m_db = nullptr;
    std::unordered_map<FileKey, std::optional<ShellBinaryInfo>, FileKeyHash> m_cache;
    mutable std::mutex m_mutex;

    friend class ShellsDBTest;
};

}
