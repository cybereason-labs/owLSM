#include "shells_db.hpp"
#include "logger.hpp"

#include <sys/stat.h>

namespace owlsm
{

ShellsDB::~ShellsDB()
{
    if (m_db)
    {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

void ShellsDB::init(const std::string& db_path)
{
    if (m_db)
    {
        throw std::runtime_error("ShellsDB already initialized");
    }

    const int rc = sqlite3_open(db_path.c_str(), &m_db);
    if (rc != SQLITE_OK)
    {
        std::string error_msg = "Failed to open SQLite database at " + db_path + ": " + std::string(sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        m_db = nullptr;
        throw std::runtime_error(error_msg);
    }
    chmod(db_path.c_str(), S_IRUSR | S_IWUSR);

    createTable();
    loadCacheFromDb();
}

void ShellsDB::createTable()
{
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS shell_db_table (
            inode INTEGER NOT NULL,
            dev INTEGER NOT NULL,
            last_modified_time INTEGER NOT NULL,
            path TEXT NOT NULL,
            build_id TEXT NOT NULL,
            shell_start_function_offset INTEGER NOT NULL,
            shell_end_function_offset INTEGER NOT NULL,
            is_shell_start_function_symbol_present INTEGER NOT NULL,
            is_shell_end_function_symbol_present INTEGER NOT NULL,
            shell_type INTEGER NOT NULL,
            PRIMARY KEY (inode, dev, last_modified_time)
        );
    )";

    char* err_msg = nullptr;
    const int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK)
    {
        std::string error_str = "Failed to create table: " + std::string(err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(m_db);
        m_db = nullptr;
        throw std::runtime_error(error_str);
    }
}

void ShellsDB::loadCacheFromDb()
{
    const char* sql = "SELECT * FROM shell_db_table;";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        std::string error_msg = "Failed to prepare SELECT statement: " + std::string(sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        m_db = nullptr;
        throw std::runtime_error(error_msg);
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        ShellBinaryInfo info;
        info.inode = static_cast<unsigned long>(sqlite3_column_int64(stmt, 0));
        info.dev = static_cast<unsigned int>(sqlite3_column_int(stmt, 1));
        info.last_modified_time = static_cast<unsigned long long>(sqlite3_column_int64(stmt, 2));
        
        const char* path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        info.path = path ? path : "";
        
        const char* build_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        info.build_id = build_id ? build_id : "";
        
        info.shell_start_function_offset = static_cast<unsigned long>(sqlite3_column_int64(stmt, 5));
        info.shell_end_function_offset = static_cast<unsigned long>(sqlite3_column_int64(stmt, 6));
        info.is_shell_start_function_symbol_present = sqlite3_column_int(stmt, 7) != 0;
        info.is_shell_end_function_symbol_present = sqlite3_column_int(stmt, 8) != 0;
        info.shell_type = static_cast<ShellType>(sqlite3_column_int(stmt, 9));

        m_cache[info.toFileKey()] = info;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        std::string error_msg = "Error while loading cache: " + std::string(sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        m_db = nullptr;
        throw std::runtime_error(error_msg);
    }
}

std::optional<ShellBinaryInfo> ShellsDB::get(const std::string& path)
{
    const auto extracted_info = ShellBinaryInfoExtractor::getShellInfo(path);
    if (!extracted_info.has_value())
    {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_cache.find(extracted_info->toFileKey());
    if (it != m_cache.end())
    {
        return it->second;
    }

    return std::nullopt;
}

bool ShellsDB::set(const ShellBinaryInfo& info)
{
    ShellBinaryInfo enriched_info = info;
    fillMissingOffsetsFromOffsetsTable(enriched_info);

    std::lock_guard<std::mutex> lock(m_mutex);
    m_cache[enriched_info.toFileKey()] = enriched_info;
    return insertOrUpdate(enriched_info);
}

bool ShellsDB::find(const std::string& path)
{
    const auto extracted_info = ShellBinaryInfoExtractor::getShellInfo(path);
    if (!extracted_info.has_value())
    {
        return false;
    }

    return find(extracted_info.value());
}

bool ShellsDB::find(const ShellBinaryInfo& info)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cache.find(info.toFileKey()) != m_cache.end();
}

std::vector<ShellBinaryInfo> ShellsDB::getAll()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<ShellBinaryInfo> result;
    result.reserve(m_cache.size());

    for (const auto& [key, value] : m_cache)
    {
        if (value.has_value())
        {
            result.push_back(value.value());
        }
    }

    return result;
}

void ShellsDB::fillMissingOffsetsFromOffsetsTable(ShellBinaryInfo& info)
{
    if (!m_db || info.build_id.empty())
    {
        return;
    }

    const auto func_names = getShellFunctionNames(info.shell_type);
    tryFillOffsetFromDb(info, func_names.start_function, info.shell_start_function_offset);

    if (func_names.end_function == func_names.start_function)
    {
        info.shell_end_function_offset = info.shell_start_function_offset;
        return;
    }

    tryFillOffsetFromDb(info, func_names.end_function, info.shell_end_function_offset);
}

void ShellsDB::tryFillOffsetFromDb(const ShellBinaryInfo& info, const std::string& func_name, unsigned long& offset)
{
    if (offset != 0 || func_name.empty())
    {
        return;
    }

    const auto db_offset = queryOffsetFromOffsetsTable(info.build_id, func_name);
    if (db_offset.has_value())
    {
        offset = db_offset.value();
        LOG_INFO("Found function offset from offsets DB: " << func_name
                 << " offset: 0x" << std::hex << offset << std::dec
                 << " build_id: " << info.build_id << " path: " << info.path);
        return;
    }

    LOG_WARN("Offset not found in binary or offsets DB for function: " << func_name
             << " build_id: " << info.build_id << " path: " << info.path);
}

std::optional<unsigned long> ShellsDB::queryOffsetFromOffsetsTable(const std::string& build_id, const std::string& func_name)
{
    const char* sql = "SELECT offset FROM offsets WHERE build_id = ? AND func_name = ?;";

    sqlite3_stmt* stmt = nullptr;
    const int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        LOG_ERROR("Failed to prepare offset query: " << sqlite3_errmsg(m_db));
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, build_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, func_name.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<unsigned long> result;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        result = static_cast<unsigned long>(sqlite3_column_int64(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return result;
}

bool ShellsDB::insertOrUpdate(const ShellBinaryInfo& info)
{
    if (!m_db)
    {
        return false;
    }

    const char* sql = R"(
        INSERT OR REPLACE INTO shell_db_table (
            inode, dev, last_modified_time, path, build_id,
            shell_start_function_offset, shell_end_function_offset,
            is_shell_start_function_symbol_present, is_shell_end_function_symbol_present,
            shell_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        LOG_ERROR("Failed to prepare INSERT statement: " << sqlite3_errmsg(m_db));
        return false;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(info.inode));
    sqlite3_bind_int(stmt, 2, static_cast<int>(info.dev));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(info.last_modified_time));
    sqlite3_bind_text(stmt, 4, info.path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, info.build_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(info.shell_start_function_offset));
    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(info.shell_end_function_offset));
    sqlite3_bind_int(stmt, 8, info.is_shell_start_function_symbol_present ? 1 : 0);
    sqlite3_bind_int(stmt, 9, info.is_shell_end_function_symbol_present ? 1 : 0);
    sqlite3_bind_int(stmt, 10, static_cast<int>(info.shell_type));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        LOG_ERROR("Failed to insert/update row: " << sqlite3_errmsg(m_db));
        return false;
    }

    return true;
}

}
