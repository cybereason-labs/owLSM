#include <gtest/gtest.h>
#include "shell_detection/shells_db.hpp"
#include "shell_detection/shell_binary_info_extractor.hpp"
#include "shell_detection/shell_types.hpp"
#include "shell_detection/shell_binary_info.hpp"

#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

namespace owlsm
{

class ShellsDBTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_temp_dir = std::filesystem::temp_directory_path() / "shells_db_test";
        std::filesystem::create_directories(m_temp_dir);
        m_db_path = (m_temp_dir / "test_shells.db").string();
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_temp_dir, ec);
    }

    bool setFromPath(ShellsDB& db, const std::string& path)
    {
        const auto info = ShellBinaryInfoExtractor::getShellInfo(path);
        if (!info.has_value())
        {
            return false;
        }
        return db.set(info.value());
    }

    std::filesystem::path m_temp_dir;
    std::string m_db_path;
};

// ============== init() Tests ==============

TEST_F(ShellsDBTest, init_creates_database_file)
{
    ShellsDB db;
    EXPECT_FALSE(db.isInitialized());
    
    EXPECT_NO_THROW(db.init(m_db_path));
    EXPECT_TRUE(db.isInitialized());
    EXPECT_TRUE(std::filesystem::exists(m_db_path));
}

TEST_F(ShellsDBTest, init_twice_throws)
{
    ShellsDB db;
    db.init(m_db_path);
    
    EXPECT_THROW(db.init(m_db_path), std::runtime_error);
}

TEST_F(ShellsDBTest, init_with_invalid_path_throws)
{
    const std::string invalid_path = (m_temp_dir / "nonexistent" / "subdir" / "test.db").string();
    
    ShellsDB db;
    EXPECT_THROW(db.init(invalid_path), std::runtime_error);
    EXPECT_FALSE(db.isInitialized());
}

// ============== set() Tests ==============

TEST_F(ShellsDBTest, set_bash_succeeds)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    const bool result = setFromPath(db, "/usr/bin/bash");
    EXPECT_TRUE(result);
}

TEST_F(ShellsDBTest, set_nonexistent_file_returns_false)
{
    ShellsDB db;
    db.init(m_db_path);
    const bool result = setFromPath(db, "/nonexistent/path/to/shell");
    EXPECT_FALSE(result);
}

TEST_F(ShellsDBTest, set_non_shell_binary_returns_false)
{
    ShellsDB db;
    db.init(m_db_path);
    const bool result = setFromPath(db, "/usr/bin/ls");
    EXPECT_FALSE(result);
}

TEST_F(ShellsDBTest, set_text_file_returns_false)
{
    const std::string text_file = (m_temp_dir / "text_file.txt").string();
    std::ofstream(text_file) << "This is a text file";

    ShellsDB db;
    db.init(m_db_path);
    const bool result = setFromPath(db, text_file);
    EXPECT_FALSE(result);
}

TEST_F(ShellsDBTest, set_multiple_shells_succeeds)
{
    ShellsDB db;
    db.init(m_db_path);
    
    if (std::filesystem::exists("/usr/bin/bash"))
    {
        EXPECT_TRUE(setFromPath(db, "/usr/bin/bash"));
    }
    if (std::filesystem::exists("/bin/dash"))
    {
        EXPECT_TRUE(setFromPath(db, "/bin/dash"));
    }
}

TEST_F(ShellsDBTest, set_same_shell_twice_updates)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    
    EXPECT_TRUE(setFromPath(db, "/usr/bin/bash"));
    EXPECT_TRUE(setFromPath(db, "/usr/bin/bash"));
    
    // Should still only have one entry
    const auto all = db.getAll();
    int bash_count = 0;
    for (const auto& info : all)
    {
        if (info.shell_type == ShellType::BASH)
        {
            bash_count++;
        }
    }
    EXPECT_EQ(bash_count, 1);
}

// ============== get() Tests ==============

TEST_F(ShellsDBTest, get_after_set_returns_info)
{
    EXPECT_TRUE(std::filesystem::exists("/usr/bin/bash"));

    ShellsDB db;
    db.init(m_db_path);
    ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
    
    const auto result = db.get("/usr/bin/bash");
    ASSERT_TRUE(result.has_value());
    
    const auto& info = result.value();
    EXPECT_EQ(info.path, "/usr/bin/bash");
    EXPECT_EQ(info.shell_type, ShellType::BASH);
    EXPECT_GT(info.inode, 0u);
}

TEST_F(ShellsDBTest, get_without_set_returns_nullopt)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    // Don't set, just get
    const auto result = db.get("/usr/bin/bash");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ShellsDBTest, get_nonexistent_file_returns_nullopt)
{
    ShellsDB db;
    db.init(m_db_path);
    const auto result = db.get("/nonexistent/path");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ShellsDBTest, get_non_shell_returns_nullopt)
{
    ShellsDB db;
    db.init(m_db_path);
    const auto result = db.get("/usr/bin/ls");
    EXPECT_FALSE(result.has_value());
}

// ============== find() Tests ==============

TEST_F(ShellsDBTest, find_after_set_returns_true)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
    
    EXPECT_TRUE(db.find("/usr/bin/bash"));
}

TEST_F(ShellsDBTest, find_without_set_returns_false)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    EXPECT_FALSE(db.find("/usr/bin/bash"));
}

TEST_F(ShellsDBTest, find_nonexistent_file_returns_false)
{
    ShellsDB db;
    db.init(m_db_path);
    EXPECT_FALSE(db.find("/nonexistent/path"));
}

TEST_F(ShellsDBTest, find_non_shell_returns_false)
{
    ShellsDB db;
    db.init(m_db_path);
    EXPECT_FALSE(db.find("/usr/bin/ls"));
}

// ============== getAll() Tests ==============

TEST_F(ShellsDBTest, getAll_empty_db_returns_empty_vector)
{
    ShellsDB db;
    db.init(m_db_path);
    const auto result = db.getAll();
    EXPECT_TRUE(result.empty());
}

TEST_F(ShellsDBTest, getAll_returns_all_set_shells)
{
    ShellsDB db;
    db.init(m_db_path);
    
    int expected_count = 0;
    if (std::filesystem::exists("/usr/bin/bash"))
    {
        setFromPath(db, "/usr/bin/bash");
        expected_count++;
    }
    if (std::filesystem::exists("/bin/dash"))
    {
        setFromPath(db, "/bin/dash");
        expected_count++;
    }

    if (expected_count == 0)
    {
        GTEST_SKIP() << "No shells found to test";
    }

    const auto result = db.getAll();
    EXPECT_EQ(result.size(), static_cast<size_t>(expected_count));
}

TEST_F(ShellsDBTest, getAll_contains_correct_info)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
    
    const auto result = db.getAll();
    ASSERT_EQ(result.size(), 1u);
    
    const auto& info = result[0];
    EXPECT_EQ(info.path, "/usr/bin/bash");
    EXPECT_EQ(info.shell_type, ShellType::BASH);
}

// ============== Persistence Tests ==============

TEST_F(ShellsDBTest, data_persists_across_instances)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    // First instance: set data
    {
        ShellsDB db;
    db.init(m_db_path);
        ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
    }

    // Second instance: verify data persists
    {
        ShellsDB db;
    db.init(m_db_path);
        EXPECT_TRUE(db.find("/usr/bin/bash"));
        
        const auto result = db.get("/usr/bin/bash");
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result.value().path, "/usr/bin/bash");
    }
}

TEST_F(ShellsDBTest, getAll_loads_from_db_on_startup)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    // First instance: set data
    {
        ShellsDB db;
    db.init(m_db_path);
        ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
    }

    // Second instance: findAll should return data loaded from DB
    {
        ShellsDB db;
    db.init(m_db_path);
        const auto result = db.getAll();
        ASSERT_EQ(result.size(), 1u);
        EXPECT_EQ(result[0].path, "/usr/bin/bash");
    }
}

// ============== Thread Safety Tests ==============

TEST_F(ShellsDBTest, concurrent_set_does_not_crash)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i)
    {
        threads.emplace_back([&db, this]()
        {
            setFromPath(db, "/usr/bin/bash");
        });
    }
    
    for (auto& t : threads)
    {
        t.join();
    }
    
    // Just verify no crash and data is consistent
    const auto result = db.getAll();
    EXPECT_EQ(result.size(), 1u);
}

TEST_F(ShellsDBTest, concurrent_get_does_not_crash)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i)
    {
        threads.emplace_back([&db]()
        {
            db.get("/usr/bin/bash");
        });
    }
    
    for (auto& t : threads)
    {
        t.join();
    }
}

TEST_F(ShellsDBTest, concurrent_mixed_operations_does_not_crash)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    
    std::vector<std::thread> threads;
    
    // Some threads set
    for (int i = 0; i < 5; ++i)
    {
        threads.emplace_back([&db, this]()
        {
            setFromPath(db, "/usr/bin/bash");
        });
    }
    
    // Some threads get
    for (int i = 0; i < 5; ++i)
    {
        threads.emplace_back([&db]()
        {
            db.get("/usr/bin/bash");
        });
    }
    
    // Some threads find
    for (int i = 0; i < 5; ++i)
    {
        threads.emplace_back([&db]()
        {
            db.find("/usr/bin/bash");
        });
    }
    
    // Some threads findAll
    for (int i = 0; i < 5; ++i)
    {
        threads.emplace_back([&db]()
        {
            db.getAll();
        });
    }
    
    for (auto& t : threads)
    {
        t.join();
    }
}

// ============== FileKey Tests ==============

TEST_F(ShellsDBTest, FileKey_equality)
{
    FileKey key1{100, 200, 300};
    FileKey key2{100, 200, 300};
    FileKey key3{101, 200, 300};
    
    EXPECT_EQ(key1, key2);
    EXPECT_FALSE(key1 == key3);
}

TEST_F(ShellsDBTest, FileKey_hash_different_for_different_keys)
{
    FileKeyHash hasher;
    
    FileKey key1{100, 200, 300};
    FileKey key2{101, 200, 300};
    FileKey key3{100, 201, 300};
    
    // Different keys should (usually) produce different hashes
    // Note: Hash collisions are possible but unlikely for these values
    EXPECT_NE(hasher(key1), hasher(key2));
    EXPECT_NE(hasher(key1), hasher(key3));
}

TEST_F(ShellsDBTest, FileKey_hash_same_for_equal_keys)
{
    FileKeyHash hasher;
    
    FileKey key1{100, 200, 300};
    FileKey key2{100, 200, 300};
    
    EXPECT_EQ(hasher(key1), hasher(key2));
}

// ============== Data Integrity Tests ==============

TEST_F(ShellsDBTest, get_returns_all_fields_correctly)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellsDB db;
    db.init(m_db_path);
    ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
    
    const auto result = db.get("/usr/bin/bash");
    ASSERT_TRUE(result.has_value());
    
    const auto& info = result.value();
    
    // Verify all key fields
    EXPECT_GT(info.inode, 0u);
    EXPECT_GT(info.dev, 0u);
    EXPECT_GT(info.last_modified_time, 0u);
    
    // Verify other fields
    EXPECT_EQ(info.path, "/usr/bin/bash");
    EXPECT_EQ(info.shell_type, ShellType::BASH);
}

TEST_F(ShellsDBTest, persistence_preserves_all_fields)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellBinaryInfo original_info;
    
    // First instance: set and capture original info
    {
        ShellsDB db;
    db.init(m_db_path);
        ASSERT_TRUE(setFromPath(db, "/usr/bin/bash"));
        const auto result = db.get("/usr/bin/bash");
        ASSERT_TRUE(result.has_value());
        original_info = result.value();
    }

    // Second instance: verify all fields match
    {
        ShellsDB db;
    db.init(m_db_path);
        const auto result = db.get("/usr/bin/bash");
        ASSERT_TRUE(result.has_value());
        
        const auto& loaded_info = result.value();
        
        EXPECT_EQ(loaded_info.inode, original_info.inode);
        EXPECT_EQ(loaded_info.dev, original_info.dev);
        EXPECT_EQ(loaded_info.last_modified_time, original_info.last_modified_time);
        EXPECT_EQ(loaded_info.path, original_info.path);
        EXPECT_EQ(loaded_info.build_id, original_info.build_id);
        EXPECT_EQ(loaded_info.shell_start_function_offset, original_info.shell_start_function_offset);
        EXPECT_EQ(loaded_info.shell_end_function_offset, original_info.shell_end_function_offset);
        EXPECT_EQ(loaded_info.is_shell_start_function_symbol_present, original_info.is_shell_start_function_symbol_present);
        EXPECT_EQ(loaded_info.is_shell_end_function_symbol_present, original_info.is_shell_end_function_symbol_present);
        EXPECT_EQ(loaded_info.shell_type, original_info.shell_type);
    }
}

}


