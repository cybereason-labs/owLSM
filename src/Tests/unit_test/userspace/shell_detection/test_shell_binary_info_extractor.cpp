#include <gtest/gtest.h>
#include "shell_detection/shell_binary_info_extractor.hpp"
#include "shell_detection/shell_types.hpp"
#include "shell_detection/shell_binary_info.hpp"

#include <filesystem>
#include <fstream>
#include <cstdlib>

namespace owlsm
{

class ShellBinaryInfoExtractorTest : public ::testing::Test 
{
public:
    static bool statxInfo(const std::string& path, ShellBinaryInfo& info)
    {
        return ShellBinaryInfoExtractor::statxInfo(path, info);
    }

    static bool isBinary(const std::string& path)
    {
        return ShellBinaryInfoExtractor::isBinary(path);
    }

    static bool getBuildId(const std::string& path, ShellBinaryInfo& info)
    {
        return ShellBinaryInfoExtractor::getBuildId(path, info);
    }

    static bool getOffsets(const std::string& path, ShellBinaryInfo& info)
    {
        return ShellBinaryInfoExtractor::getOffsets(path, info);
    }

protected:
    void SetUp() override
    {
        // Create a temp directory for test files
        m_temp_dir = std::filesystem::temp_directory_path() / "shell_extractor_test";
        std::filesystem::create_directories(m_temp_dir);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_temp_dir, ec);
    }

    std::filesystem::path m_temp_dir;
};

// ============== Shell Type Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, getShellType_bash_returns_bash_type)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }
    EXPECT_EQ(ShellBinaryInfoExtractor::getShellType("/usr/bin/bash"), ShellType::BASH);
}

TEST_F(ShellBinaryInfoExtractorTest, getShellType_dash_returns_dash_type)
{
    if (!std::filesystem::exists("/usr/bin/dash"))
    {
        GTEST_SKIP() << "/usr/bin/dash not found";
    }
    EXPECT_EQ(ShellBinaryInfoExtractor::getShellType("/usr/bin/dash"), ShellType::DASH);
}


TEST_F(ShellBinaryInfoExtractorTest, getShellType_non_shell_binary_returns_unknown)
{
    if (!std::filesystem::exists("/usr/bin/ls"))
    {
        GTEST_SKIP() << "/usr/bin/ls not found";
    }
    EXPECT_EQ(ShellBinaryInfoExtractor::getShellType("/usr/bin/ls"), ShellType::UNKNOWN);
}

TEST_F(ShellBinaryInfoExtractorTest, getShellType_nonexistent_file_returns_unknown)
{
    EXPECT_EQ(ShellBinaryInfoExtractor::getShellType("/nonexistent/path/to/shell"), ShellType::UNKNOWN);
}

TEST_F(ShellBinaryInfoExtractorTest, getShellType_text_file_returns_unknown)
{
    const auto text_file = m_temp_dir / "bash";  // named bash but not a binary
    std::ofstream ofs(text_file);
    ofs << "#!/bin/bash\necho hello\n";
    ofs.close();

    EXPECT_EQ(ShellBinaryInfoExtractor::getShellType(text_file.string()), ShellType::UNKNOWN);
}

// ============== isBinary Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, isBinary_elf_file_returns_true)
{
    if (!std::filesystem::exists("/usr/bin/ls"))
    {
        GTEST_SKIP() << "/usr/bin/ls not found";
    }
    EXPECT_TRUE(isBinary("/usr/bin/ls"));
}

TEST_F(ShellBinaryInfoExtractorTest, isBinary_text_file_returns_false)
{
    const auto text_file = m_temp_dir / "script.sh";
    std::ofstream ofs(text_file);
    ofs << "#!/bin/bash\necho hello\n";
    ofs.close();

    EXPECT_FALSE(isBinary(text_file.string()));
}

TEST_F(ShellBinaryInfoExtractorTest, isBinary_nonexistent_file_returns_false)
{
    EXPECT_FALSE(isBinary("/nonexistent/path/to/binary"));
}

TEST_F(ShellBinaryInfoExtractorTest, isBinary_empty_file_returns_false)
{
    const auto empty_file = m_temp_dir / "empty";
    std::ofstream ofs(empty_file);
    ofs.close();

    EXPECT_FALSE(isBinary(empty_file.string()));
}

// ============== statxInfo Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, statxInfo_valid_file_populates_info)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellBinaryInfo info;
    ASSERT_TRUE(statxInfo("/usr/bin/bash", info));

    EXPECT_GT(info.inode, 0u);
    EXPECT_GT(info.dev, 0u);
    EXPECT_GT(info.last_modified_time, 0u);
}

TEST_F(ShellBinaryInfoExtractorTest, statxInfo_nonexistent_file_returns_false)
{
    ShellBinaryInfo info;
    EXPECT_FALSE(statxInfo("/nonexistent/path", info));
}

TEST_F(ShellBinaryInfoExtractorTest, statxInfo_directory_returns_false)
{
    ShellBinaryInfo info;
    EXPECT_FALSE(statxInfo("/tmp", info));
}

TEST_F(ShellBinaryInfoExtractorTest, statxInfo_same_file_produces_same_inode)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellBinaryInfo info1, info2;
    ASSERT_TRUE(statxInfo("/usr/bin/bash", info1));
    ASSERT_TRUE(statxInfo("/usr/bin/bash", info2));

    EXPECT_EQ(info1.inode, info2.inode);
    EXPECT_EQ(info1.dev, info2.dev);
    EXPECT_EQ(info1.last_modified_time, info2.last_modified_time);
}

// ============== getBuildId Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, getBuildId_bash_has_build_id)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellBinaryInfo info;
    const bool result = getBuildId("/usr/bin/bash", info);
    
    // Build ID may or may not be present depending on how bash was compiled
    if (result)
    {
        EXPECT_FALSE(info.build_id.empty());
        // Build ID should be hex string (40 chars for SHA1, or more for longer hashes)
        EXPECT_GE(info.build_id.length(), 32u);
    }
}

TEST_F(ShellBinaryInfoExtractorTest, getBuildId_nonexistent_file_returns_false)
{
    ShellBinaryInfo info;
    EXPECT_FALSE(getBuildId("/nonexistent/path", info));
}

TEST_F(ShellBinaryInfoExtractorTest, getBuildId_matches_system_reported_build_id)
{
    EXPECT_TRUE(std::filesystem::exists("/usr/bin/bash"));

    ShellBinaryInfo info;
    const bool result = getBuildId("/usr/bin/bash", info);
    ASSERT_TRUE(result);
    EXPECT_FALSE(info.build_id.empty());

    // Get build ID via readelf command
    FILE* pipe = popen("readelf -n /usr/bin/bash | awk '/Build ID:/ {print $NF}'", "r");
    EXPECT_TRUE(pipe != nullptr);

    char buffer[128];
    std::string system_build_id;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        system_build_id = buffer;
        // Remove trailing newline
        if (!system_build_id.empty() && system_build_id.back() == '\n')
        {
            system_build_id.pop_back();
        }
    }
    pclose(pipe);

    EXPECT_FALSE(system_build_id.empty());

    std::cout << "system_build_id: " << system_build_id << std::endl;
    std::cout << "info.build_id: " << info.build_id << std::endl;
    
    EXPECT_EQ(info.build_id, system_build_id) 
        << "Build ID mismatch: getBuildId returned '" << info.build_id 
        << "' but readelf reported '" << system_build_id << "'";
}

// ============== getOffsets Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, getOffsets_bash_with_symbols_finds_functions)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    ShellBinaryInfo info;
    info.shell_type = ShellType::BASH;
    
    const bool result = getOffsets("/usr/bin/bash", info);
    
    // This depends on whether bash has debug symbols
    // If it does, we should find the functions
    if (result)
    {
        if (info.is_shell_start_function_symbol_present)
        {
            EXPECT_GT(info.shell_start_function_offset, 0u);
        }
        if (info.is_shell_end_function_symbol_present)
        {
            EXPECT_GT(info.shell_end_function_offset, 0u);
        }
    }
}

TEST_F(ShellBinaryInfoExtractorTest, getOffsets_unknown_shell_type_returns_false)
{
    ShellBinaryInfo info;
    info.shell_type = ShellType::UNKNOWN;
    
    EXPECT_FALSE(getOffsets("/usr/bin/bash", info));
}

TEST_F(ShellBinaryInfoExtractorTest, getOffsets_nonexistent_file_returns_false)
{
    ShellBinaryInfo info;
    info.shell_type = ShellType::BASH;
    
    EXPECT_FALSE(getOffsets("/nonexistent/path", info));
}

// ============== getShellInfo Integration Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, getShellInfo_bash_returns_complete_info)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    const auto result = ShellBinaryInfoExtractor::getShellInfo("/usr/bin/bash");
    ASSERT_TRUE(result.has_value());

    const auto& info = result.value();
    EXPECT_EQ(info.path, "/usr/bin/bash");
    EXPECT_EQ(info.shell_type, ShellType::BASH);
    EXPECT_GT(info.inode, 0u);
    EXPECT_GT(info.dev, 0u);
    EXPECT_GT(info.last_modified_time, 0u);
}

TEST_F(ShellBinaryInfoExtractorTest, getShellInfo_non_shell_returns_nullopt)
{
    if (!std::filesystem::exists("/usr/bin/ls"))
    {
        GTEST_SKIP() << "/usr/bin/ls not found";
    }

    const auto result = ShellBinaryInfoExtractor::getShellInfo("/usr/bin/ls");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ShellBinaryInfoExtractorTest, getShellInfo_nonexistent_returns_nullopt)
{
    const auto result = ShellBinaryInfoExtractor::getShellInfo("/nonexistent/path");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ShellBinaryInfoExtractorTest, getShellInfo_text_file_named_bash_returns_nullopt)
{
    // Create a text file named 'bash' - should not be detected as shell
    const auto fake_bash = m_temp_dir / "bash";
    std::ofstream ofs(fake_bash);
    ofs << "#!/bin/bash\necho I am not really bash\n";
    ofs.close();

    const auto result = ShellBinaryInfoExtractor::getShellInfo(fake_bash.string());
    EXPECT_FALSE(result.has_value());
}

TEST_F(ShellBinaryInfoExtractorTest, getShellInfo_dash_returns_complete_info)
{
    if (!std::filesystem::exists("/usr/bin/dash"))
    {
        GTEST_SKIP() << "/usr/bin/dash not found";
    }

    const auto result = ShellBinaryInfoExtractor::getShellInfo("/usr/bin/dash");
    ASSERT_TRUE(result.has_value());

    const auto& info = result.value();
    EXPECT_EQ(info.path, "/usr/bin/dash");
    EXPECT_EQ(info.shell_type, ShellType::DASH);
    EXPECT_GT(info.inode, 0u);
}

// ============== Shell Types Helper Function Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, shellTypeToString_returns_correct_names)
{
    EXPECT_EQ(shellTypeToString(ShellType::BASH), "BASH");
    EXPECT_EQ(shellTypeToString(ShellType::DASH), "DASH");
    EXPECT_EQ(shellTypeToString(ShellType::ZSH), "ZSH");
    EXPECT_EQ(shellTypeToString(ShellType::FISH), "FISH");
    EXPECT_EQ(shellTypeToString(ShellType::KSH), "KSH");
    EXPECT_EQ(shellTypeToString(ShellType::UNKNOWN), "UNKNOWN");
}

TEST_F(ShellBinaryInfoExtractorTest, shellNameToType_returns_correct_types)
{
    EXPECT_EQ(shellNameToType("bash"), ShellType::BASH);
    EXPECT_EQ(shellNameToType("dash"), ShellType::DASH);
    EXPECT_EQ(shellNameToType("zsh"), ShellType::ZSH);
    EXPECT_EQ(shellNameToType("fish"), ShellType::FISH);
    EXPECT_EQ(shellNameToType("ksh"), ShellType::KSH);
    EXPECT_EQ(shellNameToType("unknown_shell"), ShellType::UNKNOWN);
}

TEST_F(ShellBinaryInfoExtractorTest, shellNameToType_is_case_insensitive)
{
    EXPECT_EQ(shellNameToType("BASH"), ShellType::BASH);
    EXPECT_EQ(shellNameToType("Bash"), ShellType::BASH);
    EXPECT_EQ(shellNameToType("DASH"), ShellType::DASH);
    EXPECT_EQ(shellNameToType("ZSH"), ShellType::ZSH);
    EXPECT_EQ(shellNameToType("FISH"), ShellType::FISH);
    EXPECT_EQ(shellNameToType("KSH"), ShellType::KSH);
}

TEST_F(ShellBinaryInfoExtractorTest, getKnownShellNames_contains_expected_shells)
{
    const auto& names = getKnownShellNames();
    
    EXPECT_TRUE(names.find("bash") != names.end());
    EXPECT_TRUE(names.find("dash") != names.end());
    EXPECT_TRUE(names.find("zsh") != names.end());
    EXPECT_TRUE(names.find("fish") != names.end());
    EXPECT_TRUE(names.find("ksh") != names.end());
    EXPECT_TRUE(names.find("totally_not_a_shell") == names.end());
}

TEST_F(ShellBinaryInfoExtractorTest, getShellFunctionNames_bash_returns_as_expected)
{
    const auto names = getShellFunctionNames(ShellType::BASH);
    EXPECT_EQ(names.start_function, "readline");
    EXPECT_EQ(names.end_function, "readline");
}

TEST_F(ShellBinaryInfoExtractorTest, getShellFunctionNames_unknown_returns_empty)
{
    const auto names = getShellFunctionNames(ShellType::UNKNOWN);
    EXPECT_TRUE(names.start_function.empty());
    EXPECT_TRUE(names.end_function.empty());
}

// ============== ShellBinaryInfo DTO Tests ==============

TEST_F(ShellBinaryInfoExtractorTest, ShellBinaryInfo_equality_compares_key_fields)
{
    ShellBinaryInfo info1, info2;
    
    info1.inode = 12345;
    info1.dev = 1;
    info1.last_modified_time = 1000;
    info1.path = "/path/to/bash";
    
    info2.inode = 12345;
    info2.dev = 1;
    info2.last_modified_time = 1000;
    info2.path = "/different/path";  // Different path but same key fields
    
    EXPECT_TRUE(info1 == info2);
}

TEST_F(ShellBinaryInfoExtractorTest, ShellBinaryInfo_inequality_on_different_inode)
{
    ShellBinaryInfo info1, info2;
    
    info1.inode = 12345;
    info1.dev = 1;
    info1.last_modified_time = 1000;
    
    info2.inode = 54321;  // Different inode
    info2.dev = 1;
    info2.last_modified_time = 1000;
    
    EXPECT_FALSE(info1 == info2);
}

TEST_F(ShellBinaryInfoExtractorTest, ShellBinaryInfo_inequality_on_different_mtime)
{
    ShellBinaryInfo info1, info2;
    
    info1.inode = 12345;
    info1.dev = 1;
    info1.last_modified_time = 1000;
    
    info2.inode = 12345;
    info2.dev = 1;
    info2.last_modified_time = 2000;  // Different mtime
    
    EXPECT_FALSE(info1 == info2);
}

} // namespace owlsm
