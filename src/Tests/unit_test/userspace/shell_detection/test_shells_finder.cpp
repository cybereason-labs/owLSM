#include <gtest/gtest.h>
#include "shell_detection/shells_finder.hpp"
#include "shell_detection/shell_types.hpp"

#include <filesystem>
#include <fstream>
#include <set>

namespace owlsm
{

class ShellsFinderTest : public ::testing::Test
{
public:
    static std::unordered_set<std::string> getShellPathsFromSystem()
    {
        return ShellsFinder::getShellPathsFromSystem();
    }

    static std::unordered_set<std::string> resolveLinks(const std::unordered_set<std::string>& paths)
    {
        return ShellsFinder::resolveLinks(paths);
    }

    static std::unordered_set<ShellBinaryInfo, ShellBinaryInfoHash> filterToValidShells(const std::unordered_set<std::string>& paths)
    {
        return ShellsFinder::filterToValidShells(paths);
    }

protected:
    void SetUp() override
    {
        m_temp_dir = std::filesystem::temp_directory_path() / "shells_finder_test";
        std::filesystem::create_directories(m_temp_dir);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_temp_dir, ec);
    }

    std::filesystem::path m_temp_dir;
};

// ============== getShellPathsFromSystem Tests ==============

TEST_F(ShellsFinderTest, getShellPathsFromSystem_returns_paths)
{
    const auto result = getShellPathsFromSystem();
    
    // /etc/shells should have at least one shell on any system
    EXPECT_FALSE(result.empty());
    
    // All paths should be absolute
    for (const auto& path : result)
    {
        EXPECT_EQ(path[0], '/');
    }
}

TEST_F(ShellsFinderTest, getShellPathsFromSystem_contains_common_shells)
{
    const auto result = getShellPathsFromSystem();
    
    // At least one of these common shells should be present
    bool found_common_shell = false;
    for (const auto& path : result)
    {
        if (path.find("bash") != std::string::npos ||
            path.find("dash") != std::string::npos ||
            path.find("sh") != std::string::npos ||
            path.find("zsh") != std::string::npos)
        {
            found_common_shell = true;
            break;
        }
    }
    
    EXPECT_TRUE(found_common_shell);
}

// ============== resolveLinks Tests ==============

TEST_F(ShellsFinderTest, resolveLinks_existing_files_returned)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    const std::unordered_set<std::string> paths = {"/usr/bin/bash"};
    const auto result = resolveLinks(paths);
    
    ASSERT_EQ(result.size(), 1u);
    EXPECT_FALSE(result.begin()->empty());
}

TEST_F(ShellsFinderTest, resolveLinks_nonexistent_files_filtered_out)
{
    const std::unordered_set<std::string> paths = {"/nonexistent/path"};
    const auto result = resolveLinks(paths);
    
    EXPECT_TRUE(result.empty());
}

TEST_F(ShellsFinderTest, resolveLinks_symlinks_resolved)
{
    const auto real_file = m_temp_dir / "real_file";
    const auto symlink_file = m_temp_dir / "symlink_file";
    
    { std::ofstream ofs(real_file); }
    std::filesystem::create_symlink(real_file, symlink_file);
    
    const std::unordered_set<std::string> paths = {symlink_file.string()};
    const auto result = resolveLinks(paths);
    
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(*result.begin(), std::filesystem::canonical(real_file).string());
}

TEST_F(ShellsFinderTest, resolveLinks_deduplicates_symlinks_to_same_file)
{
    const auto real_file = m_temp_dir / "real_file";
    const auto symlink1 = m_temp_dir / "symlink1";
    const auto symlink2 = m_temp_dir / "symlink2";
    
    { std::ofstream ofs(real_file); }
    std::filesystem::create_symlink(real_file, symlink1);
    std::filesystem::create_symlink(real_file, symlink2);
    
    const std::unordered_set<std::string> paths = {
        symlink1.string(),
        symlink2.string(),
        real_file.string()
    };
    const auto result = resolveLinks(paths);
    
    // All three should resolve to the same file
    ASSERT_EQ(result.size(), 1u);
}

TEST_F(ShellsFinderTest, resolveLinks_empty_input_returns_empty)
{
    const std::unordered_set<std::string> paths = {};
    const auto result = resolveLinks(paths);
    
    EXPECT_TRUE(result.empty());
}

// ============== filterToValidShells Tests ==============

TEST_F(ShellsFinderTest, filterToValidShells_bash_is_valid)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    const std::unordered_set<std::string> paths = {"/usr/bin/bash"};
    const auto result = filterToValidShells(paths);
    
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result.begin()->shell_type, ShellType::BASH);
}

TEST_F(ShellsFinderTest, filterToValidShells_non_shell_filtered_out)
{
    const std::unordered_set<std::string> paths = {"/usr/bin/ls"};
    const auto result = filterToValidShells(paths);
    
    EXPECT_TRUE(result.empty());
}

TEST_F(ShellsFinderTest, filterToValidShells_empty_input_returns_empty)
{
    const std::unordered_set<std::string> paths = {};
    const auto result = filterToValidShells(paths);
    
    EXPECT_TRUE(result.empty());
}

TEST_F(ShellsFinderTest, filterToValidShells_deduplicates_by_inode_dev)
{
    if (!std::filesystem::exists("/usr/bin/bash"))
    {
        GTEST_SKIP() << "/usr/bin/bash not found";
    }

    // Even if we pass the same path multiple times (shouldn't happen with set),
    // the result should still deduplicate by inode/dev
    const std::unordered_set<std::string> paths = {"/usr/bin/bash"};
    const auto result = filterToValidShells(paths);
    
    EXPECT_EQ(result.size(), 1u);
}

// ============== getUniqueShellsFromEtcShells Integration Tests ==============

TEST_F(ShellsFinderTest, getUniqueShellsFromEtcShells_returns_shells)
{
    const auto result = ShellsFinder::getUniqueShellsFromEtcShells();
    
    // Should find at least one shell on most systems
    EXPECT_FALSE(result.empty());
    
    // All results should have valid shell types
    for (const auto& shell : result)
    {
        EXPECT_NE(shell.shell_type, ShellType::UNKNOWN);
        EXPECT_FALSE(shell.path.empty());
        EXPECT_GT(shell.inode, 0u);
    }
}

TEST_F(ShellsFinderTest, getUniqueShellsFromEtcShells_contains_bash_or_dash)
{
    const auto result = ShellsFinder::getUniqueShellsFromEtcShells();
    
    bool found_known_shell = false;
    for (const auto& shell : result)
    {
        if (shell.shell_type == ShellType::BASH || 
            shell.shell_type == ShellType::DASH)
        {
            found_known_shell = true;
            break;
        }
    }
    
    EXPECT_TRUE(found_known_shell) << "Expected to find at least bash or dash";
}

TEST_F(ShellsFinderTest, getUniqueShellsFromEtcShells_no_duplicates)
{
    const auto result = ShellsFinder::getUniqueShellsFromEtcShells();
    
    // Check for duplicate inode/dev combinations manually
    std::set<std::pair<unsigned long, unsigned int>> seen;
    for (const auto& shell : result)
    {
        auto key = std::make_pair(shell.inode, shell.dev);
        EXPECT_TRUE(seen.find(key) == seen.end()) 
            << "Found duplicate inode/dev: " << shell.inode << "/" << shell.dev;
        seen.insert(key);
    }
}

TEST_F(ShellsFinderTest, getUniqueShellsFromEtcShells_returns_complete_info)
{
    const auto result = ShellsFinder::getUniqueShellsFromEtcShells();
    
    ASSERT_FALSE(result.empty());
    
    for (const auto& info : result)
    {
        EXPECT_GT(info.inode, 0u);
        EXPECT_GT(info.dev, 0u);
        EXPECT_GT(info.last_modified_time, 0u);
        EXPECT_FALSE(info.path.empty());
        EXPECT_NE(info.shell_type, ShellType::UNKNOWN);
    }
}

// ============== ShellBinaryInfoHash Tests ==============

TEST_F(ShellsFinderTest, ShellBinaryInfoHash_same_inode_dev_same_hash)
{
    ShellBinaryInfoHash hasher;
    
    ShellBinaryInfo info1;
    info1.inode = 100;
    info1.dev = 200;
    
    ShellBinaryInfo info2;
    info2.inode = 100;
    info2.dev = 200;
    info2.path = "/different/path";  // Different path but same inode/dev
    
    EXPECT_EQ(hasher(info1), hasher(info2));
}

TEST_F(ShellsFinderTest, ShellBinaryInfoHash_different_inode_different_hash)
{
    ShellBinaryInfoHash hasher;
    
    ShellBinaryInfo info1;
    info1.inode = 100;
    info1.dev = 200;
    
    ShellBinaryInfo info2;
    info2.inode = 101;
    info2.dev = 200;
    
    EXPECT_NE(hasher(info1), hasher(info2));
}

TEST_F(ShellsFinderTest, ShellBinaryInfoHash_different_dev_different_hash)
{
    ShellBinaryInfoHash hasher;
    
    ShellBinaryInfo info1;
    info1.inode = 100;
    info1.dev = 200;
    
    ShellBinaryInfo info2;
    info2.inode = 100;
    info2.dev = 201;
    
    EXPECT_NE(hasher(info1), hasher(info2));
}

}
