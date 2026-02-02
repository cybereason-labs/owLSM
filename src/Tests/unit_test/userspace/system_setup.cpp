#include "system_setup.hpp"
#include "globals/global_strings.hpp"

#include <gtest/gtest.h>
#include <filesystem>


class SystemSetupTest : public ::testing::Test 
{
public:
    static bool start() { return owlsm::SystemSetup::start(); }
    static bool isBpfFsAvailable() { return owlsm::SystemSetup::isBpfFsAvailable(); }
    static bool tryCreateBpfFsDirectory() { return owlsm::SystemSetup::tryCreateBpfFsDirectory(); }
    static bool cleanupOwlsmDirectory() { return owlsm::SystemSetup::cleanupOwlsmDirectory(); }
};



TEST_F(SystemSetupTest, start_owlsm_dir_exists)
{
    std::filesystem::create_directories(owlsm::globals::SYS_FS_BPF_OWLSM_PATH);
    ASSERT_TRUE(SystemSetupTest::start());
}

TEST_F(SystemSetupTest, start_owlsm_dir_does_not_exist)
{
    std::error_code ec;
    std::filesystem::remove(owlsm::globals::SYS_FS_BPF_OWLSM_PATH, ec);
    ASSERT_FALSE(std::filesystem::exists(owlsm::globals::SYS_FS_BPF_OWLSM_PATH));
    ASSERT_TRUE(SystemSetupTest::start());
}

TEST_F(SystemSetupTest, isBpfFsAvailable_true)
{
    ASSERT_TRUE(SystemSetupTest::isBpfFsAvailable());
}

TEST_F(SystemSetupTest, cleanupOwlsmDirectory_owlsm_dir_exists)
{
    std::filesystem::create_directories(owlsm::globals::SYS_FS_BPF_OWLSM_PATH);
    ASSERT_TRUE(std::filesystem::exists(owlsm::globals::SYS_FS_BPF_OWLSM_PATH));
    ASSERT_TRUE(SystemSetupTest::cleanupOwlsmDirectory());
    ASSERT_FALSE(std::filesystem::exists(owlsm::globals::SYS_FS_BPF_OWLSM_PATH));
}

TEST_F(SystemSetupTest, cleanupOwlsmDirectory_owlsm_dir_does_not_exist)
{
    std::error_code ec;
    std::filesystem::remove_all(owlsm::globals::SYS_FS_BPF_OWLSM_PATH, ec);
    ASSERT_FALSE(std::filesystem::exists(owlsm::globals::SYS_FS_BPF_OWLSM_PATH));
    ASSERT_TRUE(SystemSetupTest::cleanupOwlsmDirectory());
}