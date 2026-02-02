#include <gtest/gtest.h>
#include "logger.hpp"
#include "globals/global_strings.hpp"
#include <filesystem>

class TestEnvironment : public ::testing::Environment 
{
public:
    void SetUp() override 
    {
        owlsm::Logger::initialize(owlsm::globals::UNIT_TEST_LOG_PATH, LOG_LEVEL_DEBUG, true);
    }

    void TearDown() override 
    {
        owlsm::Logger::shutdown();
        std::error_code ec;
        std::filesystem::remove(owlsm::globals::UNIT_TEST_LOG_PATH, ec);
    }
};

int main(int argc, char **argv) 
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new TestEnvironment());
    return RUN_ALL_TESTS();
}