#include <gtest/gtest.h>
#include "rules_managment/rules_metadata_tracker.hpp"

class RulesMetadataTrackerTest : public ::testing::Test {};


TEST_F(RulesMetadataTrackerTest, get_existing_metadata)
{
    std::vector<owlsm::config::Rule> rules;
    rules.push_back({
        .id = 1,
        .metadata = {.description = "test"},
    });
    rules.push_back({
        .id = 2,
        .metadata = {.description = "aaa bb 123"},
    });
    owlsm::RulesMetadataTracker rules_metadata_tracker(rules);
    auto& metadata = rules_metadata_tracker.get_metadata(1);
    EXPECT_EQ(metadata.description, "test");
    auto& metadata2 = rules_metadata_tracker.get_metadata(2);
    EXPECT_EQ(metadata2.description, "aaa bb 123");
}

TEST_F(RulesMetadataTrackerTest, get_non_existing_metadata)
{
    std::vector<owlsm::config::Rule> rules;
    rules.push_back({
        .id = 1,
        .metadata = {.description = "test"},
    });
    owlsm::RulesMetadataTracker rules_metadata_tracker(rules);
    EXPECT_THROW(rules_metadata_tracker.get_metadata(5), std::runtime_error);
}

TEST_F(RulesMetadataTrackerTest, get_metadata_many_times)
{
    std::vector<owlsm::config::Rule> rules;
    rules.push_back({
        .id = 1,
        .metadata = {.description = "test"},
    });
    rules.push_back({
        .id = 2,
        .metadata = {.description = "aaa bb 123"},
    });
    owlsm::RulesMetadataTracker rules_metadata_tracker(rules);
    auto& metadata = rules_metadata_tracker.get_metadata(1);
    EXPECT_EQ(metadata.description, "test");
    auto& metadata2 = rules_metadata_tracker.get_metadata(2);
    EXPECT_EQ(metadata2.description, "aaa bb 123");
    auto& metadata3 = rules_metadata_tracker.get_metadata(1);
    EXPECT_EQ(metadata3.description, "test");
    auto& metadata4 = rules_metadata_tracker.get_metadata(2);
    EXPECT_EQ(metadata4.description, "aaa bb 123");
}

TEST_F(RulesMetadataTrackerTest, add_duplicate_rule_id_keeps_first)
{
    std::vector<owlsm::config::Rule> rules;
    rules.push_back({
        .id = 1,
        .metadata = {.description = "first"},
    });
    rules.push_back({
        .id = 1,
        .metadata = {.description = "second"},
    });
    owlsm::RulesMetadataTracker rules_metadata_tracker(rules);
    auto& metadata = rules_metadata_tracker.get_metadata(1);
    EXPECT_EQ(metadata.description, "first");
}