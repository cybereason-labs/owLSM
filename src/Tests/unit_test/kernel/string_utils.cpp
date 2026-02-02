#include "test_base.hpp"
#include "map_populator.hpp"
#include <string>
#include <cstring>

struct StringUtilsTestCase 
{ 
    std::string haystack;
    std::string needle; 
    enum comparison_type test_type;
};

template<typename T>
bool executeBpfProgram(T* skel, const StringUtilsTestCase& test_case)
{
    MapPopulatorTest::clear_string_maps(skel);
    MapPopulatorTest::populate_string_maps(skel, test_case.needle, test_case.test_type);
    
    int program_fd = bpf_program__fd(skel->progs.test_string_utils_program);
    int map_fd  = bpf_map__fd(skel->maps.test_string_utils_map);
    
    string_utils_test t{};
    t.id = MapPopulatorTest::get_test_id();
    strncpy(t.haystack, test_case.haystack.c_str(), PATH_MAX);
    strncpy(t.needle,   test_case.needle.c_str(), MAX_NEEDLE_LENGTH);
    t.haystack_length = test_case.haystack.length();
    t.needle_length = test_case.needle.length();
    t.test_type = test_case.test_type;
    t.actual_result = -1;

    unsigned int key = 0;
    bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);
    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts)) {throw std::runtime_error("bpf_prog_test_run_opts failed");}

    bpf_map_lookup_elem(map_fd, &key, &t);
    
    MapPopulatorTest::clear_string_maps(skel);
    
    return t.actual_result;
}

TEST_F(BpfTestBase, StringUtils_ExactMatchTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello worl", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "ello worl", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "helloworld", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_EXACT_MATCH}));
}

TEST_F(BpfTestBase, StringUtils_ContainsTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "world", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world!", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "acd", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"foo", "", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "foo", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string(PATH_MAX - 1, 'a').c_str(), std::string(MAX_NEEDLE_LENGTH, 'a').c_str(), COMPARISON_TYPE_CONTAINS}));
}

TEST_F(BpfTestBase, StringUtils_StartsWithTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "world", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world!", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "acd", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"foo", "", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "foo", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string(PATH_MAX - 1, 'a').c_str(), std::string(MAX_NEEDLE_LENGTH, 'a').c_str(), COMPARISON_TYPE_STARTS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_EndsWithTest) 
{
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "world", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello world!", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abcd", "acd", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"foo", "", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "foo", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"", "", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{std::string(PATH_MAX - 1, 'a').c_str(), std::string(MAX_NEEDLE_LENGTH, 'a').c_str(), COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_SpecialCharactersTest) 
{
    // Test with special characters (file paths)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "/usr/bin/bash", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "/usr", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "bash", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"/usr/bin/bash", "bin", COMPARISON_TYPE_CONTAINS}));
    
    // Test with special regex-like characters (should be treated literally)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test.*file", ".*", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"file[123]", "[123]", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test$var", "$var", COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_RepeatedPatternsTest) 
{
    // Test patterns with repeated characters (stress test for KMP DFA)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aaaaaab", "aaab", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abababab", "ababab", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abcabc", COMPARISON_TYPE_CONTAINS}));
    
    // Partial matches that should fail
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abababab", "abababac", COMPARISON_TYPE_CONTAINS}));
    
    // Test with pattern at the very end
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"xxxxxxxxxabc", "abc", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"xxxxxxxxxabc", "abc", COMPARISON_TYPE_ENDS_WITH}));
    
    // Test with pattern at the very beginning
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcxxxxxxxxx", "abc", COMPARISON_TYPE_STARTS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_SingleCharacterTest) 
{
    // Single character searches
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"a", "a", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "a", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "c", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "b", COMPARISON_TYPE_CONTAINS}));
    
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"abc", "d", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"a", "b", COMPARISON_TYPE_EXACT_MATCH}));
    
    // Single character repeated
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aaaa", "a", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"baaa", "a", COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_CaseSensitivityTest) 
{
    // Verify case sensitivity (all should be case-sensitive)
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "hello world", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "hello", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "WORLD", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "HELLO", COMPARISON_TYPE_CONTAINS}));
    
    // Same case should match
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "Hello", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "World", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"Hello World", "lo Wo", COMPARISON_TYPE_CONTAINS}));
}

TEST_F(BpfTestBase, StringUtils_WhitespaceTest) 
{
    // Test with various whitespace
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", " ", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"  leading", "  ", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"trailing  ", "  ", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"\t\n", "\t\n", COMPARISON_TYPE_EXACT_MATCH}));
    
    // Whitespace differences should fail exact match
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello world", "hello  world", COMPARISON_TYPE_EXACT_MATCH}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"hello\tworld", "hello world", COMPARISON_TYPE_EXACT_MATCH}));
}

TEST_F(BpfTestBase, StringUtils_OverlappingPatternTest) 
{
    // Test overlapping patterns where naive search might fail (critical for DFA correctness)
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"aabaacaabaa", "aabaa", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abacababc", "ababc", COMPARISON_TYPE_CONTAINS}));
    
    // Pattern appears multiple times
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abc", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abc", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"abcabcabc", "abc", COMPARISON_TYPE_ENDS_WITH}));
    
    // Complex overlapping pattern
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"ababababc", "ababc", COMPARISON_TYPE_CONTAINS}));
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{"ababababd", "ababc", COMPARISON_TYPE_CONTAINS}));
}

TEST_F(BpfTestBase, StringUtils_NumericTest) 
{
    // Numeric strings
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "123", COMPARISON_TYPE_STARTS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "345", COMPARISON_TYPE_ENDS_WITH}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "234", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"12345", "12345", COMPARISON_TYPE_EXACT_MATCH}));
    
    // Mixed alphanumeric
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"test123file", "123", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"v1.2.3", "1.2", COMPARISON_TYPE_CONTAINS}));
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{"file_v2.0.1", "v2.0.1", COMPARISON_TYPE_ENDS_WITH}));
}

TEST_F(BpfTestBase, StringUtils_BoundaryLengthTest) 
{
    // Test at MAX_NEEDLE_LENGTH boundary (32 bytes)
    std::string max_needle(MAX_NEEDLE_LENGTH, 'x');
    std::string haystack_with_max(PATH_MAX - 1, 'x');
    
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{haystack_with_max, max_needle, COMPARISON_TYPE_CONTAINS}));
    std::string needle_31(MAX_NEEDLE_LENGTH - 1, 'a');
    std::string haystack_31(MAX_NEEDLE_LENGTH - 1, 'a');
    EXPECT_TRUE(executeBpfProgram(skel, StringUtilsTestCase{haystack_31, needle_31, COMPARISON_TYPE_EXACT_MATCH}));
    
    // Test with different character at boundary
    std::string needle_max_b(MAX_NEEDLE_LENGTH, 'b');
    EXPECT_FALSE(executeBpfProgram(skel, StringUtilsTestCase{haystack_with_max, needle_max_b, COMPARISON_TYPE_CONTAINS}));
}