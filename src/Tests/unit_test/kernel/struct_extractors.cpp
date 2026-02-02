#include "test_base.hpp"
#include "map_populator.hpp"
#include <gtest/gtest.h>
#include <string>
#include <cstring>
#include <filesystem>
#include <fstream>

struct StructExtractorsGetPathFromPathTestCase 
{ 
    std::string path;
    bool create_path; 
    bool is_directory;
};


void create_chown_delete(const std::string& path, bool create, bool directory)
{
    std::error_code ec;

    std::filesystem::remove(path, ec);
    if (std::filesystem::exists(path, ec)) 
    {
        throw std::runtime_error("Path exists: " + path);
    }

    if (create) 
    {
        if (directory)
        {
            std::filesystem::create_directories(path, ec);
            if (ec) throw std::runtime_error("create_directories");
        }
        else
        {
            std::filesystem::create_directories(std::filesystem::path{path}.parent_path(), ec);
            if (ec) throw std::runtime_error("create_directories parent path");

            std::ofstream os{path};
            if (!std::filesystem::exists(path)) throw std::runtime_error("file create");
        }
    }

    std::string path_to_chown = create ? path : "/opt";
    if (::chown(path_to_chown.c_str(), 0, 0) != 0)
    {
        throw std::runtime_error("chown");
    }

    if (directory)
        std::filesystem::remove_all(path, ec);  
    else
        std::filesystem::remove(path, ec);
}


bool executeBpfProgramGetPathFromPath(auto* skel, const StructExtractorsGetPathFromPathTestCase& test_case, int map_fd)
{
    struct struct_extractors_test t = {};
    std::strncpy(t.path_to_find, test_case.path.c_str(), PATH_MAX - 1);
    t.path_to_find[PATH_MAX - 1] = '\0';
    
    unsigned int key = 0;
    bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);

    create_chown_delete(test_case.path, test_case.create_path, test_case.is_directory);
    bpf_map_lookup_elem(map_fd, &key, &t);
    bool result = t.found;
    return result;
}

TEST_F(BpfTestBase, StructExtractors_GetPathFromPath) 
{
    const auto map_fd  = bpf_map__fd(skel->maps.struct_extractors_test_map);
    struct bpf_link *lsm_link = bpf_program__attach_lsm(skel->progs.test_get_path_from_path);
    if (!lsm_link) 
    {
        throw std::runtime_error("run_get_path_from_path_tests attach failed");
    }

    std::string max_path_length = "/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmno";
    std::string path_too_long = "/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmnop/abcdefghijklmno/abcdefghijklmno";
    std::string to_many_path_components = "/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/";
    std::string path_component_to_long = std::string("/" + std::string(130 , 'a'));
    std::string invalid_path = "tmp/t1";
    std::string weird_path = "/aaaaaa/bbbbbb !%^$&*@().,bb#bb    bbbb/bb/b/b/b/b/cc-=_ cc ccc/.txt";

    // Files
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {max_path_length, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_too_long, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {to_many_path_components, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_component_to_long, true, false}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {invalid_path, true, false}, map_fd));
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {weird_path, true, false}, map_fd));

    // Directories
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {max_path_length, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_too_long, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {to_many_path_components, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {path_component_to_long, true, true}, map_fd));
    EXPECT_FALSE(executeBpfProgramGetPathFromPath(skel, {invalid_path, true, true}, map_fd));
    EXPECT_TRUE(executeBpfProgramGetPathFromPath(skel, {weird_path, true, true}, map_fd));
    bpf_link__destroy(lsm_link);
}

bool executeBpfProgramGetCmdFromTask(auto* skel, const std::string& cmd, bool should_find = true)
{
    MapPopulatorTest::clear_string_maps(skel);
    MapPopulatorTest::populate_string_maps(skel, cmd, COMPARISON_TYPE_CONTAINS);
    
    int map_fd  = bpf_map__fd(skel->maps.struct_extractors_test_map);
    struct bpf_link *lsm_link = bpf_program__attach_lsm(skel->progs.test_get_cmd_from_task);
    if (!lsm_link) 
    {
        throw std::runtime_error("run_get_cmd_from_task_tests attach failed");
    }

    struct struct_extractors_test t = {};
    std::strncpy(t.cmd_to_find, cmd.c_str(), CMD_MAX);
    t.cmd_length = cmd.size();
    t.dfa_id = MapPopulatorTest::get_test_id();
    t.found = 0;
    unsigned int key = 0;
    bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);

    if (should_find)
    {
        std::system(("echo '" + cmd + "' &>/dev/null").c_str());
    }
    else 
    {
        std::system(std::string("echo random stuff &>/dev/null").c_str());
    }

    bpf_map_lookup_elem(map_fd, &key, &t);
    bpf_link__destroy(lsm_link);
    
    MapPopulatorTest::clear_string_maps(skel);
    
    bool result = t.found;
    return result;
}

TEST_F(BpfTestBase, StructExtractors_GetCmdFromTask) 
{
    EXPECT_TRUE(executeBpfProgramGetCmdFromTask(skel, R"(-t -f /d *#^@%"!  \"rbz./1b~`c)"));
    EXPECT_TRUE(executeBpfProgramGetCmdFromTask(skel, R"(this is the RULE_CMD_MAX length!)"));
    EXPECT_TRUE(executeBpfProgramGetCmdFromTask(skel, R"(aaa)"));
    EXPECT_FALSE(executeBpfProgramGetCmdFromTask(skel, R"(aaa)", false));
}