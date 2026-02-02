#include "test_base.hpp"
#include <gtest/gtest.h>
#include <string>
#include <cstring>

void setup(auto* skel)
{
    unsigned long long prog_start_ns = 10;
    unsigned int key = 0;
    int map_fd = bpf_map__fd(skel->maps.ebpf_program_start_time);
    if (bpf_map_update_elem(map_fd, &key, &prog_start_ns, BPF_ANY) < 0)
    {
        throw std::runtime_error("save_ebpf_attach_time: bpf_map_update_elem");
    }
    if (bpf_map_freeze(map_fd) < 0)
    {
        throw std::runtime_error("bpf_map_freeze (BPF_MAP_FREEZE)");
    }
}

bool executeBpfProgram(auto* skel, unsigned int ms, int expected)
{
    int program_fd = bpf_program__fd(skel->progs.test_prevention_program);
    int test_map_fd  = bpf_map__fd(skel->maps.test_prevention_map);

    prevention_test t{};
    t.process_start_time = ms;
    t.result = -1;

    unsigned int key = 0;
    bpf_map_update_elem(test_map_fd, &key, &t, BPF_ANY);

    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts))
    {
        throw std::runtime_error("bpf_prog_test_run_opts failed");
    }

    bpf_map_lookup_elem(test_map_fd, &key, &t);
    return t.result == expected;
}

TEST_F(BpfTestBase, Prevention_ProcessCreatedAfterEbpfAttachedTest)
{
    EXPECT_NO_THROW(setup(skel));
    EXPECT_TRUE(executeBpfProgram(skel, 1, 0));
    EXPECT_TRUE(executeBpfProgram(skel, 9, 0));
    EXPECT_TRUE(executeBpfProgram(skel, 10, 0));
    EXPECT_TRUE(executeBpfProgram(skel, 11, 1));
    EXPECT_TRUE(executeBpfProgram(skel, 100000000, 1));
}