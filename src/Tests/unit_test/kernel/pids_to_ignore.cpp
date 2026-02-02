#include "test_base.hpp"

TEST_F(BpfTestBase, PidsToIgnore_IsCurrentPidRelatedTest)
{
    int program_fd = bpf_program__fd(skel->progs.test_program_related_pids_program);
    int map_fd  = bpf_map__fd(skel->maps.test_program_related_pids_map);
    unsigned int key = 0;
    int value = 0;
    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts))
    {
        throw std::runtime_error("bpf_prog_test_run_opts failed");
    }

    bpf_map_lookup_elem(map_fd, &key, &value);
    EXPECT_TRUE(value == 4);
}

TEST_F(BpfTestBase, PidsToIgnore_IsSystemTaskTest)
{
    int program_fd = bpf_program__fd(skel->progs.test_is_system_task_program);
    int map_fd  = bpf_map__fd(skel->maps.test_program_related_pids_map);
    unsigned int key = 0;
    int value = 0;
    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts))
    {
        throw std::runtime_error("bpf_prog_test_run_opts failed");
    }

    bpf_map_lookup_elem(map_fd, &key, &value);
    EXPECT_EQ(value, 0);
}

TEST_F(BpfTestBase, PidsToIgnore_IsTaskWithMmTest)
{
    int program_fd = bpf_program__fd(skel->progs.test_is_task_with_mm_program);
    int map_fd  = bpf_map__fd(skel->maps.test_program_related_pids_map);
    unsigned int key = 0;
    int value = 0;
    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts))
    {
        throw std::runtime_error("bpf_prog_test_run_opts failed");
    }

    bpf_map_lookup_elem(map_fd, &key, &value);
    EXPECT_EQ(value, 1);
}

TEST_F(BpfTestBase, PidsToIgnore_IsUserspaceProgramTest)
{
    int program_fd = bpf_program__fd(skel->progs.test_is_userspace_program_program);
    int map_fd  = bpf_map__fd(skel->maps.test_program_related_pids_map);
    unsigned int key = 0;
    int value = 0;
    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts))
    {
        throw std::runtime_error("bpf_prog_test_run_opts failed");
    }

    bpf_map_lookup_elem(map_fd, &key, &value);
    EXPECT_EQ(value, 1);
}