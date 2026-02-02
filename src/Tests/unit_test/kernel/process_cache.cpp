#include "test_base.hpp"

process_cache_test aliveProcessCacheOperation(auto* skel, enum process_cache_operations op, int pid, int ppid = 0)
{
    int program_fd = bpf_program__fd(skel->progs.test_process_cache_program);
    int map_fd  = bpf_map__fd(skel->maps.test_alive_process_cache_map);
    int key = 0;
    process_cache_test t = {};
    t.operation = op;
    t.process.pid = pid;
    t.process.ppid = ppid;

    if(op == GET_ENTRY)
    {
        bpf_map_lookup_elem(map_fd, &key, &t);
    }
    else
    {
        bpf_map_update_elem(map_fd, &key, &t, BPF_ANY);
        struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
        if (bpf_prog_test_run_opts(program_fd, &opts)) {throw std::runtime_error("bpf_prog_test_run_opts failed");}
    }
    return t;
}

TEST_F(BpfTestBase, ProcessCache_alive)
{
    EXPECT_TRUE(aliveProcessCacheOperation(skel, GET_ENTRY, 1).process.ppid == 0);
    aliveProcessCacheOperation(skel, UPDATE_ENTRY, 1, 2);
    EXPECT_TRUE(aliveProcessCacheOperation(skel, GET_ENTRY, 1).process.ppid == 2);

    aliveProcessCacheOperation(skel, DELETE_ENTRY, 1);
    EXPECT_TRUE(aliveProcessCacheOperation(skel, GET_ENTRY, 1).process.ppid == 0);

    EXPECT_TRUE(aliveProcessCacheOperation(skel, GET_ENTRY, 77).process.ppid == 0);
    aliveProcessCacheOperation(skel, DELETE_ENTRY, 77);
    EXPECT_TRUE(aliveProcessCacheOperation(skel, GET_ENTRY, 77).process.ppid == 0);
    aliveProcessCacheOperation(skel, UPDATE_ENTRY, 77, 88);
    EXPECT_TRUE(aliveProcessCacheOperation(skel, GET_ENTRY, 77).process.ppid == 88);
}