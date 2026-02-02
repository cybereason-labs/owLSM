#include "test_base.hpp"

int executeBpfProgram(auto* skel)
{
    int program_fd = bpf_program__fd(skel->progs.test_get_current_and_increment_tail_counter);
    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts)) {throw std::runtime_error("bpf_prog_test_run_opts failed");}
    return opts.retval;
}

TEST_F(BpfTestBase, TailCallCounter_GetCurrentAndIncrementTailCounterTest) 
{
    EXPECT_EQ(executeBpfProgram(skel), 0);
    EXPECT_EQ(executeBpfProgram(skel), 1);
    EXPECT_EQ(executeBpfProgram(skel), 2);

    int program_fd = bpf_program__fd(skel->progs.test_reset_tail_counter);
    struct bpf_test_run_opts opts = {.sz = sizeof(struct bpf_test_run_opts)};
    if (bpf_prog_test_run_opts(program_fd, &opts)) {throw std::runtime_error("bpf_prog_test_run_opts failed");}
    
    for(int i = 0; i < 50; ++i)
    {
        EXPECT_EQ(executeBpfProgram(skel), i);
    }
}