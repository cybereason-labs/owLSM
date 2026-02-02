#include "shared_unit_tests_structs_definitions.h"
#include "error_reports.bpf.h"
#include "pids_to_ignore.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, int);
} test_program_related_pids_map SEC(".maps");

SEC("raw_tp")
int test_program_related_pids_program(struct __sk_buff *skb)
{
    u32 key = 0;
    int *t = bpf_map_lookup_elem(&test_program_related_pids_map, &key);
    if (!t)
    {
        return 0;
    }

    int result = 0;
    if(!is_current_pid_related())
    {
        ++result;
    }
    
    add_current_pid_to_related_pids();
    if(is_current_pid_related())
    {
        ++result;
    }

    remove_current_pid_from_related_pids();
    if(!is_current_pid_related())
    {
        ++result;
    }

    add_pid_to_related_pids(bpf_get_current_pid_tgid() >> 32);
    if(is_current_pid_related())
    {
        ++result;
    }

    *t = result;
    return 0;
}

SEC("raw_tp")
int test_is_system_task_program(struct __sk_buff *skb)
{
    u32 key = 0;
    int *t = bpf_map_lookup_elem(&test_program_related_pids_map, &key);
    if (!t)
    {
        return 0;
    }

    *t = is_system_task();
    return 0;
}

SEC("raw_tp")
int test_is_task_with_mm_program(struct __sk_buff *skb)
{
    u32 key = 0;
    int *t = bpf_map_lookup_elem(&test_program_related_pids_map, &key);
    if (!t)
    {
        return 0;
    }

    *t = is_task_with_mm();
    return 0;
}

SEC("raw_tp")
int test_is_userspace_program_program(struct __sk_buff *skb)
{
    u32 key = 0;
    int *t = bpf_map_lookup_elem(&test_program_related_pids_map, &key);
    if (!t)
    {
        return 0;
    }
    *t = is_userspace_program();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";