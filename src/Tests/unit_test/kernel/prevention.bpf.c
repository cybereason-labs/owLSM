#include "shared_unit_tests_structs_definitions.h"
#include "prevention.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct prevention_test);
} test_prevention_map SEC(".maps");

SEC("raw_tp")
int test_prevention_program(struct __sk_buff *skb)
{
    u32 key = 0;
    struct prevention_test *t = bpf_map_lookup_elem(&test_prevention_map, &key);
    if (!t)
    {
        return 0;
    }

    t->result = is_process_created_after_ebpf_attached(&t->process_start_time);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";