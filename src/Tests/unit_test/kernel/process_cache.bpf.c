#include "shared_unit_tests_structs_definitions.h"
#include "process_cache.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct process_cache_test);
} test_alive_process_cache_map SEC(".maps");

SEC("raw_tp")
int test_process_cache_program(struct __sk_buff *skb)
{
    u32 key = 0;
    struct process_cache_test *p = bpf_map_lookup_elem(&test_alive_process_cache_map, &key);
    if (!p)
    {
        return 0;
    }

    switch(p->operation)
    {
        case UPDATE_ENTRY:
        {
            update_process_in_alive_process_cache(p->process.pid, &p->process);
            break;
        }
        case DELETE_ENTRY:
        {
            delete_process_from_alive_process_cache(p->process.pid);
            break;
        }
        case GET_ENTRY:
        {
            struct process_t *current = get_process_from_alive_process_cache(p->process.pid);
            bpf_probe_read_kernel(&p->process, sizeof(struct process_t), current);
            break;
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";