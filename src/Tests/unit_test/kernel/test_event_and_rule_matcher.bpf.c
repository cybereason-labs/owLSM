#include "shared_unit_tests_structs_definitions.h"
#include "event_and_rule_matcher.bpf.h"
#include "tail_calls_manager.bpf.h"

// Test structure to pass event and rule to test program
struct event_and_rule_matcher_test
{
    struct event_t event;
    struct rule_t rule;
    int actual_result;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key,   u32);
    __type(value, struct event_and_rule_matcher_test);
} event_and_rule_matcher_test_map SEC(".maps");

SEC("raw_tp")
int test_event_and_rule_matcher_test_program(struct __sk_buff *skb)
{
    bpf_printk("test_event_and_rule_matcher_test_program\n");
    u32 key = 0;
    struct event_and_rule_matcher_test *t = bpf_map_lookup_elem(&event_and_rule_matcher_test_map, &key);
    if (!t)
    {
        bpf_printk("test_event_and_rule_matcher_test_program: map lookup failed\n");
        return 0;
    }
    store_currently_handled_event(&t->event);

    t->actual_result = evaluate_rule_against_event(&t->rule, &t->event);
    bpf_printk("test_event_and_rule_matcher_test_program: actual_result: %d\n", t->actual_result);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";