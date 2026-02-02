#include "tail_calls_manager.bpf.h"

SEC("raw_tp")
int test_get_current_and_increment_tail_counter(struct __sk_buff *skb)
{
    return get_current_and_increment_tail_counter();
}

SEC("raw_tp")
int test_reset_tail_counter(struct __sk_buff *skb)
{
    reset_tail_counter();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";