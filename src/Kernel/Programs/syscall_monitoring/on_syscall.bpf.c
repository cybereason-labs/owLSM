#include "common_maps.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "error_reports.bpf.h"

SEC("raw_tracepoint/sys_enter")
int syscall_enter(struct bpf_raw_tracepoint_args *ctx)
{
    set_hook_name("syscall_enter", 13);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(task, tgid);
    if(bpf_map_lookup_elem(&parent_processes_to_kill, &pid))
    {
        bpf_send_signal(SIGKILL);
        bpf_map_delete_elem(&parent_processes_to_kill, &pid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";