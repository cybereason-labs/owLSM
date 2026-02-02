#include "fill_event_structs.bpf.h"
#include "pids_to_ignore.bpf.h"

SEC("fentry/do_exit")
int BPF_PROG(exit_hook, long code)
{
    set_hook_name("exit_hook", 9);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pid_t tgid = BPF_CORE_READ(task, tgid);
    pid_t pid  = BPF_CORE_READ(task, pid);
    
    if(!is_userspace_program())
    {
        bpf_map_delete_elem(&kthread_exec_pids, &pid);
        return ALLOW;
    }

    if (tgid != pid) 
    {
        return ALLOW; 
    }
    
    if(is_current_pid_related())
    {
        remove_current_pid_from_related_pids();
        return 0;
    }
    pid = tgid;
    struct event_t *event = allocate_event_with_basic_stats();
    if (!event)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_event_with_basic_stats failed pid: %d", pid);
        goto do_exit_end;
    }

    event->type = EXIT;
    fill_exit_event_t(&event->data.exit, code);
    fill_event_process_from_cache(&event->process);
    fill_event_parent_process_from_cache(&event->process, &event->parent_process);

    add_process_to_dead_proccesses_lru(&event->process);
    bpf_ringbuf_submit(event, 0);

do_exit_end:
    delete_process_from_alive_process_cache(pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";