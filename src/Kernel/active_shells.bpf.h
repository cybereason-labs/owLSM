#pragma once
#include "common_maps.bpf.h"

statfunc void delete_pid_from_active_shell_pids(unsigned int pid)
{
    bpf_map_delete_elem(&active_shell_pids, &pid);
}
