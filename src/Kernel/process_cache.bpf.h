#pragma once
#include "error_reports.bpf.h"
#include "struct_extractors.bpf.h"
#include "allocators.bpf.h"

statfunc void delete_process_from_alive_process_cache(u32 pid)
{
    // bpf_map_delete_elem is a concurrent function - https://elixir.bootlin.com/linux/v6.14.7/source/kernel/bpf/syscall.c#L1790
    bpf_map_delete_elem(&alive_process_cache_map, &pid); 
}

statfunc int update_process_in_cache(const void *key, const struct process_t *p, void* cache) 
{
    int result = SUCCESS;
    struct process_t * tmp = allocate_process_t(); 
    if(!tmp)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_process_t failed");
        result = GENERIC_ERROR;
    }
    else if(bpf_probe_read_kernel(tmp, sizeof(struct process_t), p) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        result = GENERIC_ERROR;
    }
    // bpf_map_update_elem is a concurrent function - https://docs.kernel.org/bpf/map_hash.html#bpf-map-update-elem
    else if(bpf_map_update_elem(cache, key, tmp, BPF_ANY) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_map_update_elem failed");
        result = GENERIC_ERROR;
    }
    return result;
}

statfunc struct process_t *get_process_from_cache(void* cache, const void* key)
{
    struct process_t *ent;
    ent = bpf_map_lookup_elem(cache, key);
    if (!ent)
    {
        return NULL;
    }

    struct process_t *p = allocate_process_t(); 
    if(!p)
    {
        REPORT_ERROR(GENERIC_ERROR, "allocate_process_t failed");
        p = NULL;
    }
    else if(bpf_probe_read_kernel(p, sizeof(struct process_t), ent) != SUCCESS)
    {
        REPORT_ERROR(GENERIC_ERROR, "bpf_probe_read_kernel failed");
        p = NULL;
    }

    return p;
}

statfunc int update_process_in_alive_process_cache(u32 pid, const struct process_t *p) 
{
    return update_process_in_cache(&pid, p, &alive_process_cache_map);
}

statfunc int add_process_to_dead_proccesses_lru(const struct process_t *p)
{
    return update_process_in_cache(&p->unique_process_id, p, &dead_process_cache_lru_map);
}

// TODO - This function has a race condition. Another CPU can delete/update the value of ent until bpf_probe_read_kernel finishes. Find a way to solve race.  
// We will need to understand if we had a race, and if so, create the process from zero.
statfunc struct process_t *get_process_from_alive_process_cache(u32 pid)
{
    return get_process_from_cache(&alive_process_cache_map, &pid);
}

statfunc struct process_t *get_process_from_dead_proccesses_lru(unsigned long long unique_process_id)
{
    return get_process_from_cache(&dead_process_cache_lru_map, &unique_process_id);
}

statfunc struct process_t *get_process_from_caches(unsigned int pid, unsigned long long unique_process_id)
{
    struct process_t *p = get_process_from_alive_process_cache(pid);
    return p ? p : get_process_from_dead_proccesses_lru(unique_process_id);
}

statfunc int is_process_in_alive_process_cache(unsigned int pid)
{
    return bpf_map_lookup_elem(&alive_process_cache_map, &pid) != NULL ? TRUE : FALSE;
}