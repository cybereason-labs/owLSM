#pragma once
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef WRITE_EVENT
struct {
        __uint(type,       BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 8192);
        __type(key,        unsigned long long);
        __type(value,      unsigned char);
} global_write_event_cache_lru_map SEC(".maps");

struct {
        __uint(type,       BPF_MAP_TYPE_LRU_PERCPU_HASH);
        __uint(max_entries, 512);
        __type(key,        unsigned long long);
        __type(value,      unsigned char);
} private_write_event_cache_lru_map SEC(".maps");
#endif //WRITE_EVENT

#ifdef READ_EVENT
struct {
        __uint(type,       BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 8192);
        __type(key,        unsigned long long);
        __type(value,      unsigned char);
} global_read_event_cache_lru_map SEC(".maps");

struct {
        __uint(type,       BPF_MAP_TYPE_LRU_PERCPU_HASH);
        __uint(max_entries, 512);
        __type(key,        unsigned long long);
        __type(value,      unsigned char);
} private_read_event_cache_lru_map SEC(".maps");
#endif //READ_EVENT

statfunc unsigned long long calculate_event_hash(struct file *file)
{
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    int pid = BPF_CORE_READ(task, tgid);
    unsigned long long start_time = BPF_CORE_READ(task, start_time);
    unsigned long long unique_process_id = build_process_unique_id(pid, start_time);
    unsigned long long inode = BPF_CORE_READ(file, f_inode, i_ino);
    unsigned long long dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    unsigned long long dentry_ptr = (unsigned long long)BPF_CORE_READ(file, f_path.dentry); // different files can have a the same inode. So must look at both file and inode.

    const unsigned long long magic = 0x9e3779b97f4a7c15ULL;
    uint64_t h = unique_process_id;
    h ^= inode  + magic + (h << 6) + (h >> 2);
    h ^= dev + magic + (h << 6) + (h >> 2);
    h ^= dentry_ptr + magic + (h << 6) + (h >> 2);
    return h;
}

statfunc int get_event_verdict_from_cache(void *per_cpu_lru, void *global_lru, const unsigned long long * key)
{
    unsigned char * val = bpf_map_lookup_elem(per_cpu_lru, key);
    if (val)
    {
        return *val;
    }

    val = bpf_map_lookup_elem(global_lru, key);
    if (val) 
    {
        bpf_map_update_elem(per_cpu_lru, key, val, BPF_ANY);
        return *val;
    }

    return NOT_IN_CACHE;
}

statfunc void update_event_verdict_to_cache(void *private_lru, void *public_lru, const unsigned long long * key, unsigned char verdict)
{
    bpf_map_update_elem(public_lru, key, &verdict, BPF_ANY);
    bpf_map_update_elem(private_lru, key, &verdict, BPF_ANY);
}

#ifdef WRITE_EVENT
statfunc int get_write_event_verdict_from_cache(const unsigned long long * key)
{
    return get_event_verdict_from_cache(&private_write_event_cache_lru_map, &global_write_event_cache_lru_map, key);
}

statfunc void update_write_event_verdict_to_cache(const unsigned long long * key, unsigned char verdict)
{
    update_event_verdict_to_cache(&private_write_event_cache_lru_map, &global_write_event_cache_lru_map, key, verdict);
}
#endif // WRITE_EVENT

#ifdef READ_EVENT
statfunc int get_read_event_verdict_from_cache(const unsigned long long * key)
{
    return get_event_verdict_from_cache(&private_read_event_cache_lru_map, &global_read_event_cache_lru_map, key);
}

statfunc void update_read_event_verdict_to_cache(const unsigned long long * key, unsigned char verdict)
{
    update_event_verdict_to_cache(&private_read_event_cache_lru_map, &global_read_event_cache_lru_map, key, verdict);
}
#endif // READ_EVENT