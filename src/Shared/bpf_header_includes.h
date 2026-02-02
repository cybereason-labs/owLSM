#pragma once
#ifdef __BPF_KERNEL__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#else

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#endif // __KERNEL__