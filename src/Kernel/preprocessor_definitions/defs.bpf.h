#pragma once
#include "bpf_header_includes.h"
#include "events_structs.h"

#define statfunc static __attribute__((always_inline))
          
#define LIMIT_PATH_SIZE(x)           ((x) & (PATH_MAX - 1)) 

#define ALLOW 0
#define DENY -1

#define SUCCESS 0
#define GENERIC_ERROR -1
#define NOT_IN_CACHE -2
#define NOT_SUPPORTED -3

#define TRUE 1
#define FALSE 0

#define SIGKILL 9