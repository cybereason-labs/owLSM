# AGENTS.md - Unit Tests

## Overview

The Unit Tests component contains Google Test (gtest) based unit tests for both eBPF kernel code and C++ userspace code. Kernel tests use BPF skeleton loading to test eBPF functions in isolation. Userspace tests directly test C++ classes and functions.

### Types of Unit Tests

1. **Kernel Tests** (`kernel/`) - Test eBPF functions by small ebpf programs that wrap the target ebpf function. Then loading them and verifying their behavior through BPF maps
2. **Userspace Tests** (`userspace/`) - Standard C++ unit tests for userspace components

---

## Project Structure

```
unit_test/
├── AGENTS.md                    # This file
├── Makefile                     # Build rules
├── main.cpp                     # Test runner entry point
├── kernel/                      # eBPF unit tests
│   ├── test_base.hpp            # Base class for kernel tests
│   ├── map_populator.hpp        # Helper to populate BPF maps
│   ├── shared_unit_tests_structs_definitions.h  # Test-specific structs
│   ├── *.bpf.c                  # Test eBPF programs
│   └── *.cpp                    # Test implementations
└── userspace/                   # Userspace unit tests
    ├── configuration/           # Config parsing tests
    ├── rule_managment/          # Rule management tests
    └── system_setup.cpp         # System setup tests
```

### Kernel Test Organization

Each kernel feature has two files:
- `feature.bpf.c` - eBPF test program that exercises the feature
- `feature.cpp` - C++ test that loads the eBPF program and validates via maps

Example:
```
kernel/
├── string_utils.bpf.c     # eBPF program testing string functions
├── string_utils.cpp       # C++ test loading above program
├── process_cache.bpf.c    # eBPF program testing process cache
├── process_cache.cpp      # C++ test loading above program
└── ...
```

---

## Build and Run

### Build Tests

```bash
# Inside Docker container
make test -j$(nproc)
```

### Run Tests

```bash
# On HOST (not in container) - requires root for eBPF loading
sudo ./build/unit_tests/bin/unit_tests

# Run specific test
sudo ./build/unit_tests/bin/unit_tests --gtest_filter="TestSuiteName.TestName"

# List all tests
./build/unit_tests/bin/unit_tests --gtest_list_tests
```

---

## Concepts and Design

### Kernel Test Pattern

1. **BPF Program** (`*.bpf.c`) - Contains test logic that runs in kernel
2. **Test Fixture** (`*.cpp`) - Loads BPF program, sets up inputs via maps, triggers execution, reads results from maps

```cpp
// Example: kernel/string_utils.cpp
class StringUtilsTest : public TestBase
{
protected:
    void SetUp() override
    {
        // Load BPF program
        loadBpfProgram("string_utils.bpf.o");
    }
};

TEST_F(StringUtilsTest, TestContains)
{
    // Populate input map
    populateMap("input_map", test_data);
    
    // Trigger BPF program
    triggerProgram();
    
    // Read result from output map
    auto result = readMap("output_map");
    EXPECT_EQ(result, expected);
}
```

### TestBase Class

`kernel/test_base.hpp` provides:
- BPF program loading/unloading
- Map access helpers
- Program triggering utilities

---

## How to Add New Tests

### Adding Kernel Tests

1. Create `kernel/your_feature.bpf.c`:
```c
#include "shared_unit_tests_structs_definitions.h"

SEC("syscall") // or appropriate program type
unsigned int test_your_feature(struct __sk_buff *skb)
{
    return result;
}

char LICENSE[] SEC("license") = "GPL";
```

2. Create `kernel/your_feature.cpp`:
```cpp
#include "test_base.hpp"
#include <gtest/gtest.h>

class YourFeatureTest : public TestBase
{
    // Test fixture
};

TEST_F(YourFeatureTest, TestCase1)
{
    // Test implementation
}
```

3. Add source files to `Makefile`

### Adding Userspace Tests

1. Create test file in appropriate subdirectory under `userspace/`
2. Use standard Google Test patterns
3. Add source file to `Makefile`

---

## Important Notes

- Kernel tests require running on HOST with root privileges
- BPF test programs are compiled separately from main kernel code
- Use `test_base.hpp` helpers for consistent BPF program management
- Tests use Google Test framework - see [gtest documentation](https://google.github.io/googletest/)

