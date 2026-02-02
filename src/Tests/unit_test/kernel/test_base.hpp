#pragma once

#include <gtest/gtest.h>
#include "globals/global_strings.hpp"
#include "log_levels_enum.h"
#include "shared_unit_tests_structs_definitions.h"
#include "rodata_maps_related_structs.h"
#include "system_setup.hpp"
#include "ebpf_unit_tests.skel.h"

class BpfTestBase : public ::testing::Test 
{
protected:
    void SetUp() override 
    {
        bpf_object_open_opts open_opts = {};
        open_opts.sz = sizeof(open_opts);
        open_opts.pin_root_path = owlsm::globals::SYS_FS_BPF_OWLSM_PATH;
        skel = ebpf_unit_tests__open_opts(&open_opts);
        if (!skel) 
        {
            throw std::runtime_error("Failed to open BPF skeleton. errno: " + std::to_string(errno));
        }
        
        int err = ebpf_unit_tests__load(skel);
        if (err)
        {
            ebpf_unit_tests__destroy(skel);
            skel = nullptr;
            throw std::runtime_error("Failed to load BPF skeleton. errno: " + std::to_string(err));
        }
    }

    void TearDown() override 
    {
        if (skel) 
        {
            ebpf_unit_tests__destroy(skel);
            skel = nullptr;
        }
        owlsm::SystemSetup::cleanupOwlsmDirectory();
    }

    ebpf_unit_tests* skel = nullptr;
};

