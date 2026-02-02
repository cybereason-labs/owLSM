
#include <filesystem>
#include <system_error>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "system_setup.hpp"
#include "globals/global_strings.hpp"
#include "globals/global_objects.hpp"
#include "logger.hpp"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

namespace owlsm 
{

bool SystemSetup::start()
{
    if (globals::g_config.userspace.set_limits)
    {
        liftResourceLimits();
    }
    if(!isBpfFsAvailable() && !tryCreateBpfFsDirectory())
    {
        return false;
    }
    return cleanupOwlsmDirectory();
}

bool SystemSetup::isBpfFsAvailable()
{
    struct statfs s = {0};
    if (statfs(globals::SYS_FS_BPF_PATH, &s) < 0)
    {
        LOG_ERROR("Failed to statfs " << globals::SYS_FS_BPF_PATH << ": " << " errno: " << errno);
        return false;
    }
    if (s.f_type != BPF_FS_MAGIC)
    {
        LOG_INFO(globals::SYS_FS_BPF_PATH << " is not a BPF filesystem.");
        return false;
    }
    
    if (!std::filesystem::is_directory(globals::SYS_FS_BPF_PATH)) 
    {
        LOG_INFO(globals::SYS_FS_BPF_PATH << " exists but is not a directory.");
        return false;
    }

    return true;
}

bool SystemSetup::tryCreateBpfFsDirectory()
{
    std::error_code ec;
    if(std::filesystem::exists(globals::SYS_FS_BPF_PATH, ec))
    {
        std::filesystem::remove_all(globals::SYS_FS_BPF_PATH, ec);
        if(ec)
        {
            LOG_ERROR("Failed to remove " << globals::SYS_FS_BPF_PATH << ": " << ec.message());
            return false;
        }
    }
    std::filesystem::create_directories(globals::SYS_FS_BPF_PATH, ec);
    if(ec)
    {
        LOG_ERROR("Failed to create " << globals::SYS_FS_BPF_PATH << ": " << ec.message());
        return false;
    }
    if (mount(globals::SYS_FS_BPF_PATH, globals::SYS_FS_BPF_PATH, "bpf", 0, NULL) < 0)
    {
        LOG_ERROR("Failed to mount " << globals::SYS_FS_BPF_PATH << ". errno: " << errno);
        return false;
    }
    return true;
}

bool SystemSetup::cleanupOwlsmDirectory(bool on_exit)
{
    std::error_code ec;
    if (std::filesystem::exists(globals::SYS_FS_BPF_OWLSM_PATH, ec)) 
    {
        if (!on_exit)
        {
            LOG_WARN("Already exists: '" << globals::SYS_FS_BPF_OWLSM_PATH << "'. Likely we didn't exit gracefully last time.");
        }
        std::filesystem::remove_all(globals::SYS_FS_BPF_OWLSM_PATH, ec);
        if (ec) 
        {
            LOG_ERROR("Failed to remove " << globals::SYS_FS_BPF_OWLSM_PATH << ": " << ec.message());
            return false;
        }
    }
    return true;
}

void SystemSetup::liftResourceLimits()
{
    struct rlimit rl;
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;

    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0)
    {
        LOG_ERROR("Failed to set RLIMIT_MEMLOCK to unlimited. errno: " << errno);
    }
    if (setrlimit(RLIMIT_CORE, &rl) != 0)
    {
        LOG_ERROR("Failed to set RLIMIT_CORE to unlimited. errno: " << errno);
    }
}

}