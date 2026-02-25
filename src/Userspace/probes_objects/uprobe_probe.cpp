#include "log_levels_enum.h"
#include "rodata_maps_related_structs.h"
#include "all_bpf.skel.h"

#include "uprobe_probe.hpp"
#include "globals/global_objects.hpp"

namespace owlsm
{

void UprobeProbe::bpfLoad()
{
    switch (m_target)
    {
        case ShellType::DASH:
        {
            addProgramToArray(m_skel->progs.exitList_2, m_skel->maps.dash_shell_command_prog_array);
            break;
        }
        default: break;
    }
}

void UprobeProbe::bpfAttach()
{
    switch (m_target)
    {
        case ShellType::BASH: 
        {
            attachProbe(m_skel->progs.exit_readline, "readline", true); 
            attachProbe(m_skel->progs.enter_readline, "readline", false); 
            break;
        }
        case ShellType::ZSH:
        {
            attachProbe(m_skel->progs.exit_zleentry, "zleentry", true);
            attachProbe(m_skel->progs.enter_zleentry, "zleentry", false);
            attachProbe(m_skel->progs.enter_parse_event, "parse_event", false);
            break;
        }
        case ShellType::DASH:
        {
            attachProbe(m_skel->progs.exitList, "list", true);
            attachProbe(m_skel->progs.enterSetprompt, "setprompt", false);
            break;
        }
        default: break;
    }
}

void UprobeProbe::bpfDetach()
{
    for (const auto& link : m_links)
    {
        bpf_link__destroy(link);
    }
    m_links.clear();
}

void UprobeProbe::attachProbe(const bpf_program* program, const std::string& func_name, bool retprobe)
{
    const auto shell_info = globals::g_shells_db.get(m_path);
    if (!shell_info.has_value())
    {
        LOG_ERROR("Shell not found in DB for probe attachment: " << m_path);
        return;
    }

    const auto func_names = getShellFunctionNames(m_target);
    size_t offset = 0;

    if (func_name == func_names.start_function)
    {
        offset = shell_info->shell_start_function_offset;
    }
    else if (func_name == func_names.end_function)
    {
        offset = shell_info->shell_end_function_offset;
    }

    if (offset == 0)
    {
        LOG_ERROR("No offset available for function: " << func_name
                  << " shell: " << m_path << " type: " << shellTypeToString(m_target));
        return;
    }

    attachProbeByOffset(program, offset, retprobe, func_name);
}

void UprobeProbe::attachProbeByOffset(const bpf_program* program, size_t offset, bool retprobe, const std::string& name_for_log) 
{
    LIBBPF_OPTS(bpf_uprobe_opts, opts);
    opts.retprobe = retprobe;
    bpf_link* link = bpf_program__attach_uprobe_opts(program, -1, m_path.c_str(), offset, &opts);
    if (!link)
    {
        LOG_ERROR("failed to attach probe. errno: " << std::to_string(errno) << " program: " << bpf_program__name(program));
        return;
    }
    m_links.push_back(link);
    LOG_INFO("attached probe. program: " << bpf_program__name(program) << " offset: 0x" << std::hex << offset << std::dec << " (" << name_for_log << ") path: " << m_path);
}

}
