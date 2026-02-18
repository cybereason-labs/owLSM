#pragma once

#include "events_structs.h"
#include "abstract_probe.hpp"
#include "shell_detection/shell_types.hpp"

#include <vector>
#include <string>

namespace owlsm
{

class UprobeProbe : public AbstractProbe
{
public:
    UprobeProbe(const std::string& path, ShellType target) 
        : AbstractProbe(probe_type::UPROBE), m_path(path), m_target(target) {}

    virtual ~UprobeProbe() override = default;
    
    virtual void bpfAttach() override;
    virtual void bpfDetach() override;

private:
    using AbstractProbe::attachProbe;
    void attachProbe(const bpf_program* program, const std::string& func_name, bool retprobe);
    void attachProbeByOffset(const bpf_program* program, size_t offset, bool retprobe, const std::string& name_for_log);

    std::string m_path;
    ShellType m_target;
    std::vector<bpf_link*> m_links;
};

}
