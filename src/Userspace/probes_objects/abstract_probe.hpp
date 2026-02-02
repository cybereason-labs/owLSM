#pragma once

#include "logger.hpp"
#include "bpf_header_includes.h"

struct all_bpf; // Forward declaration

namespace owlsm
{

enum class probe_type
{
    UNKNOWN,
    PROBE_MANAGER,
    LSM,
    FENTRY,
    TRACEPOINT
};

class AbstractProbe
{
public:
    virtual ~AbstractProbe() = default;

    virtual void bpfOpen() {};
    virtual void bpfLoad() {};
    virtual void bpfAttach() {};
    virtual void bpfDetach() {};
    virtual void bpfDestroy() {};
    virtual void setSkel(const std::shared_ptr<all_bpf>& skel) { m_skel = skel; }

protected:
    explicit AbstractProbe(probe_type type) : m_type(type) {}

    virtual void attachProbe(const bpf_program* program, bpf_link** link)
    {
        bpf_link* new_link = bpf_program__attach(program);
        if(!new_link)
        {
            throw std::runtime_error("failed to attach probe. errno: " + std::to_string(errno) + " program: " + bpf_program__name(program));
        }
        LOG_INFO("attached probe. program: " << bpf_program__name(program));
        *link = new_link;
    }
    
    const probe_type m_type;
    std::shared_ptr<all_bpf> m_skel;
};
}