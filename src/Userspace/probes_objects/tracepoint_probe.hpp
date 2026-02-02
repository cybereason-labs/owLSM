#pragma once

#include "abstract_probe.hpp"

namespace owlsm
{
class TracepointProbe : public AbstractProbe
{
public:
    TracepointProbe() 
        : AbstractProbe(probe_type::TRACEPOINT) {}

    virtual ~TracepointProbe() override = default;

    virtual void bpfAttach() override 
    {
        attachProbe(m_skel->progs.syscall_enter,&m_skel->links.syscall_enter);
    }

};
}