#pragma once

#include "events_structs.h"
#include "abstract_probe.hpp"

namespace owlsm
{
class FentryProbe : public AbstractProbe
{
public:
    FentryProbe(enum event_type event_type) 
        : AbstractProbe(probe_type::FENTRY), m_event_type(event_type) {}

    virtual ~FentryProbe() override = default;

private:
    virtual void bpfAttach() override 
    {
        switch (m_event_type)
        {
            case FORK: attachProbe(m_skel->progs.fork_hook, &m_skel->links.fork_hook); break;
            case EXIT: attachProbe(m_skel->progs.exit_hook, &m_skel->links.exit_hook); break;
            default: break;
        }
    }

    enum event_type m_event_type;
};
}