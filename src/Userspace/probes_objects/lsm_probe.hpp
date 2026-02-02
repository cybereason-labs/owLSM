#pragma once

#include "events_structs.h"
#include "abstract_probe.hpp"

namespace owlsm
{
class LsmProbe : public AbstractProbe
{
public:
    LsmProbe(enum event_type event_type) 
        : AbstractProbe(probe_type::LSM), m_event_type(event_type) {}
    
    virtual ~LsmProbe() override = default;
    
    virtual void bpfOpen() override;
    virtual void bpfLoad() override;
    virtual void bpfAttach() override;

private:
    void addProgramToArray(const bpf_program* program, const bpf_map* table);

    enum event_type m_event_type;
};
}
