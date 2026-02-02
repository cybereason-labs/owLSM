#pragma once

#include "probes_objects/abstract_probe.hpp"
#include "configuration/rule.hpp"
#include "events_structs.h"

namespace owlsm
{
class ProbeManager : public AbstractProbe
{
public:
    ProbeManager(std::vector<std::shared_ptr<AbstractProbe>>&& probes) 
        : AbstractProbe(probe_type::PROBE_MANAGER), m_probes(std::move(probes)) {}
    
    virtual ~ProbeManager() override = default;
    
    void bpfOpen(const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules);
    void bpfLoad(const std::vector<unsigned int>& excluded_pids);
    virtual void bpfAttach() override;
    virtual void bpfDetach() override;
    virtual void bpfDestroy() override;

private:
    void startRingbuffers();
    void saveEbpfAttachTime();
    void addProgramRelatedPids(const std::vector<unsigned int>& excluded_pids);

    using AbstractProbe::bpfOpen;
    using AbstractProbe::bpfLoad;

    std::vector<std::shared_ptr<AbstractProbe>> m_probes;
};
}
