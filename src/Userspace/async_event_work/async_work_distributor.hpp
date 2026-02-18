#pragma once

#include "async_event_work/shell_async_worker.hpp"
#include "globals/global_objects.hpp"

#include <memory>

namespace owlsm::events
{

class AsyncEventWorkDistributor
{
public:
    AsyncEventWorkDistributor()
    {
        if (owlsm::globals::g_config.features.shell_commands_monitoring.enabled)
        {
            m_shell_async_worker.start();
        }
    }

    ~AsyncEventWorkDistributor()
    {
        if (owlsm::globals::g_config.features.shell_commands_monitoring.enabled)
        {
            m_shell_async_worker.stop();
        }
    }

    void distribute(std::shared_ptr<Event>& event)
    {
        if (owlsm::globals::g_config.features.shell_commands_monitoring.enabled)
        {
            m_shell_async_worker.distributeIfNeeded(event);
        }
    }

private:
    ShellAsyncWorker m_shell_async_worker;
};

class AsyncErrorWorkDistributor
{
public:
    AsyncErrorWorkDistributor() = default;

    void distribute(std::shared_ptr<Error>& error)
    {
        // Currently does nothing - placeholder for future async work distribution
    }
};

}


