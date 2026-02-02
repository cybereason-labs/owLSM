#pragma once

#include "events/event.hpp"

#include <memory>

namespace owlsm::events
{

class AsyncEventWorkDistributor
{
public:
    AsyncEventWorkDistributor() = default;

    void distribute(std::shared_ptr<Event>& event)
    {
        // Currently does nothing - placeholder for future async work distribution
    }
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


