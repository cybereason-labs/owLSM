#pragma once

#include "base_async_worker.hpp"
#include "events/event.hpp"
#include "shell_detection/shell_binary_info.hpp"

#include <unordered_set>
#include <memory>

namespace owlsm::events
{

class ShellAsyncWorker : public BaseAsyncWorker<Event>
{
public:
    ShellAsyncWorker();
    ~ShellAsyncWorker() override = default;

    void distributeIfNeeded(std::shared_ptr<Event> event);

protected:
    void processItem(std::shared_ptr<Event>& item) override;

private:
    std::unordered_set<FileKey, FileKeyHash> m_non_shells_quick_cache; // data source is always the event

    friend class ShellAsyncWorkerTest;
};

}

