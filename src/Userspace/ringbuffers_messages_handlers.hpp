#pragma once

#include "bpf_header_includes.h"
#include "events/sync_enrichment.hpp"
#include "async_event_work/async_work_distributor.hpp"
#include "events/parse_messages.hpp"
#include "logger.hpp"

#include <nlohmann/json.hpp>
#include "globals/global_objects.hpp"
#include "globals/global_numbers.hpp"

#include <cstddef>
#include <deque>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <string>
#include <chrono>
#include <algorithm>
#include <unistd.h>

namespace owlsm
{

template <typename MessageType, typename SyncEnrichment, typename AsyncWorkDistributor>
class RingbufferMessagesHandler
{
    using RawType = typename MessageType::RawType;

public:
    RingbufferMessagesHandler(std::shared_ptr<struct ring_buffer>& ringbuffer, int output_fd)
        : m_ringbuffer(ringbuffer), m_output_fd(output_fd) {}

    void start()
    {
        m_running = true;
        m_polling_thread = std::thread(&RingbufferMessagesHandler::ringbufferWorker, this);
        m_processing_thread = std::thread(&RingbufferMessagesHandler::consumerWorker, this);
        LOG_INFO("RingbufferMessagesHandler started. Output fd: " << m_output_fd);
    }

    void destroy()
    {
        m_running = false;
        if (m_polling_thread.joinable())
        {
            m_polling_thread.join();
        }
        if (m_processing_thread.joinable())
        {
            m_processing_thread.join();
        }
        m_ringbuffer.reset();
        LOG_INFO("RingbufferMessagesHandler stopped. Output fd: " << m_output_fd);
    }

    int eventReceivedCallback(void* ctx, void* data, size_t len)
    {
        if (!m_running)
        {
            return 0;
        }

        if (len < sizeof(RawType))
        {
            LOG_ERROR("Invalid event data length");
            return -1;
        }

        const auto* ev = static_cast<const RawType*>(data);
        if (!ev)
        {
            LOG_ERROR("Invalid event data");
            return -1;
        }

        {
            std::lock_guard<std::mutex> lock(m_main_queue_mutex);
            if (m_main_queue.size() >= owlsm::globals::g_config.userspace.max_events_queue_size)
            {
                LOG_ERROR("Max events queue size reached");
                return -1;
            }
            m_main_queue.push_back(*ev);
        }
        return 0;
    }

private:
    void ringbufferWorker()
    {
        while (m_running)
        {
            ring_buffer__poll(m_ringbuffer.get(), 100);
        }
    }

    void consumerWorker()
    {
        std::string output_buffer;
        output_buffer.reserve(owlsm::globals::MB * 5);

        while (m_running)
        {
            {
                std::lock_guard<std::mutex> lock(m_main_queue_mutex);
                if (!m_main_queue.empty())
                {
                    m_thread_queue.swap(m_main_queue);
                }
            }

            if (m_thread_queue.empty())
            {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                continue;
            }

            convertToMessages();
            enrichMessages();

            output_buffer.clear();
            buildOutputBuffer(output_buffer);
            efficientBulkWrite(output_buffer);

            distributeMessages();
            m_messages_queue.clear();
            m_thread_queue.clear();
        }

        {
            std::lock_guard<std::mutex> lock(m_main_queue_mutex);
            m_thread_queue.swap(m_main_queue);
        }
        
        if (!m_thread_queue.empty())
        {
            convertToMessages();
            enrichMessages();
            output_buffer.clear();
            buildOutputBuffer(output_buffer);
            efficientBulkWrite(output_buffer);
            distributeMessages();
            m_messages_queue.clear();
            m_thread_queue.clear();
        }
    }

    void convertToMessages()
    {
        m_messages_queue.resize(m_thread_queue.size());
        std::transform(
            m_thread_queue.begin(),
            m_thread_queue.end(),
            m_messages_queue.begin(),
            [](const RawType& ev) { return std::make_shared<MessageType>(ev); }
        );
    }

    void enrichMessages()
    {
        for (auto& msg : m_messages_queue)
        {
            m_sync_enrichment.enrich(msg);
        }
    }

    void distributeMessages()
    {
        for (auto& msg : m_messages_queue)
        {
            m_async_work_distributor.distribute(msg);
        }
    }

    void buildOutputBuffer(std::string& output_buffer)
    {
        for (const auto& msg : m_messages_queue)
        {
            try
            {
                nlohmann::json j;
                owlsm::events::to_json(j, msg);
                output_buffer += j.dump();
                output_buffer += '\n';
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Failed to serialize message to JSON: " << e.what());
            }
        }
    }

    void efficientBulkWrite(const std::string& output_buffer)
    {
        const char* data = output_buffer.data();
        size_t remaining = output_buffer.size();

        while (remaining > 0)
        {
            ssize_t written = ::write(m_output_fd, data, remaining);
            if (written < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                LOG_ERROR("Failed to write to output file descriptor");
                break;
            }
            data += written;
            remaining -= written;
        }
    }

    std::shared_ptr<struct ring_buffer> m_ringbuffer;
    int m_output_fd;
    std::thread m_polling_thread;
    std::thread m_processing_thread;
    std::deque<RawType> m_main_queue;
    std::mutex m_main_queue_mutex;
    std::deque<RawType> m_thread_queue;
    std::vector<std::shared_ptr<MessageType>> m_messages_queue;
    SyncEnrichment m_sync_enrichment;
    AsyncWorkDistributor m_async_work_distributor;
    std::atomic<bool> m_running{false};
};

class RingbuffersMessagesHandlers 
{
    using EventHandler = RingbufferMessagesHandler<events::Event, events::SyncEventEnrichment, events::AsyncEventWorkDistributor>;
    using ErrorHandler = RingbufferMessagesHandler<events::Error, events::SyncErrorEnrichment, events::AsyncErrorWorkDistributor>;

public:
    RingbuffersMessagesHandlers() = default;

    ~RingbuffersMessagesHandlers()
    {
        destroy();
    }

    RingbuffersMessagesHandlers(RingbuffersMessagesHandlers&&) = delete;
    RingbuffersMessagesHandlers& operator=(RingbuffersMessagesHandlers&&) = delete;
    RingbuffersMessagesHandlers(const RingbuffersMessagesHandlers&) = delete;
    RingbuffersMessagesHandlers& operator=(const RingbuffersMessagesHandlers&) = delete;

    void start(std::shared_ptr<struct ring_buffer>& event_ringbuffer, std::shared_ptr<struct ring_buffer>& error_ringbuffer);
    void destroy();
    int handle_event(void* ctx, void* data, size_t len);
    int handle_error(void* ctx, void* data, size_t len);

private:
    std::unique_ptr<EventHandler> m_event_handler = nullptr;
    std::unique_ptr<ErrorHandler> m_error_handler = nullptr;
};

extern RingbuffersMessagesHandlers g_ringbuffers_messages_handlers;
int handle_event_callback(void* ctx, void* data, size_t len);
int handle_error_callback(void* ctx, void* data, size_t len);

}