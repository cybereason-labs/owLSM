#pragma once

#include <condition_variable>
#include <mutex>
#include <atomic>

namespace owlsm
{

class PosixSignalHandler
{
public:
    PosixSignalHandler();
    void waitForExitSignal();

private:
    static void signalHandler(int signal);
    
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_exit_requested;
    
    static PosixSignalHandler* s_instance;
};

}
