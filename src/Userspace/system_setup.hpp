#pragma once

class SystemSetupTest;

namespace owlsm 
{

class SystemSetup
{
public:
    static bool start();
    static bool cleanupOwlsmDirectory(bool on_exit = false);
private:
    static bool isBpfFsAvailable();
    static bool tryCreateBpfFsDirectory();
    static void liftResourceLimits();

    friend class ::SystemSetupTest;
};

}

