#include "globals/global_strings.hpp"
#include "cmd_parser.hpp"
#include "logger.hpp"
#include "configuration/config_parser.hpp"
#include "system_setup.hpp"
#include "probes_objects/create_probe_objects.hpp"
#include "globals/global_objects.hpp"
#include "posix_signal_handler.hpp"
#include "rules_managment/rules_organizer.hpp"
#include "configuration/schema.inc"

#include <unistd.h>
#include <filesystem>
#include <iostream>

owlsm::ProbeManager safeSetup(int argc, char *argv[]);
owlsm::ProbeManager setup(int argc, char *argv[]);
void cleanup(owlsm::ProbeManager& probe_manager);

int main(int argc, char *argv[])
{
    if(getuid() != 0)
    {
        std::cerr << "Error: This program must be run as root" << std::endl;
        exit(1);
    }

    owlsm::PosixSignalHandler signal_handler;
    owlsm::ProbeManager probe_manager = safeSetup(argc, argv);
    signal_handler.waitForExitSignal();
    cleanup(probe_manager);
    return 0;
}

owlsm::ProbeManager safeSetup(int argc, char *argv[])
{
    try 
    {
        return setup(argc, argv);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Setup failed: '" << e.what() << "' Exiting..." << std::endl;
        exit(1);
    }
    catch (...)
    {
        std::cerr << "Setup failed: Unknown exception. Exiting..." << std::endl;
        exit(1);
    }
}

owlsm::ProbeManager setup(int argc, char *argv[])
{
    owlsm::Logger::initialize(std::filesystem::canonical("/proc/self/exe").parent_path() / owlsm::globals::LOG_FILE_NAME, LOG_LEVEL_DEBUG);
    LOG_INFO("Starting OWLSM. Version: " + std::string(OWLSM_VERSION_STR));

    owlsm::CmdParser cmd_parser(argc, argv);
    const std::string& config_path = cmd_parser.getConfigPath();
    if(!config_path.empty())
    {
        owlsm::config::ConfigParser config_parser(config_path, std::string(reinterpret_cast<const char*>(g_schema_json), g_schema_json_len));
        owlsm::globals::g_config = config_parser.getConfig();
        config_parser.ClearRules();
    }
    owlsm::Logger::getInstance().setLogLevel(owlsm::globals::g_config.userspace.log_level);

    owlsm::RulesOrganizer::add_end_rules(owlsm::globals::g_config.rules_config.rules);
    auto organized_rules = owlsm::RulesOrganizer::organize_rules(owlsm::globals::g_config.rules_config.rules);

    owlsm::SystemSetup::start();
    owlsm::ProbeManager probe_manager = owlsm::CreateProbeObjects::createProbeManager();
    probe_manager.bpfOpen(organized_rules);
    auto excluded_pids = cmd_parser.getPids();
    excluded_pids.push_back(getpid());
    probe_manager.bpfLoad(excluded_pids);
    probe_manager.bpfAttach();

    return probe_manager;
}

void cleanup(owlsm::ProbeManager& probe_manager)
{
    probe_manager.bpfDetach();
    probe_manager.bpfDestroy();
    owlsm::Logger::shutdown();
}