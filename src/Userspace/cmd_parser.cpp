#include "cmd_parser.hpp"

#include <cxxopts/cxxopts.hpp>
#include <iostream>
#include <cstdlib>

namespace owlsm {

CmdParser::CmdParser(int argc, char** argv) 
{
    try 
    {
        cxxopts::Options options(argv[0], "OWLSM - eBPF Security Monitoring");
        
        options.add_options()
            ("c,config", "Path to configuration file (required. Exactly once)", cxxopts::value<std::string>())
            ("e,exclude-pid", "PID to exclude from monitoring (can be specified multiple times)", cxxopts::value<std::vector<unsigned int>>())
            ("h,help", "Show help message");

        auto result = options.parse(argc, argv);

        if (result.count("help")) 
        {
            std::cout << options.help() << std::endl;
            std::cout << "Example: " << argv[0] << " -c /path/to/config.json -e 123 -e 456" << std::endl;
            std::exit(0);
        }

        const auto config_count = result.count("config");
        if (config_count > 1) 
        {
            std::cerr << "Error: -c/--config <path> is required at most once.\n";
            std::cerr << "Use -h for help.\n";
            std::exit(1);
        }
        else if (config_count == 1)
        {
            m_config_path = result["config"].as<std::string>();
        }

        if (result.count("exclude-pid")) 
        {
            m_pids = result["exclude-pid"].as<std::vector<unsigned int>>();
        }

    } 
    catch (const cxxopts::exceptions::exception& e) 
    {
        std::cerr << "Command-line parsing error: " << e.what() << "\n";
        std::cerr << "Use -h for help.\n";
        std::exit(1);
    }
}

}
