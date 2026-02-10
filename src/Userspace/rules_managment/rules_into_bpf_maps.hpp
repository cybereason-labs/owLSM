#pragma once

#include "configuration/rule.hpp"
#include "bpf_header_includes.h"
#include "rules_structs.h"

#include <unordered_map>
#include <unistd.h>
#include <vector>
#include <memory>
#include <cstring>

class RulesIntoBpfMapsTest;
class MapPopulatorTest;

namespace owlsm 
{

class RulesIntoBpfMaps
{
public:
    void create_rule_maps_from_organized_rules(
        const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules,
        const std::unordered_map<int, config::RuleString>& id_to_string,
        const std::unordered_map<int, config::Predicate>& id_to_predicate,
        const std::unordered_map<int, config::RuleIP>& id_to_ip);
    
private:
    void populate_predicates_map(const std::unordered_map<int, config::Predicate>& id_to_predicate);
    void populate_rules_strings_map(const std::unordered_map<int, config::RuleString>& id_to_string);
    void populate_idx_to_DFA_map(const std::unordered_map<int, config::RuleString>& id_to_string);
    void populate_rules_ips_map(const std::unordered_map<int, config::RuleIP>& id_to_ip);
    void populate_event_rule_maps(const std::unordered_map<enum event_type, std::vector<std::shared_ptr<config::Rule>>>& organized_rules);
    int create_pin_map(enum bpf_map_type type,const std::string& map_name, size_t value_size, size_t max_entries, int flags);
    void freeze_map(int fd);
    
    void build_dfa(const std::string& pattern, flat_2d_dfa_array_t& dfa)
    {
        std::memset(&dfa, 0, sizeof(flat_2d_dfa_array_t));
        
        size_t pattern_len = pattern.length();
        
        // First, build the failure function (standard KMP)
        std::vector<int> failure(pattern_len, 0);
        int k = 0;
        for (size_t i = 1; i < pattern_len; ++i)
        {
            while (k > 0 && pattern[k] != pattern[i])
            {
                k = failure[k - 1];
            }
            if (pattern[k] == pattern[i])
            {
                ++k;
            }
            failure[i] = k;
        }
        
        // Build the DFA from the failure function
        // For each state (0 to pattern_len) and each character (0-255),
        // compute the next state using flat indexing: (state * 256) + c
        for (size_t state = 0; state <= pattern_len; ++state)
        {
            for (int c = 0; c < 256; ++c)
            {
                size_t idx = (state * DFA_ALPHABET_SIZE) + c;
                
                if (state < pattern_len && static_cast<unsigned char>(pattern[state]) == c)
                {
                    // Character matches - advance to next state
                    dfa.value[idx] = static_cast<unsigned char>(state + 1);
                }
                else if (state == 0)
                {
                    // At state 0, mismatch stays at 0
                    dfa.value[idx] = 0;
                }
                else
                {
                    // Follow failure function and try again
                    // Use the DFA we've already built for smaller states
                    size_t fail_idx = (failure[state - 1] * DFA_ALPHABET_SIZE) + c;
                    dfa.value[idx] = dfa.value[fail_idx];
                }
            }
        }
    }
    
    std::string event_type_to_string(event_type type)
    {
        switch(type)
        {
            case EXEC:        return "exec_rules";
            case FORK:        return "fork_rules";
            case EXIT:        return "exit_rules";
            case FILE_CREATE: return "file_create_rules";
            case CHOWN:       return "chown_rules";
            case CHMOD:       return "chmod_rules";
            case WRITE:       return "write_rules";
            case READ:        return "read_rules";
            case UNLINK:      return "unlink_rules";
            case RENAME:      return "rename_rules";
            case NETWORK:     return "network_rules";
            case MKDIR:       return "mkdir_rules";
            case RMDIR:       return "rmdir_rules";
            default:          return "unknown_rules";
        }
    }
    
    friend class ::RulesIntoBpfMapsTest;
    friend class ::MapPopulatorTest;
};
}
