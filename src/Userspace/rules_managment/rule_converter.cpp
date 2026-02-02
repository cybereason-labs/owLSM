#include "rule_converter.hpp"

#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <arpa/inet.h>

namespace owlsm 
{

rule_t RuleStructConverter::convertRule(const config::Rule& rule)
{
    if (rule.tokens.size() > MAX_TOKENS_PER_RULE)
    {
        throw std::runtime_error("Rule tokens exceed maximum limit. Rule id: " + std::to_string(rule.id));
    }

    rule_t result = {};
    result.id = rule.id;
    result.action = rule.action;
    result.token_count = rule.tokens.size();
    result.is_end_of_rules = rule.is_end_of_rules ? 1 : 0;
    
    for (size_t i = 0; i < result.token_count; i++)
    {
        result.tokens[i] = convertToken(rule.tokens[i]);
    }
    
    return result;
}

token_t RuleStructConverter::convertToken(const config::Token& token)
{
    token_t result = {};
    
    result.operator_type = token.operator_type;
    result.pred_idx = token.predicate_idx;
    result.result = TOKEN_RESULT_UNKNOWN;
    
    return result;
}

predicate_t RuleStructConverter::convertPredicate(const config::Predicate& predicate)
{
    predicate_t result = {};
    
    result.field = predicate.field;
    result.operation = predicate.comparison_type;
    result.string_idx = predicate.string_idx;
    result.numerical_value = predicate.numerical_value;
    
    return result;
}

rule_string_t RuleStructConverter::convertRuleString(const config::RuleString& rule_string)
{
    if (rule_string.value.size() > MAX_RULE_STR_LENGTH)
    {
        throw std::runtime_error("Rule string value exceeds maximum length. Rule string value: " + rule_string.value);
    }

    rule_string_t result = {};
    std::memcpy(result.value, rule_string.value.data(), rule_string.value.size());
    result.length = rule_string.value.size();
    result.idx_to_DFA = -1;

    return result;
}

rule_ip_t RuleStructConverter::convertRuleIP(const config::RuleIP& rule_ip)
{
    rule_ip_t result = {};
    
    if (rule_ip.ip_type == AF_INET)
    {
        struct in_addr addr;
        if (inet_pton(AF_INET, rule_ip.ip.c_str(), &addr) != 1)
        {
            throw std::runtime_error("Invalid IPv4 address: " + rule_ip.ip);
        }
        result.ip[0] = addr.s_addr;
        
        if (rule_ip.cidr == 0)
        {
            result.cidr_mask[0] = 0;
        }
        else
        {
            result.cidr_mask[0] = htonl(~((1U << (32 - rule_ip.cidr)) - 1));
        }
    }
    else
    {
        struct in6_addr addr;
        if (inet_pton(AF_INET6, rule_ip.ip.c_str(), &addr) != 1)
        {
            throw std::runtime_error("Invalid IPv6 address: " + rule_ip.ip);
        }
        std::memcpy(result.ip, addr.s6_addr, sizeof(result.ip));
        
        unsigned int remaining_bits = rule_ip.cidr;
        for (int i = 0; i < 4; ++i)
        {
            if (remaining_bits >= 32)
            {
                result.cidr_mask[i] = 0xFFFFFFFF;
                remaining_bits -= 32;
            }
            else if (remaining_bits > 0)
            {
                result.cidr_mask[i] = htonl(~((1U << (32 - remaining_bits)) - 1));
                remaining_bits = 0;
            }
            else
            {
                result.cidr_mask[i] = 0;
            }
        }
    }
    
    return result;
}

}
