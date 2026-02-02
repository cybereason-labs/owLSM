#pragma once

#include "configuration/rule.hpp"
#include "rules_structs.h"

#include <cstring>

class RuleConverterTest;

namespace owlsm 
{
class RuleStructConverter
{
public:
    static rule_t convertRule(const config::Rule& rule);
    static predicate_t convertPredicate(const config::Predicate& predicate);
    static rule_string_t convertRuleString(const config::RuleString& rule_string);
    static rule_ip_t convertRuleIP(const config::RuleIP& rule_ip);

private:
    static token_t convertToken(const config::Token& token);

    friend class ::RuleConverterTest;
};
}
