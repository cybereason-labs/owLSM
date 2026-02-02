#pragma once
#include "error_reports.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "rules_structs.h"

int evaluate_rule_against_event(struct rule_t *rule, const struct event_t *event);

statfunc int event_rule_matcher(struct rule_t *rule, struct event_t *event)
{
    return evaluate_rule_against_event(rule, event);
}

static long event_rule_matcher_callback(struct bpf_map *map, const void *key, void *value, void *callback_ctx)
{
    struct event_t** current_event_p = (struct event_t**)callback_ctx;
    if(!current_event_p)
    {
        REPORT_ERROR(GENERIC_ERROR, "current_event_p is null");
        return 1; 
    }

    struct rule_t* current_rule = (struct rule_t*)value;
    if(!current_rule)
    {
        REPORT_ERROR(GENERIC_ERROR, "current_rule is null");
        return 1;
    }

    struct event_t* current_event = *current_event_p;
    if(!current_event)
    {
        REPORT_ERROR(GENERIC_ERROR, "current_event is null");
        return 1;
    }

    if (current_rule->is_end_of_rules)
    {
        return 1;
    }

    if(event_rule_matcher(current_rule, current_event) == TRUE)
    {
        current_event->action = current_rule->action;
        current_event->matched_rule_id = current_rule->id;
        return 1;
    }

    return 0;
}