#include "event_and_rule_matcher.bpf.h"

__noinline int eval_file(const struct event_t *current_event, const struct file_t *file, struct predicate_t *pred, enum rule_field_type rule_file_field_type)
{
    if(!current_event || !file || !pred)
    {
        return FALSE;
    }

    switch (rule_file_field_type)
    {
        case TARGET_FILE_PATH: return compare_string(file->path.value, file->path.length, PATH_MAX - 1, pred);
        case TARGET_FILE_FILENAME: return compare_string(file->filename.value, file->filename.length, FILENAME_MAX_LENGTH - 1, pred);
        case TARGET_FILE_OWNER_UID: return compare_numeric(current_event, file->owner.uid, pred);
        case TARGET_FILE_OWNER_GID: return compare_numeric(current_event, file->owner.gid, pred);
        case TARGET_FILE_MODE: return compare_numeric(current_event, file->mode, pred);
        case TARGET_FILE_SUID: return compare_numeric(current_event, file->suid, pred);
        case TARGET_FILE_SGID: return compare_numeric(current_event, file->sgid, pred);
        case TARGET_FILE_NLINK: return compare_numeric(current_event, file->nlink, pred);
        case TARGET_FILE_TYPE: return compare_numeric(current_event, file->type, pred);
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected field: %d", rule_file_field_type);
            return FALSE;
    }
    return FALSE;
}

__noinline int eval_process(const struct event_t *current_event, const struct process_t *process, struct predicate_t *pred, enum rule_field_type rule_file_field_type)
{
    if(!current_event || !process || !pred)
    {
        return FALSE;
    }

    switch (rule_file_field_type)
    {
        case TARGET_PROCESS_CMD: return compare_string(process->cmd.value, process->cmd.length, CMD_MAX - 1, pred);
        case TARGET_PROCESS_SHELL_COMMAND: return compare_string(process->shell_command.value, process->shell_command.length, CMD_MAX - 1, pred);
        case TARGET_PROCESS_PID: return compare_numeric(current_event, process->pid, pred);
        case TARGET_PROCESS_PPID: return compare_numeric(current_event, process->ppid, pred);
        case TARGET_PROCESS_RUID: return compare_numeric(current_event, process->ruid, pred);
        case TARGET_PROCESS_RGID: return compare_numeric(current_event, process->rgid, pred);
        case TARGET_PROCESS_EUID: return compare_numeric(current_event, process->euid, pred);
        case TARGET_PROCESS_EGID: return compare_numeric(current_event, process->egid, pred);
        case TARGET_PROCESS_SUID: return compare_numeric(current_event, process->suid, pred);
        case TARGET_PROCESS_PTRACE_FLAGS: return compare_numeric(current_event, process->ptrace_flags, pred);
        default: return eval_file(current_event, &process->file, pred, rule_file_field_type);
    }
}

__noinline int evaluate_token_against_event(struct token_t *token, struct eval_stack *stack, const struct event_t *event)
{
    if(!token || !stack || !event)
    {
        return FALSE;
    }

    switch (token->operator_type)
    {
        case OPERATOR_PREDICATE:
        {
            if (!stack_push(stack, token))
            {
                REPORT_ERROR(GENERIC_ERROR, "PRED push failed");
                return FALSE;
            }
            break;
        }
        case OPERATOR_AND:
        {
            struct token_t b, a;
            if (!stack_pop(stack, &b) || !stack_pop(stack, &a))
            {
                REPORT_ERROR(GENERIC_ERROR, "AND: stack underflow");
                return FALSE;
            }

            enum token_result a_res = get_pred_evaluation(&a, event);

            enum token_result final_res;
            if (a_res == TOKEN_RESULT_FALSE)
            {
                final_res = TOKEN_RESULT_FALSE;
            }
            else
            {
                enum token_result b_res = get_pred_evaluation(&b, event);
                final_res = b_res;
            }

            struct token_t result_token = {
                .operator_type = OPERATOR_PREDICATE,
                .pred_idx = -1,
                .result = final_res
            };
            if (!stack_push(stack, &result_token))
            {
                REPORT_ERROR(GENERIC_ERROR, "AND: push failed");
                return FALSE;
            }
            break;
        }
        case OPERATOR_OR:
        {
            struct token_t b, a;
            if (!stack_pop(stack, &b) || !stack_pop(stack, &a))
            {
                REPORT_ERROR(GENERIC_ERROR, "OR: stack underflow");
                return FALSE;
            }

            enum token_result a_res = get_pred_evaluation(&a, event);
            enum token_result final_res;
            if (a_res == TOKEN_RESULT_TRUE)
            {
                final_res = TOKEN_RESULT_TRUE;
            }
            else
            {
                enum token_result b_res = get_pred_evaluation(&b, event);
                final_res = b_res;
            }

            struct token_t result_token = {
                .operator_type = OPERATOR_PREDICATE,
                .pred_idx = -1,
                .result = final_res
            };
            if (!stack_push(stack, &result_token))
            {
                REPORT_ERROR(GENERIC_ERROR, "OR: push failed");
                return FALSE;
            }
            break;
        }
        case OPERATOR_NOT:
        {
            struct token_t a;
            if (!stack_pop(stack, &a))
            {
                REPORT_ERROR(GENERIC_ERROR, "NOT: stack underflow");
                return FALSE;
            }
            enum token_result a_res = get_pred_evaluation(&a, event);
            enum token_result final_res = (a_res == TOKEN_RESULT_TRUE) ? TOKEN_RESULT_FALSE : TOKEN_RESULT_TRUE;
            struct token_t result_token = {
                .operator_type = OPERATOR_PREDICATE,
                .pred_idx = -1,
                .result = final_res
            };
            if (!stack_push(stack, &result_token))
            {
                REPORT_ERROR(GENERIC_ERROR, "NOT: push failed");
                return FALSE;
            }
            break;
        }
    }
    return TRUE;
}
