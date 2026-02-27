#pragma once

#include "error_reports.bpf.h"
#include "preprocessor_definitions/defs.bpf.h"
#include "rules_structs.h"
#include "string_utils.bpf.h"

statfunc struct event_t* get_currently_handled_event()
{
    unsigned int key = 0;
    return bpf_map_lookup_elem(&currently_handled_event, &key);
}


statfunc int fieldref_pred_get_numeric_value_file(const struct file_t *file, enum rule_field_type rule_file_field_type)
{
    switch (rule_file_field_type)
    {
        case TARGET_FILE_OWNER_UID: return file->owner.uid;
        case TARGET_FILE_OWNER_GID: return file->owner.gid;
        case TARGET_FILE_MODE: return file->mode;
        case TARGET_FILE_SUID: return file->suid;
        case TARGET_FILE_SGID: return file->sgid;
        case TARGET_FILE_NLINK: return file->nlink;
        case TARGET_FILE_TYPE: return file->type;
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected field: %d", rule_file_field_type);
            return 0;
    }
    return 0;
}

statfunc int fieldref_pred_get_numeric_value_process(const struct process_t *process, enum rule_field_type field)
{
    switch (field)
    {
        case TARGET_PROCESS_PID: return process->pid;
        case TARGET_PROCESS_PPID: return process->ppid;
        case TARGET_PROCESS_RUID: return process->ruid;
        case TARGET_PROCESS_RGID: return process->rgid;
        case TARGET_PROCESS_EUID: return process->euid;
        case TARGET_PROCESS_EGID: return process->egid;
        case TARGET_PROCESS_SUID: return process->suid;
        case TARGET_PROCESS_PTRACE_FLAGS: return process->ptrace_flags;
        default: return fieldref_pred_get_numeric_value_file(&process->file, field);
    }
}

statfunc int fieldref_pred_get_numeric_value_target_file(const struct event_t *current_event, enum rule_field_type fieldref)
{
    switch (current_event->type)
    {
        case FILE_CREATE: return fieldref_pred_get_numeric_value_file(&current_event->data.file_create.file, fieldref);
        case MKDIR: return fieldref_pred_get_numeric_value_file(&current_event->data.mkdir.file, fieldref);
        case RMDIR: return fieldref_pred_get_numeric_value_file(&current_event->data.rmdir.file, fieldref);
        case CHOWN: return fieldref_pred_get_numeric_value_file(&current_event->data.chown.file, fieldref);
        case CHMOD: return fieldref_pred_get_numeric_value_file(&current_event->data.chmod.file, fieldref);
        case READ: return fieldref_pred_get_numeric_value_file(&current_event->data.read.file, fieldref);
        case WRITE: return fieldref_pred_get_numeric_value_file(&current_event->data.write.file, fieldref);
        case UNLINK: return fieldref_pred_get_numeric_value_file(&current_event->data.unlink.file, fieldref);
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected event type: %d", current_event->type);
            return 0;
    }
}

statfunc int fieldref_pred_get_numeric_value_target_process(const struct event_t *current_event, enum rule_field_type field)
{
    switch (current_event->type)
    {
        case EXEC: return fieldref_pred_get_numeric_value_process(&current_event->data.exec.new_process, field);
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected event type: %d", current_event->type);
            return 0;
    }
}

statfunc int fieldref_pred_get_numeric_value(const struct event_t *current_event, enum rule_field_type fieldref)
{
    switch (fieldref)
    {
        // Target file fields (event type dispatch)
        case TARGET_FILE_OWNER_UID: return fieldref_pred_get_numeric_value_target_file(current_event, fieldref);
        case TARGET_FILE_OWNER_GID: return fieldref_pred_get_numeric_value_target_file(current_event, fieldref);
        case TARGET_FILE_MODE: return fieldref_pred_get_numeric_value_target_file(current_event, fieldref);
        case TARGET_FILE_SUID: return fieldref_pred_get_numeric_value_target_file(current_event, fieldref);
        case TARGET_FILE_SGID: return fieldref_pred_get_numeric_value_target_file(current_event, fieldref);
        case TARGET_FILE_NLINK: return fieldref_pred_get_numeric_value_target_file(current_event, fieldref);
        case TARGET_FILE_TYPE: return fieldref_pred_get_numeric_value_target_file(current_event, fieldref);

        // Target process fields (event type dispatch, EXEC only)
        case TARGET_PROCESS_PID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_PID);
        case TARGET_PROCESS_PPID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_PPID);
        case TARGET_PROCESS_RUID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_RUID);
        case TARGET_PROCESS_RGID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_RGID);
        case TARGET_PROCESS_EUID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_EUID);
        case TARGET_PROCESS_EGID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_EGID);
        case TARGET_PROCESS_SUID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_SUID);
        case TARGET_PROCESS_PTRACE_FLAGS: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_PROCESS_PTRACE_FLAGS);
        case TARGET_PROCESS_FILE_OWNER_UID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_FILE_OWNER_UID);
        case TARGET_PROCESS_FILE_OWNER_GID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_FILE_OWNER_GID);
        case TARGET_PROCESS_FILE_MODE: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_FILE_MODE);
        case TARGET_PROCESS_FILE_SUID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_FILE_SUID);
        case TARGET_PROCESS_FILE_SGID: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_FILE_SGID);
        case TARGET_PROCESS_FILE_NLINK: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_FILE_NLINK);
        case TARGET_PROCESS_FILE_TYPE: return fieldref_pred_get_numeric_value_target_process(current_event, TARGET_FILE_TYPE);

        // Process fields (direct access to current_event->process)
        case PROCESS_PID: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_PID);
        case PROCESS_PPID: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_PPID);
        case PROCESS_RUID: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_RUID);
        case PROCESS_RGID: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_RGID);
        case PROCESS_EUID: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_EUID);
        case PROCESS_EGID: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_EGID);
        case PROCESS_SUID: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_SUID);
        case PROCESS_PTRACE_FLAGS: return fieldref_pred_get_numeric_value_process(&current_event->process, TARGET_PROCESS_PTRACE_FLAGS);
        case PROCESS_FILE_OWNER_UID: return fieldref_pred_get_numeric_value_file(&current_event->process.file, TARGET_FILE_OWNER_UID);
        case PROCESS_FILE_OWNER_GID: return fieldref_pred_get_numeric_value_file(&current_event->process.file, TARGET_FILE_OWNER_GID);
        case PROCESS_FILE_MODE: return fieldref_pred_get_numeric_value_file(&current_event->process.file, TARGET_FILE_MODE);
        case PROCESS_FILE_SUID: return fieldref_pred_get_numeric_value_file(&current_event->process.file, TARGET_FILE_SUID);
        case PROCESS_FILE_SGID: return fieldref_pred_get_numeric_value_file(&current_event->process.file, TARGET_FILE_SGID);
        case PROCESS_FILE_NLINK: return fieldref_pred_get_numeric_value_file(&current_event->process.file, TARGET_FILE_NLINK);
        case PROCESS_FILE_TYPE: return fieldref_pred_get_numeric_value_file(&current_event->process.file, TARGET_FILE_TYPE);

        // Parent process fields (direct access to current_event->parent_process)
        case PARENT_PROCESS_PID: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_PID);
        case PARENT_PROCESS_PPID: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_PPID);
        case PARENT_PROCESS_RUID: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_RUID);
        case PARENT_PROCESS_RGID: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_RGID);
        case PARENT_PROCESS_EUID: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_EUID);
        case PARENT_PROCESS_EGID: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_EGID);
        case PARENT_PROCESS_SUID: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_SUID);
        case PARENT_PROCESS_PTRACE_FLAGS: return fieldref_pred_get_numeric_value_process(&current_event->parent_process, TARGET_PROCESS_PTRACE_FLAGS);
        case PARENT_PROCESS_FILE_OWNER_UID: return fieldref_pred_get_numeric_value_file(&current_event->parent_process.file, TARGET_FILE_OWNER_UID);
        case PARENT_PROCESS_FILE_OWNER_GID: return fieldref_pred_get_numeric_value_file(&current_event->parent_process.file, TARGET_FILE_OWNER_GID);
        case PARENT_PROCESS_FILE_MODE: return fieldref_pred_get_numeric_value_file(&current_event->parent_process.file, TARGET_FILE_MODE);
        case PARENT_PROCESS_FILE_SUID: return fieldref_pred_get_numeric_value_file(&current_event->parent_process.file, TARGET_FILE_SUID);
        case PARENT_PROCESS_FILE_SGID: return fieldref_pred_get_numeric_value_file(&current_event->parent_process.file, TARGET_FILE_SGID);
        case PARENT_PROCESS_FILE_NLINK: return fieldref_pred_get_numeric_value_file(&current_event->parent_process.file, TARGET_FILE_NLINK);
        case PARENT_PROCESS_FILE_TYPE: return fieldref_pred_get_numeric_value_file(&current_event->parent_process.file, TARGET_FILE_TYPE);

        // Rename source file fields
        case RENAME_SOURCE_FILE_OWNER_UID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.source_file, TARGET_FILE_OWNER_UID);
        case RENAME_SOURCE_FILE_OWNER_GID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.source_file, TARGET_FILE_OWNER_GID);
        case RENAME_SOURCE_FILE_MODE: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.source_file, TARGET_FILE_MODE);
        case RENAME_SOURCE_FILE_SUID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.source_file, TARGET_FILE_SUID);
        case RENAME_SOURCE_FILE_SGID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.source_file, TARGET_FILE_SGID);
        case RENAME_SOURCE_FILE_NLINK: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.source_file, TARGET_FILE_NLINK);
        case RENAME_SOURCE_FILE_TYPE: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.source_file, TARGET_FILE_TYPE);

        // Rename destination file fields
        case RENAME_DESTINATION_FILE_OWNER_UID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.destination_file, TARGET_FILE_OWNER_UID);
        case RENAME_DESTINATION_FILE_OWNER_GID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.destination_file, TARGET_FILE_OWNER_GID);
        case RENAME_DESTINATION_FILE_MODE: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.destination_file, TARGET_FILE_MODE);
        case RENAME_DESTINATION_FILE_SUID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.destination_file, TARGET_FILE_SUID);
        case RENAME_DESTINATION_FILE_SGID: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.destination_file, TARGET_FILE_SGID);
        case RENAME_DESTINATION_FILE_NLINK: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.destination_file, TARGET_FILE_NLINK);
        case RENAME_DESTINATION_FILE_TYPE: return fieldref_pred_get_numeric_value_file(&current_event->data.rename.destination_file, TARGET_FILE_TYPE);

        // Event-specific fields
        case CHMOD_REQUESTED_MODE: return current_event->data.chmod.requested_mode;
        case NETWORK_SOURCE_PORT: return current_event->data.network.source_port;
        case NETWORK_DESTINATION_PORT: return current_event->data.network.destination_port;
        case NETWORK_DIRECTION: return current_event->data.network.direction;

        default:
            REPORT_ERROR(GENERIC_ERROR, "invalid numeric fieldref: %d", fieldref);
            return FALSE;
    }
}

statfunc int fieldref_pred_fill_needle_file(struct string_utils_ctx *sctx, const struct file_t *file, enum rule_field_type field)
{
    switch (field)
    {
        case TARGET_FILE_PATH:
            sctx->needle_length = file->path.length;
            sctx->needle_max_length = PATH_MAX - 1;
            return bpf_probe_read_kernel(sctx->needle, sctx->needle_max_length, file->path.value) == SUCCESS ? TRUE : FALSE;
        case TARGET_FILE_FILENAME:
            sctx->needle_length = file->filename.length;
            sctx->needle_max_length = FILENAME_MAX_LENGTH - 1;
            return bpf_probe_read_kernel(sctx->needle, sctx->needle_max_length, file->filename.value) == SUCCESS ? TRUE : FALSE;
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected string file field: %d", field);
            return FALSE;
    }
}

statfunc int fieldref_pred_fill_needle_process(struct string_utils_ctx *sctx, const struct process_t *process, enum rule_field_type field)
{
    switch (field)
    {
        case TARGET_PROCESS_CMD:
            sctx->needle_length = process->cmd.length;
            sctx->needle_max_length = CMD_MAX - 1;
            return bpf_probe_read_kernel(sctx->needle, sctx->needle_max_length, process->cmd.value) == SUCCESS ? TRUE : FALSE;
        case TARGET_PROCESS_SHELL_COMMAND:
            sctx->needle_length = process->shell_command.length;
            sctx->needle_max_length = CMD_MAX - 1;
            return bpf_probe_read_kernel(sctx->needle, sctx->needle_max_length, process->shell_command.value) == SUCCESS ? TRUE : FALSE;
        default:
            return fieldref_pred_fill_needle_file(sctx, &process->file, field);
    }
}

statfunc int fieldref_pred_fill_needle_target_file(const struct event_t *current_event,struct string_utils_ctx *sctx, enum rule_field_type fieldref)
{
    switch (current_event->type)
    {
        case FILE_CREATE: return fieldref_pred_fill_needle_file(sctx, &current_event->data.file_create.file, fieldref);
        case MKDIR: return fieldref_pred_fill_needle_file(sctx, &current_event->data.mkdir.file, fieldref);
        case RMDIR: return fieldref_pred_fill_needle_file(sctx, &current_event->data.rmdir.file, fieldref);
        case CHOWN: return fieldref_pred_fill_needle_file(sctx, &current_event->data.chown.file, fieldref);
        case CHMOD: return fieldref_pred_fill_needle_file(sctx, &current_event->data.chmod.file, fieldref);
        case READ: return fieldref_pred_fill_needle_file(sctx, &current_event->data.read.file, fieldref);
        case WRITE: return fieldref_pred_fill_needle_file(sctx, &current_event->data.write.file, fieldref);
        case UNLINK: return fieldref_pred_fill_needle_file(sctx, &current_event->data.unlink.file, fieldref);
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected event type: %d", current_event->type);
            return FALSE;
    }
}

statfunc int fieldref_pred_fill_needle_target_process(const struct event_t *current_event, struct string_utils_ctx *sctx, enum rule_field_type field)
{
    switch (current_event->type)
    {
        case EXEC: return fieldref_pred_fill_needle_process(sctx, &current_event->data.exec.new_process, field);
        default:
            REPORT_ERROR(GENERIC_ERROR, "unexpected event type: %d", current_event->type);
            return FALSE;
    }
}

statfunc int fieldref_pred_fill_needle(struct string_utils_ctx *sctx, enum rule_field_type fieldref)
{
    const struct event_t *current_event = get_currently_handled_event();
    if(!current_event)
    {
        return FALSE;
    }

    switch (fieldref)
    {
        // Target file string fields (event type dispatch)
        case TARGET_FILE_PATH: return fieldref_pred_fill_needle_target_file(current_event, sctx, fieldref);
        case TARGET_FILE_FILENAME: return fieldref_pred_fill_needle_target_file(current_event, sctx, fieldref);

        // Target process string fields (event type dispatch, EXEC only)
        case TARGET_PROCESS_CMD: return fieldref_pred_fill_needle_target_process(current_event,sctx, TARGET_PROCESS_CMD);
        case TARGET_PROCESS_SHELL_COMMAND: return fieldref_pred_fill_needle_target_process(current_event, sctx, TARGET_PROCESS_SHELL_COMMAND);
        case TARGET_PROCESS_FILE_PATH: return fieldref_pred_fill_needle_target_process(current_event,sctx, TARGET_FILE_PATH);
        case TARGET_PROCESS_FILE_FILENAME: return fieldref_pred_fill_needle_target_process(current_event, sctx, TARGET_FILE_FILENAME);

        // Process string fields (direct access to current_event->process)
        case PROCESS_CMD: return fieldref_pred_fill_needle_process(sctx, &current_event->process, TARGET_PROCESS_CMD);
        case PROCESS_SHELL_COMMAND: return fieldref_pred_fill_needle_process(sctx, &current_event->process, TARGET_PROCESS_SHELL_COMMAND);
        case PROCESS_FILE_PATH: return fieldref_pred_fill_needle_file(sctx, &current_event->process.file, TARGET_FILE_PATH);
        case PROCESS_FILE_FILENAME: return fieldref_pred_fill_needle_file(sctx, &current_event->process.file, TARGET_FILE_FILENAME);

        // Parent process string fields (direct access to current_event->parent_process)
        case PARENT_PROCESS_CMD: return fieldref_pred_fill_needle_process(sctx, &current_event->parent_process, TARGET_PROCESS_CMD);
        case PARENT_PROCESS_SHELL_COMMAND: return fieldref_pred_fill_needle_process(sctx, &current_event->parent_process, TARGET_PROCESS_SHELL_COMMAND);
        case PARENT_PROCESS_FILE_PATH: return fieldref_pred_fill_needle_file(sctx, &current_event->parent_process.file, TARGET_FILE_PATH);
        case PARENT_PROCESS_FILE_FILENAME: return fieldref_pred_fill_needle_file(sctx, &current_event->parent_process.file, TARGET_FILE_FILENAME);

        // Rename file string fields
        case RENAME_SOURCE_FILE_PATH: return fieldref_pred_fill_needle_file(sctx, &current_event->data.rename.source_file, TARGET_FILE_PATH);
        case RENAME_SOURCE_FILE_FILENAME: return fieldref_pred_fill_needle_file(sctx, &current_event->data.rename.source_file, TARGET_FILE_FILENAME);
        case RENAME_DESTINATION_FILE_PATH: return fieldref_pred_fill_needle_file(sctx, &current_event->data.rename.destination_file, TARGET_FILE_PATH);
        case RENAME_DESTINATION_FILE_FILENAME: return fieldref_pred_fill_needle_file(sctx, &current_event->data.rename.destination_file, TARGET_FILE_FILENAME);

        default:
            REPORT_ERROR(GENERIC_ERROR, "invalid string fieldref: %d", fieldref);
            return FALSE;
    }
}
