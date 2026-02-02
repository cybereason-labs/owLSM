from Utils.logger_utils import logger
from Utils.process_utils import *
from Utils.file_utils import *
import os

def create_local_user(username: str, password: str) -> bool:
    try:
        user_exists = run_command_sync(f"id {username}", expect_exit_code=0)
        if user_exists:
            logger.log_info(f"User '{username}' already exists")
            return True
        
        if not run_command_sync(f"useradd -m {username}", expect_exit_code=0):
            logger.log_error(f"Failed to create user: {username}")
            return False
        
        password_input = f"{username}:{password}"
        if not run_command_sync(f"chpasswd", stdin_data=password_input, expect_exit_code=0):
            logger.log_error(f"Failed to set password for user: {username}")
            return False

        run_command_sync(f"id -u {username}")
        run_command_sync(f"passwd -S {username}")
        
        logger.log_info(f"Successfully created user: {username}")
        return True
        
    except Exception as e:
        logger.log_error(f"Failed to create user {username}: {e}")
        return False

def add_user_to_group(username: str, group: str) -> bool:
    try:
        if not run_command_sync(f"usermod -aG {group} {username}"):
            logger.log_error(f"Failed to add user '{username}' to group '{group}'")
            return False
        
        logger.log_info(f"Successfully added user '{username}' to group '{group}'")
        return True
        
    except Exception as e:
        logger.log_error(f"Failed to add user {username} to group {group}: {e}")
        return False

def delete_user(username: str) -> bool:
    try:
        if not run_command_sync(f"id {username}"):
            logger.log_info(f"User '{username}' does not exist")
            return True
        
        if not run_command_sync(f"userdel -r {username}"):
            logger.log_error(f"Failed to delete user: {username}")
            return False
        
        remove_directory(f"/home/{username}")

        logger.log_info(f"Successfully deleted user: {username}")
        return True
        
    except Exception as e:
        logger.log_error(f"Failed to delete user {username}: {e}")
        return False

def ensure_automation_running_as_root():
    if os.geteuid() != 0:
        logger.log_error("automation must be run as root")
        assert False, "automation must be run as root"