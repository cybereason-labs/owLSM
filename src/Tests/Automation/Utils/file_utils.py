import os
import shutil
from Utils.logger_utils import logger
from state_db.file_db import file_db


def create_file(path: str) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o444))
        logger.log_info(f"Successfully created file: {path}")
        file_db.add(path)
        return True
    except Exception as e:
        logger.log_error(f"Failed to create file: {path}. Error: {e}")
        return False


def recreate_file(path: str) -> bool:
    try:
        if os.path.exists(path):
            os.remove(path)
            file_db.remove(path)
        return create_file(path)
    except Exception as e:
        logger.log_error(f"Failed to recreate file: {path}. Error: {e}")
        return False


def remove_file(path: str) -> bool:
    try:
        if os.path.exists(path):
            os.remove(path)
        logger.log_info(f"Successfully removed file: {path}")
        file_db.remove(path)
        return True
    except Exception as e:
        logger.log_error(f"Failed to remove file: {path}. Error: {e}")
        return False


def create_directory(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        logger.log_info(f"Successfully created directory: {path}")
        file_db.add(path)
        return True
    except Exception as e:
        logger.log_error(f"Failed to create directory: {path}. Error: {e}")
        return False


def recreate_directory(path: str) -> bool:
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
            file_db.remove(path)
        return create_directory(path)
    except Exception as e:
        logger.log_error(f"Failed to recreate directory: {path}. Error: {e}")
        return False


def remove_directory(path: str) -> bool:
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
        logger.log_info(f"Successfully removed directory: {path}")
        file_db.remove(path)
        return True
    except Exception as e:
        logger.log_error(f"Failed to remove directory: {path}. Error: {e}")
        return False


def create_hard_link(source_path: str, target_path: str) -> bool:
    try:
        os.link(source_path, target_path)
        logger.log_info(f"Successfully created hard link: {target_path}")
        file_db.add(target_path)
        return True
    except Exception as e:
        logger.log_error(f"Failed to create hard link: {target_path}. Error: {e}")
        return False