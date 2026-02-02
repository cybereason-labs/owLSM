from Utils.logger_utils import logger
from globals.system_related_globals import system_globals
from state_db.file_db import file_db
from state_db.process_db import process_db
import os
import shutil
import psutil
from pathlib import Path

def session_cleanup():
    logger.log_info("pytest_sessioncleanup")
    if system_globals.OWLSM_PROCESS_OBJECT:
        try:
            system_globals.OWLSM_PROCESS_OBJECT.kill()
        except Exception as e:
            logger.log_error(f"Failed to kill OWLSM process: {e}")
    
    file_paths = file_db.get_all()
    for path in file_paths:
        try:
            if os.path.exists(path):
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
        except Exception as e:
            logger.log_error(f"Failed to cleanup file/dir '{path}': {e}")
    
    file_db.remove_all()
    
    process_entries = process_db.get_all()
    for pid, start_time in process_entries:
        try:
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                if abs(process.create_time() - start_time) < 3.0:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                else:
                    logger.log_warning(f"PID {pid} exists but start time mismatch - skipping cleanup")
        except Exception as e:
            logger.log_error(f"Failed to cleanup process PID {pid}: {e}")
    
    process_db.remove_all()


def remove_old_log_directories():
    try:
        log_storage_path = Path(system_globals.LOG_STORAGE_PATH)
        if log_storage_path.exists() and log_storage_path.is_dir():
            directories = [d for d in log_storage_path.iterdir() if d.is_dir()]
            
            if len(directories) > 5:
                directories.sort(key=lambda x: x.stat().st_mtime)
                oldest_dir = directories[0]
                shutil.rmtree(oldest_dir)
                logger.log_info(f"Removed oldest log directory: {oldest_dir}")
    except Exception as e:
        logger.log_error(f"Failed to cleanup old log directories: {e}")


def save_log_files(scenario_name: str):
    try:
        log_storage_path = Path(system_globals.LOG_STORAGE_PATH) / system_globals.TESTS_START_TIME / scenario_name
        if not log_storage_path.exists():
            log_storage_path.mkdir(parents=True, exist_ok=True)
        shutil.copy(system_globals.LOG_PATH, log_storage_path / system_globals.LOG_PATH.name)
        shutil.copy(system_globals.OWLSM_OUTPUT_LOG, log_storage_path / system_globals.OWLSM_OUTPUT_LOG.name)
    except Exception as e:
        logger.log_error(f"Failed to save log files: {e}")