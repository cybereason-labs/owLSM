import subprocess
import os
import signal
import psutil
from Utils.logger_utils import logger
from state_db.process_db import process_db
from globals.system_related_globals import system_globals

def run_command_sync(command: str, timeout: int = None, stdout_fd=None, stderr_fd=None, stdin_data=None, expect_exit_code=None, user: str = None) -> bool:
    return_value = False
    try:
        stdout_target = stdout_fd if stdout_fd is not None else subprocess.PIPE
        stderr_target = stderr_fd if stderr_fd is not None else subprocess.PIPE
        
        result = subprocess.run(
            command.split(), 
            stdout=stdout_target,
            stderr=stderr_target,
            input=stdin_data,
            text=True,
            timeout=timeout,
            user=user,
        )
        
        user_info = f" (as user: {user})" if user else ""
        if stdout_fd is None and stderr_fd is None:
            logger.log_info(f"Command completed{user_info}: {command}, stdout: {result.stdout.strip()}, stderr: {result.stderr.strip()}, exit code: {result.returncode}")
        else:
            logger.log_info(f"Command completed{user_info}: {command}, exit code: {result.returncode} (output redirected to provided file descriptors)")

        if expect_exit_code is not None:
            return_value = (result.returncode == expect_exit_code)
        else:
            return_value = True
        
    except subprocess.TimeoutExpired as e:
        message = f"Command timed out after {timeout}s: {command}"
        if stdout_fd is None and e.stdout:
            message += f"\nSTDOUT: {e.stdout.strip()}"
        if stderr_fd is None and e.stderr:
            message += f"\nSTDERR: {e.stderr.strip()}"
        logger.log_error(message)
        return_value = False
        
    except Exception as e:
        logger.log_error(f"Failed to run command: {command}. Error: {e}")
        return_value = False

    return return_value


def run_command_async(command: str, stdout_fd=None, stderr_fd=None, user: str = None):
    try:
        stdout_target = stdout_fd if stdout_fd is not None else subprocess.PIPE
        stderr_target = stderr_fd if stderr_fd is not None else subprocess.PIPE
        
        proc = subprocess.Popen(
            command.split(),
            stdout=stdout_target,
            stderr=stderr_target,
            stdin=subprocess.PIPE,
            text=True,
            user=user,
        )
        
        process_db.add(proc.pid, get_pid_start_time(proc.pid))
        user_info = f" (as user: {user})" if user else ""
        if stdout_fd is None and stderr_fd is None:
            logger.log_info(f"Started async command{user_info}: {command} (PID: {proc.pid}) with output captured to pipes")
        else:
            logger.log_info(f"Started async command{user_info}: {command} (PID: {proc.pid}) with output redirected to provided file descriptors")
        return proc
        
    except Exception as e:
        logger.log_error(f"Failed to start async command: {command}. Error: {e}")
        return None

def ensure_async_command_runs_for_at_least_seconds(command: str, seconds: int, stdout_fd=None, stderr_fd=None):
    proc = run_command_async(command, stdout_fd, stderr_fd)
    if proc is None:
        assert False, f"Failed to start async command: {command}"
    
    try:
        proc.wait(timeout=seconds)
        logger.log_error(f"Async command {command} ran for less than {seconds} seconds")
        assert False, f"Async command {command} ran for less than {seconds} seconds"
    except subprocess.TimeoutExpired:
        return proc
    except Exception as e:
        logger.log_error(f"Failed to ensure async command runs for at least {seconds} seconds: {command}. Error: {e}")
        assert False, f"Failed to ensure async command runs for at least {seconds} seconds: {command}. Error: {e}"


def run_command_sync_as_grandchild(command: str, timeout: int = None, user: str = None) -> bool:
        logger.log_info(f"running command as grandchild: {command}")
        child_pid = fork_current_process()
        if child_pid == 0:
            run_command_sync(command, timeout, user=user)
        else:
            os.waitpid(child_pid, 0)
            return True
    
def fork_current_process():
    child_pid = None
    try:
        child_pid = os.fork()
    except Exception as e:
        logger.log_error(f"Failed to fork current process. Error: {e}")
        assert False, f"Failed to fork current process. Error: {e}"

    if child_pid != 0:
        process_db.add(child_pid, get_pid_start_time(child_pid))

    return child_pid


def get_pid_start_time(pid: int):
    return psutil.Process(pid).create_time()

def stop_owlsm_process():
    if system_globals.OWLSM_PROCESS_OBJECT:
        try:
            system_globals.OWLSM_PROCESS_OBJECT.send_signal(signal.SIGINT)
            try:
                system_globals.OWLSM_PROCESS_OBJECT.wait(timeout=10)
                logger.log_info(f"OWLSM process stopped successfully, pid: {system_globals.OWLSM_PROCESS_OBJECT.pid}")
            except subprocess.TimeoutExpired:
                system_globals.OWLSM_PROCESS_OBJECT.kill()
                logger.log_error(f"OWLSM process did not stop within 10 seconds after SIGINT, pid: {system_globals.OWLSM_PROCESS_OBJECT.pid}. Killing process.")
                assert False, f"OWLSM process did not stop within 10 seconds after SIGINT, pid: {system_globals.OWLSM_PROCESS_OBJECT.pid}. Killing process."
        except Exception as e:
            logger.log_error(f"Failed to kill OWLSM process: {e}")
            assert False, f"Failed to kill OWLSM process: {e}"
            
    system_globals.OWLSM_PROCESS_OBJECT = None

def start_owlsm_process(command: str):
    system_globals.OWLSM_OUTPUT_LOG_FD = open(system_globals.OWLSM_OUTPUT_LOG, 'w')
    system_globals.OWLSM_PROCESS_OBJECT = ensure_async_command_runs_for_at_least_seconds(
        command, system_globals.OWLSM_SETUP_TIME_IN_SECONDS, system_globals.OWLSM_OUTPUT_LOG_FD, system_globals.OWLSM_OUTPUT_LOG_FD)
    logger.log_info(f"owLSM installation attempt completed")
    process_db.remove(system_globals.OWLSM_PROCESS_OBJECT.pid)