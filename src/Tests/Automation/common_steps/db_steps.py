import os
from pytest_bdd import given, when, then, parsers
from state_db.owlsm_db import owlsm_db
from Utils.file_utils import get_build_id
from Utils.logger_utils import logger

KNOWN_SHELL_NAMES = {"bash", "dash", "zsh", "fish", "ksh"}

@given(parsers.parse('I delete the "{table_name}" table from the owLSM DB'))
@when(parsers.parse('I delete the "{table_name}" table from the owLSM DB'))
@then(parsers.parse('I delete the "{table_name}" table from the owLSM DB'))
def i_delete_table_from_owlsm_db(table_name):
    assert owlsm_db.delete_table(table_name), f"Failed to delete table '{table_name}' from the owLSM DB"

def get_shell_paths_from_system() -> set:
    shells = set()
    try:
        with open('/etc/shells', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    shells.add(line)
    except Exception as e:
        logger.log_error(f"Failed to read /etc/shells: {e}")
    return shells


def resolve_symlinks(paths: set) -> set:
    resolved = set()
    for path in paths:
        try:
            if os.path.exists(path):
                real_path = os.path.realpath(path)
                resolved.add(real_path)
            else:
                logger.log_warning(f"Shell path does not exist: {path}")
        except Exception as e:
            logger.log_warning(f"Failed to resolve path {path}: {e}")
    return resolved


def is_elf_binary(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
            return magic == b'\x7fELF'
    except Exception:
        return False


def filter_to_valid_shells(paths: set) -> dict:
    result = {}
    for path in paths:
        filename = os.path.basename(path)
        if filename not in KNOWN_SHELL_NAMES:
            continue
        
        if not is_elf_binary(path):
            continue
        
        try:
            stat_info = os.stat(path)
            mtime_ns = int(stat_info.st_mtime_ns)
            
            build_id = get_build_id(path)
            
            result[path] = {
                'inode': stat_info.st_ino,
                'dev': stat_info.st_dev,
                'last_modified_time': mtime_ns,
                'build_id': build_id
            }
            logger.log_info(f"Found valid shell: {path} (inode={stat_info.st_ino}, dev={stat_info.st_dev}, mtime_ns={mtime_ns}, build_id={build_id})")
        except Exception as e:
            logger.log_warning(f"Failed to get info for shell {path}: {e}")
    
    return result


def get_unique_shells_from_etc_shells() -> dict:
    shell_paths = get_shell_paths_from_system()
    if not shell_paths:
        return {}
    
    resolved_paths = resolve_symlinks(shell_paths)
    if not resolved_paths:
        return {}
    
    return filter_to_valid_shells(resolved_paths)


@given("all shells from /etc/shells are in the DB with correct data")
@when("all shells from /etc/shells are in the DB with correct data")
@then("all shells from /etc/shells are in the DB with correct data")
def verify_all_shells_in_db_with_correct_data():
    python_shells = get_unique_shells_from_etc_shells()
    assert len(python_shells) >= 1, "Expected at least 1 shell from /etc/shells, but found none"
    
    db_rows = owlsm_db.get_all_data_from_table("shell_db_table")
    
    db_shells_by_key = {}
    for row in db_rows:
        key = (row['inode'], row['dev'], row['last_modified_time'])
        db_shells_by_key[key] = row
    
    for path, expected_info in python_shells.items():
        key = (expected_info['inode'], expected_info['dev'], expected_info['last_modified_time'])
        
        assert key in db_shells_by_key, (
            f"Shell '{path}' (inode={expected_info['inode']}, dev={expected_info['dev']}, "
            f"mtime={expected_info['last_modified_time']}) not found in DB. "
            f"DB has {len(db_shells_by_key)} entries: {list(db_shells_by_key.keys())}"
        )
        
        db_row = db_shells_by_key[key]
        
        assert db_row['build_id'] == expected_info['build_id'], (
            f"Build ID mismatch for shell '{path}': "
            f"expected '{expected_info['build_id']}', got '{db_row['build_id']}'"
        )
        
        logger.log_info(f"Shell '{path}' verified in DB with correct data")
    
    logger.log_info(f"All {len(python_shells)} shells from /etc/shells verified in DB")

