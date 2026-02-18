import os
import shutil
from elftools.elf.elffile import ELFFile
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


def recreate_directory(path: str, mode: int = 0o777) -> bool:
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
            file_db.remove(path)
        os.mkdir(path, mode)
        logger.log_info(f"Successfully created directory: {path} with mode: {oct(mode)}")
        file_db.add(path)
        return True
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


def get_build_id(binary_path: str) -> str:
    try:
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)
            
            build_id_section = elf.get_section_by_name('.note.gnu.build-id')
            if build_id_section is not None:
                build_id = _get_build_id_from_iterator(build_id_section)
                if build_id is not None:
                    return build_id
            
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_NOTE':
                    build_id = _get_build_id_from_iterator(segment)
                    if build_id is not None:
                        return build_id
            
            assert False, f"No GNU build-id found in binary: {binary_path}"
            
    except Exception as e:
        assert False, f"Failed to extract build-id from {binary_path}: {e}"


def _get_build_id_from_iterator(elf_part):
    for note in elf_part.iter_notes():
        if note['n_type'] == 'NT_GNU_BUILD_ID':
            build_id = note['n_desc']
            return build_id

    return None