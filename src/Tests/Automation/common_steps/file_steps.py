from pytest_bdd import given, when, then, parsers
from Utils.file_utils import *

@given(parsers.parse('I ensure new file "{filepath}" is created'))
@when(parsers.parse('I ensure new file "{filepath}" is created'))
@then(parsers.parse('I ensure new file "{filepath}" is created'))
def ensure_new_file_created(filepath):
    assert recreate_file(filepath), f"Failed to create file: {filepath}"

@given(parsers.parse('I ensure the file "{filepath}" exists'))
@when(parsers.parse('I ensure the file "{filepath}" exists'))
@then(parsers.parse('I ensure the file "{filepath}" exists'))
def ensure_file_exists(filepath):
    assert create_file(filepath), f"Failed to create file: {filepath}"


@given(parsers.parse('I ensure the file "{filepath}" does not exist'))
@when(parsers.parse('I ensure the file "{filepath}" does not exist'))
@then(parsers.parse('I ensure the file "{filepath}" does not exist'))
def ensure_file_not_exists(filepath):
    assert remove_file(filepath), f"Failed to remove file: {filepath}"


@given(parsers.parse('I ensure the directory "{dirpath}" exists'))
@when(parsers.parse('I ensure the directory "{dirpath}" exists'))
@then(parsers.parse('I ensure the directory "{dirpath}" exists'))
def ensure_directory_exists(dirpath):
    assert create_directory(dirpath), f"Failed to create directory: {dirpath}"


@given(parsers.parse('I ensure the directory "{dirpath}" does not exist'))
@when(parsers.parse('I ensure the directory "{dirpath}" does not exist'))
@then(parsers.parse('I ensure the directory "{dirpath}" does not exist'))
def ensure_directory_not_exists(dirpath):
    assert remove_directory(dirpath), f"Failed to remove directory: {dirpath}"


@given(parsers.parse('I fail to create file "{filepath}"'))
@when(parsers.parse('I fail to create file "{filepath}"'))
@then(parsers.parse('I fail to create file "{filepath}"'))
def ensure_file_not_created(filepath):
    assert not create_file(filepath), f"Expected file to not be created: {filepath}"


@given(parsers.parse('I try to write to the file "{filepath}" the content "{content}"'))
@when(parsers.parse('I try to write to the file "{filepath}" the content "{content}"'))
@then(parsers.parse('I try to write to the file "{filepath}" the content "{content}"'))
def try_to_write_to_file(filepath, content):
    try:
        open(filepath, 'w').write(content)
        file_db.add(filepath)
        logger.log_info(f"Successfully wrote to file: {filepath}")
    except Exception as e:
        logger.log_error(f"Failed to write to file: {filepath}. Error: {e}")
        pass

@given(parsers.parse('I try to append to the file "{filepath}" the content "{content}"'))
@when(parsers.parse('I try to append to the file "{filepath}" the content "{content}"'))
@then(parsers.parse('I try to append to the file "{filepath}" the content "{content}"'))
def try_to_append_to_file(filepath, content):
    try:
        open(filepath, 'a').write(content)
        file_db.add(filepath)
        logger.log_info(f"Successfully appended to file: {filepath}")
    except Exception as e:
        logger.log_error(f"Failed to append to file: {filepath}. Error: {e}")
        pass

@given(parsers.parse('file size of "{filepath}" is "{size}" bytes'))
@when(parsers.parse('file size of "{filepath}" is "{size}" bytes'))
@then(parsers.parse('file size of "{filepath}" is "{size}" bytes'))
def file_size(filepath, size):
    try:
        actual_size = os.path.getsize(filepath)
        assert actual_size == int(size), f"Expected file size to be {size} bytes, but got {actual_size} bytes: {filepath}"
    except OSError as e:
        assert False, f"Failed to get file size for {filepath}: {e}"


@given(parsers.parse('I ensure the hard link "{source_path}" to "{target_path}" exists'))
@when(parsers.parse('I ensure the hard link "{source_path}" to "{target_path}" exists'))
@then(parsers.parse('I ensure the hard link "{source_path}" to "{target_path}" exists'))
def ensure_hard_link_exists(source_path, target_path):
    assert create_hard_link(source_path, target_path), f"Failed to create hard link: {target_path}"


@given(parsers.parse('The file "{filepath}" should exist "{exists}"'))
@when(parsers.parse('The file "{filepath}" should exist "{exists}"'))
@then(parsers.parse('The file "{filepath}" should exist "{exists}"'))
def check_file_exists(filepath, exists):
    if exists.lower() == "true" and os.path.exists(filepath):
        return
    if exists.lower() == "false" and not os.path.exists(filepath):
        return
    else:
        logger.log_error(f"Expected file {filepath} to exist: {exists}, but actual: {os.path.exists(filepath)}")
        assert False, f"Expected file {filepath} to exist: {exists}, but actual: {os.path.exists(filepath)}"


@given(parsers.parse('I add the path "{path}" to the file db'))
@when(parsers.parse('I add the path "{path}" to the file db'))
@then(parsers.parse('I add the path "{path}" to the file db'))
def add_file_to_db(path):
    file_db.add(path)

@given(parsers.parse('I chmod the file "{filepath}" to "{mode}"'))
@when(parsers.parse('I chmod the file "{filepath}" to "{mode}"'))
@then(parsers.parse('I chmod the file "{filepath}" to "{mode}"'))
def chmod_file(filepath, mode):
    mode_num = int(mode, 8)
    try:
        os.chmod(filepath, mode_num)
        logger.log_info(f"Successfully chmod file: {filepath} to {mode}")
    except Exception as e:
        logger.log_error(f"Failed to chmod file: {filepath} to {mode}. Error: {e}")
        assert False, f"Failed to chmod file: {filepath} to {mode}. Error: {e}"

@given(parsers.parse('I rename the file "{source_path}" to "{target_path}"'))
@when(parsers.parse('I rename the file "{source_path}" to "{target_path}"'))
@then(parsers.parse('I rename the file "{source_path}" to "{target_path}"'))
def rename_file(source_path, target_path):
    try:
        os.rename(source_path, target_path)
        file_db.add(target_path)
        logger.log_info(f"Successfully renamed file: {source_path} to {target_path}")
    except Exception as e:
        logger.log_error(f"Failed to rename file: {source_path} to {target_path}. Error: {e}")
        assert False, f"Failed to rename file: {source_path} to {target_path}. Error: {e}"