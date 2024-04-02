import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io
import json
import traceback
import zipfile
from base64 import b64decode
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from shutil import copy
from tempfile import TemporaryDirectory
from typing import Any
import logging

import git
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, TYPE_TO_EXTENSION, FileType
from demisto_sdk.commands.common.logger import logging_setup
from demisto_sdk.commands.common.tools import find_type
from demisto_sdk.commands.common.handlers import YAML_Handler
from demisto_sdk.commands.init.contribution_converter import (ContributionConverter)
from demisto_sdk.commands.lint.lint_manager import LintManager
from demisto_sdk.commands.split.ymlsplitter import YmlSplitter
from demisto_sdk.commands.validate.old_validate_manager import OldValidateManager as ValidateManager


COMMAND_OUTPUT_PREFIX = "ValidationResult"
COMMAND_OUTPUT_KEY_NAME = "Name"
COMMAND_OUTPUT_KEY_LINE = "Line"
COMMAND_OUTPUT_KEY_ERROR = "Error"
CACHED_MODULES_DIR = '/tmp/cached_modules'
yaml = YAML_Handler()


def get_extracted_code_filepath(extractor: YmlSplitter) -> str:
    output_path = extractor.get_output_path()
    base_name = os.path.basename(output_path) if not extractor.base_name else extractor.base_name
    code_file = f'{output_path}/{base_name}'
    script = extractor.yml_data['script']
    lang_type: str = script['type'] if extractor.file_type == 'integration' else extractor.yml_data['type']
    code_file = f'{code_file}{TYPE_TO_EXTENSION[lang_type]}'
    return code_file


def get_pack_name(zip_fp: str) -> str:
    """returns the pack name from the zipped contribution file's metadata.json file"""
    with zipfile.ZipFile(zip_fp) as zipped_contrib, zipped_contrib.open('metadata.json') as metadata_file:
        metadata = json.loads(metadata_file.read())
    return metadata.get('name', 'ServerSidePackValidationDefaultName')


def adjust_linter_row_and_col(
        error_output: dict, code_fp_to_row_offset: dict | None = None,
        row_offset: int = 2, row_start: int = 1, col_offset: int = 1, col_start: int = 0
) -> None:
    """Update the linter errors row and column numbering

    Accounts for lines inserted during demisto-sdk extract, and that row numbering starts with one. We
    take the max between the adjusted vector number and the vector start because the lowest the adjusted
    vector number should be is its associated vector start number. e.g. the adjusted column number should
    never be less than the column start number aka zero - so if the adjusted column number is -1, we set
    it to the column start number instead, aka zero.

    Args:
        error_output (dict): A single validation result dictionary (validate and lint) from the total list
        code_fp_to_row_offset (Optional[dict]): Mapping of file paths to the row offset for that code file
        row_offset (int): The number of rows to adjust by
        row_start (int): The lowest allowable number for rows
        col_offset (int): The number of columns to adjust by
        col_start (int): The lowest allowable number for columns
    """
    row, col = 'row', 'col'
    vector_details = [
        (row, row_offset, row_start),
        (col, col_offset, col_start)
    ]
    try:
        for vector, offset, start in vector_details:
            if vector in error_output:
                # grab and set the row offset from the file to row offset mapping if it exists and we are
                # operating on 'row'
                if code_fp_to_row_offset and vector == row:
                    filepath = error_output.get('filePath', '')
                    if filepath in code_fp_to_row_offset:
                        offset_for_file = code_fp_to_row_offset.get(filepath)
                        if isinstance(offset_for_file, int):
                            offset = offset_for_file
                original_vector_value: Any | None = error_output.get(vector)
                if original_vector_value:
                    error_output[vector] = str(max(int(original_vector_value) - offset, start))
    except ValueError as e:
        demisto.debug(f'Failed adjusting "{vector}" on validation result {error_output}'
                      f'\n{e}')


def get_files_to_validate(file_path: str) -> str:
    """
    Returns the files to validate.

    Args:
    - `file_path` (``str``): The input path. If the path is a directory,
    we get all files within that directory.

    Returns:
    - `str` of the file(s) to validate/lint. If it's multiple files,
    it will return a comma-separated list of them.
    """

    if not Path(file_path).is_dir():
        return file_path

    # Get all files in the directory
    files = [str(file) for file in Path(file_path).iterdir() if file.is_file()]

    # Join the files into a comma-separated string
    files_csv = ','.join(files)

    return files_csv


def run_validate(file_path: str, json_output_file: str) -> None:
    os.environ['DEMISTO_SDK_SKIP_VERSION_CHECK'] = '1'
    tests_dir = 'Tests'
    if not os.path.exists(tests_dir):
        os.makedirs(tests_dir)
    with open(f'{tests_dir}/id_set.json', 'w') as f:
        json.dump({}, f)

    files_to_validate = get_files_to_validate(file_path)

    # FIXME use the new validation manager
    v_manager = ValidateManager(
        is_backward_check=False,
        prev_ver="origin/master",
        use_git=False,
        only_committed_files=False,
        print_ignored_files=False,
        skip_conf_json=True,
        validate_id_set=False,
        file_path=files_to_validate,
        validate_all=False,
        is_external_repo=False,
        skip_pack_rn_validation=False,
        print_ignored_errors=False,
        silence_init_prints=False,
        no_docker_checks=False,
        skip_dependencies=False,
        id_set_path=None,
        staged=False,
        json_file_path=json_output_file,
        skip_schema_check=True,
        create_id_set=False,
        check_is_unskipped=False
    )
    v_manager.run_validation()


def run_lint(file_path: str, json_output_file: str) -> None:
    lint_log_dir = os.path.dirname(json_output_file)
    logging_setup(console_log_threshold=logging.DEBUG, skip_log_file_creation=True)

    lint_manager = LintManager(
        input=str(file_path),
        git=False,
        all_packs=False,
        prev_ver='origin/master',
        json_file_path=json_output_file
    )
    lint_manager.run(
        parallel=1, no_flake8=False, no_xsoar_linter=False, no_bandit=False, no_mypy=False,
        no_pylint=True, no_coverage=True, coverage_report='', no_vulture=False, no_test=True, no_pwsh_analyze=True,
        no_pwsh_test=True, keep_container=False, test_xml='', failure_report=lint_log_dir, docker_timeout=60,
        docker_image_flag=None, docker_image_target=None
    )


def prepare_content_pack_for_validation(filename: str, data: bytes, tmp_directory: str) -> tuple[str, dict]:
    # write zip file data to file system
    zip_path = os.path.abspath(os.path.join(tmp_directory, filename))
    with open(zip_path, 'wb') as fp:
        fp.write(data)

    pack_name = get_pack_name(zip_path)
    contrib_converter = ContributionConverter(name=pack_name, contribution=zip_path, base_dir=tmp_directory)
    # FIXME convert_contribution_to_pack doesn't return anything
    code_fp_to_row_offset = contrib_converter.convert_contribution_to_pack()
    # Call the standalone function and get the raw response
    os.remove(zip_path)
    return contrib_converter.pack_dir_path, code_fp_to_row_offset


def prepare_single_content_item_for_validation(
    filename: str,
    data: bytes,
    tmp_directory: str
) -> tuple[str, dict]:

    tmp_path_file_to_validate = Path(tmp_directory, filename)
    tmp_path_file_to_validate.touch()
    tmp_path_file_to_validate.write_bytes(data)

    file_type = find_type(path=str(tmp_path_file_to_validate))

    # If the content item is a JSON
    # or a Playbook, we return the path as is
    if tmp_path_file_to_validate.suffix == ".json" or file_type in (FileType.PLAYBOOK.value, FileType.TEST_PLAYBOOK.value):
        return str(tmp_path_file_to_validate), {}
    elif file_type in (FileType.INTEGRATION.value, FileType.SCRIPT.value):
        output_path = Path(tmp_directory, "Packs", "Base", ENTITY_TYPE_TO_DIR.get(file_type))
        with Path(tmp_directory, "Packs", "Base", "pack_metadata.json").open("w") as md:
            json.dump({'description': 'Temporary Pack', 'author': 'xsoar'}, md)
        extractor = YmlSplitter(
            input=str(tmp_path_file_to_validate),
            output=output_path,
            file_type=file_type,
            no_logging=True,
            no_pipenv=True,
            no_basic_fmt=True
        )
        tmp_path_file_to_validate.unlink()
        # validate the resulting package files, ergo set path_to_validate to the package directory that results
        # from extracting the unified yaml to a package format
        extractor.extract_to_package_format()
        code_fp_to_row_offset = {get_extracted_code_filepath(extractor): extractor.lines_inserted_at_code_start}
        return extractor.get_output_path(), code_fp_to_row_offset
    else:
        raise NotImplementedError(f"Validation for file type '{file_type}' not supported")


def validate_content(filename: str, data: bytes, tmp_directory: str) -> list:
    json_output_path = os.path.join(tmp_directory, 'validation_res.json')
    lint_output_path = os.path.join(tmp_directory, 'lint_res.json')
    output_capture = io.StringIO()
    log_capture = io.StringIO()

    with redirect_stdout(output_capture), redirect_stderr(output_capture):
        if filename.endswith('.zip'):
            path_to_validate, code_fp_to_row_offset = prepare_content_pack_for_validation(
                filename, data, tmp_directory
            )
        else:
            path_to_validate, code_fp_to_row_offset = prepare_single_content_item_for_validation(
                filename, data, tmp_directory
            )

        handler = logging.StreamHandler(log_capture)
        for name in [None, 'demisto-sdk']:
            logger = logging.getLogger(name)
            logger.handlers.clear()
            logger.addHandler(handler)

        run_validate(path_to_validate, json_output_path)
        run_lint(path_to_validate, lint_output_path)

        handler.flush()
        handler.close()

    demisto.debug("log capture:" + log_capture.getvalue())
    all_outputs = []
    with open(json_output_path) as json_outputs:
        outputs_as_json = json.load(json_outputs)
        if outputs_as_json:
            if isinstance(outputs_as_json, list):
                all_outputs.extend(outputs_as_json)
            else:
                all_outputs.append(outputs_as_json)

    with open(lint_output_path) as json_outputs:
        outputs_as_json = json.load(json_outputs)
        if outputs_as_json:
            if isinstance(outputs_as_json, list):
                for validation in outputs_as_json:
                    adjust_linter_row_and_col(validation, code_fp_to_row_offset)
                all_outputs.extend(outputs_as_json)
            else:
                all_outputs.append(outputs_as_json)
    return all_outputs


def get_content_modules(content_tmp_dir: str, verify_ssl: bool = True) -> None:
    """Copies the required content modules for linting from the cached dir
    The cached dir is updated once a day

    Args:
         content_tmp_dir (str): The content tmp dir to copy the content modules to
         verify_ssl (bool): Whether to verify SSL
    """
    modules = [
        {
            'file': 'CommonServerPython.py',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
                          '/CommonServerPython/CommonServerPython.py',
            'content_path': 'Packs/Base/Scripts/CommonServerPython',
        },
        {
            'file': 'CommonServerPowerShell.ps1',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
                          '/CommonServerPowerShell/CommonServerPowerShell.ps1',
            'content_path': 'Packs/Base/Scripts/CommonServerPowerShell',
        },
        {
            'file': 'demistomock.py',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.py',
            'content_path': 'Tests/demistomock',
        },
        {
            'file': 'demistomock.ps1',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.ps1',
            'content_path': 'Tests/demistomock',
        },
        {
            'file': 'tox.ini',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/tox.ini',
            'content_path': '.'
        },
        {
            'file': 'conftest.py',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Tests/scripts/dev_envs/pytest'
                          '/conftest.py',
            'content_path': 'Tests/scripts/dev_envs/pytest'
        },
        {
            'file': 'approved_usecases.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Tests/Marketplace/approved_usecases.json',
            'content_path': 'Tests/Marketplace',
        },
        {
            'file': 'approved_tags.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Tests/Marketplace/approved_tags.json',
            'content_path': 'Tests/Marketplace',
        },
        {
            'file': 'approved_categories.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Tests/Marketplace/approved_categories.json',
            'content_path': 'Tests/Marketplace',
        },

    ]
    for module in modules:
        content_path = os.path.join(content_tmp_dir, module['content_path'])
        os.makedirs(content_path, exist_ok=True)
        try:
            cached_module_path = os.path.join(CACHED_MODULES_DIR, module['file'])
            fname = Path(cached_module_path)
            modified_time = datetime.fromtimestamp(fname.stat().st_mtime) if os.path.isfile(cached_module_path) \
                else datetime(1970, 1, 1)
            if modified_time + timedelta(days=1) < datetime.utcnow():
                demisto.debug(f'Downloading {module["file"]} from git')
                res = requests.get(module['github_url'], verify=verify_ssl, timeout=10)
                res.raise_for_status()
                with open(cached_module_path, 'wb') as f:
                    f.write(res.content)
            demisto.debug(f'Copying from {cached_module_path} to {content_path}')
            copy(cached_module_path, content_path)
        except Exception as e:
            fallback_path = f'/home/demisto/{module["file"]}'
            demisto.debug(f'Failed downloading content module {module["github_url"]} - {e}. '
                          f'Copying from {fallback_path}')
            copy(fallback_path, content_path)


def get_file_name_and_contents(
        filename: str | None = None,
        data: str | None = None,
        entry_id: str | None = None,
) -> tuple[str, bytes]:
    """
    Return the file name and the decoded contents to validate.

    Args:
    - `filename` (``str | None``): The name of the file to validate.
    - `data` (``str | None``): The base64 encoded data of the file to validate.
    - `entry_id` (``str | None``): The entry ID.

    Returns:
    - ``tuple[str, bytes]`` with the name of the file and the decoded
    contents of the file.

    Throws:
    - `ValueError` if the provided arguments are unexpected.
    """

    if filename and data:
        return filename, b64decode(data)
    elif entry_id:
        file_object = demisto.getFilePath(entry_id)
        with open(file_object['path'], 'rb') as f:
            file_contents = f.read()
        return file_object['name'], file_contents
    else:
        raise ValueError("Invalid arguments provided")


def main():
    cwd = os.getcwd()
    try:
        args = demisto.args()
        content_tmp_dir = TemporaryDirectory()
        if args.get('use_system_proxy') == 'no':
            del os.environ['HTTP_PROXY']
            del os.environ['HTTPS_PROXY']
            del os.environ['http_proxy']
            del os.environ['https_proxy']
        verify_ssl = argToBoolean(args.get('trust_any_certificate'))

        content_repo = git.Repo.init(content_tmp_dir.name)
        content_repo.create_remote('origin', 'https://github.com/demisto/content.git')
        os.makedirs(CACHED_MODULES_DIR, exist_ok=True)

        get_content_modules(content_tmp_dir.name, verify_ssl)

        filename, file_contents = get_file_name_and_contents(
            args.get('filename'),
            args.get('data'),
            args.get('entry_id'),
        )

        os.makedirs(content_tmp_dir.name, exist_ok=True)
        os.chdir(content_tmp_dir.name)

        result = validate_content(filename, file_contents, content_tmp_dir.name)
        outputs = []
        for validation in result:
            if validation.get('ui') or validation.get('fileType') in {'py', 'ps1'}:
                outputs.append({
                    COMMAND_OUTPUT_KEY_NAME: validation.get('name'),
                    COMMAND_OUTPUT_KEY_ERROR: validation.get('message'),
                    COMMAND_OUTPUT_KEY_LINE: validation.get('row'),
                })
        return_results(CommandResults(
            readable_output=tableToMarkdown('Validation Results', outputs),
            outputs_prefix=COMMAND_OUTPUT_PREFIX,
            outputs=outputs,
            raw_response=result,
        ))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute ValidateContent. Error: {str(e)}')
    finally:
        content_tmp_dir.cleanup()
        os.chdir(cwd)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
