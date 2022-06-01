import io
import json
import traceback
import types
import zipfile
from base64 import b64decode
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from shutil import copy
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Tuple

import git
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, TYPE_TO_EXTENSION, FileType
from demisto_sdk.commands.common.content import Content
from demisto_sdk.commands.common.logger import logging_setup
from demisto_sdk.commands.common.tools import find_type
from demisto_sdk.commands.init.contribution_converter import (
    AUTOMATION, INTEGRATION, INTEGRATIONS_DIR, SCRIPT, SCRIPTS_DIR,
    ContributionConverter, get_child_directories, get_child_files)
from demisto_sdk.commands.lint.lint_manager import LintManager
from demisto_sdk.commands.split.ymlsplitter import YmlSplitter
from demisto_sdk.commands.validate.validate_manager import ValidateManager
from ruamel.yaml import YAML

import demistomock as demisto
from CommonServerPython import *

CACHED_MODULES_DIR = '/tmp/cached_modules'
yaml = YAML()


def _create_pack_base_files(self):
    """
    Create empty 'README.md', '.secrets-ignore', and '.pack-ignore' files that are expected
    to be in the base directory of a pack
    """
    fp = open(os.path.join(self.pack_dir_path, 'README.md'), 'a')
    fp.close()

    fp = open(os.path.join(self.pack_dir_path, '.secrets-ignore'), 'a')
    fp.close()

    fp = open(os.path.join(self.pack_dir_path, '.pack-ignore'), 'a')
    fp.close()


def get_extracted_code_filepath(extractor: YmlSplitter) -> str:
    output_path = extractor.get_output_path()
    base_name = os.path.basename(output_path) if not extractor.base_name else extractor.base_name
    code_file = f'{output_path}/{base_name}'
    script = extractor.yml_data['script']
    lang_type: str = script['type'] if extractor.file_type == 'integration' else extractor.yml_data['type']
    code_file = f'{code_file}{TYPE_TO_EXTENSION[lang_type]}'
    return code_file


def content_item_to_package_format(
        self, content_item_dir: str, del_unified: bool = True, source_mapping: Optional[Dict] = None,  # noqa: F841
        code_fp_to_row_offset: Dict = {}
) -> None:
    child_files = get_child_files(content_item_dir)
    for child_file in child_files:
        cf_name_lower = os.path.basename(child_file).lower()
        if cf_name_lower.startswith((SCRIPT, AUTOMATION, INTEGRATION)) and cf_name_lower.endswith('yml'):
            content_item_file_path = child_file
            file_type = find_type(content_item_file_path)
            file_type = file_type.value if file_type else file_type
            try:
                extractor = YmlSplitter(
                    input=content_item_file_path, file_type=file_type, output=content_item_dir, no_logging=True,
                    no_pipenv=True, no_basic_fmt=True)
                extractor.extract_to_package_format()
                code_fp = get_extracted_code_filepath(extractor)
                code_fp_to_row_offset[code_fp] = extractor.lines_inserted_at_code_start
            except Exception as e:
                err_msg = f'Error occurred while trying to split the unified YAML "{content_item_file_path}" ' \
                          f'into its component parts.\nError: "{e}"'
                self.contrib_conversion_errs.append(err_msg)
            if del_unified:
                os.remove(content_item_file_path)


def convert_contribution_to_pack(contrib_converter: ContributionConverter) -> Dict:
    """Create or updates a pack in the content repo from the contents of a contribution zipfile

    Args:
        contrib_converter (ContributionConverter): Contribution contributor object
    """
    # only create pack_metadata.json and base pack files if creating a new pack
    if contrib_converter.create_new:
        if contrib_converter.contribution:
            # create pack metadata file
            with zipfile.ZipFile(contrib_converter.contribution) as zipped_contrib:
                with zipped_contrib.open('metadata.json') as metadata_file:
                    metadata = json.loads(metadata_file.read())
                    contrib_converter.create_metadata_file(metadata)
        # create base files
        contrib_converter.create_pack_base_files = types.MethodType(_create_pack_base_files, contrib_converter)
        contrib_converter.create_pack_base_files()
    # unpack
    contrib_converter.unpack_contribution_to_dst_pack_directory()
    # convert
    unpacked_contribution_dirs = get_child_directories(contrib_converter.pack_dir_path)
    for unpacked_contribution_dir in unpacked_contribution_dirs:
        contrib_converter.convert_contribution_dir_to_pack_contents(unpacked_contribution_dir)
    # extract to package format
    code_fp_to_row_offset: Dict[str, int] = {}
    for pack_subdir in get_child_directories(contrib_converter.pack_dir_path):
        basename = os.path.basename(pack_subdir)
        if basename in {SCRIPTS_DIR, INTEGRATIONS_DIR}:
            contrib_converter.content_item_to_package_format = types.MethodType(content_item_to_package_format,
                                                                                contrib_converter)
            contrib_converter.content_item_to_package_format(
                pack_subdir, del_unified=True, source_mapping=None, code_fp_to_row_offset=code_fp_to_row_offset
            )
    return code_fp_to_row_offset


def get_pack_name(zip_fp: str) -> str:
    """returns the pack name from the zipped contribution file's metadata.json file"""
    with zipfile.ZipFile(zip_fp) as zipped_contrib:
        with zipped_contrib.open('metadata.json') as metadata_file:
            metadata = json.loads(metadata_file.read())
    return metadata.get('name', 'ServerSidePackValidationDefaultName')


def adjust_linter_row_and_col(
        error_output: Dict, code_fp_to_row_offset: Optional[Dict] = None,
        row_offset: int = 2, row_start: int = 1, col_offset: int = 1, col_start: int = 0
) -> None:
    """Update the linter errors row and column numbering

    Accounts for lines inserted during demisto-sdk extract, and that row numbering starts with one. We
    take the max between the adjusted vector number and the vector start because the lowest the adjusted
    vector number should be is its associated vector start number. e.g. the adjusted column number should
    never be less than the column start number aka zero - so if the adjusted column number is -1, we set
    it to the column start number instead, aka zero.

    Args:
        error_output (Dict): A single validation result dictionary (validate and lint) from the total list
        code_fp_to_row_offset (Optional[Dict]): Mapping of file paths to the row offset for that code file
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
                original_vector_value: Optional[Any] = error_output.get(vector)
                if original_vector_value:
                    error_output[vector] = str(max(int(original_vector_value) - offset, start))
    except ValueError as e:
        demisto.debug(f'Failed adjusting "{vector}" on validation result {error_output}'
                      f'\n{e}')


def run_validate(file_path: str, json_output_file: str) -> None:
    os.environ['DEMISTO_SDK_SKIP_VERSION_CHECK'] = '1'
    tests_dir = 'Tests'
    if not os.path.exists(tests_dir):
        os.makedirs(tests_dir)
    with open(f'{tests_dir}/id_set.json', 'w') as f:
        json.dump({}, f)
    v_manager = ValidateManager(
        is_backward_check=False, prev_ver=None, use_git=False, only_committed_files=False,
        print_ignored_files=False, skip_conf_json=True, validate_id_set=False, file_path=file_path,
        validate_all=False, is_external_repo=False, skip_pack_rn_validation=False, print_ignored_errors=False,
        silence_init_prints=False, no_docker_checks=False, skip_dependencies=False, id_set_path=None,
        staged=False, json_file_path=json_output_file, skip_schema_check=True, create_id_set=False, check_is_unskipped=False)
    v_manager.run_validation()


def run_lint(file_path: str, json_output_file: str) -> None:
    lint_log_dir = os.path.dirname(json_output_file)
    logging_setup(verbose=3, quiet=False, log_path=lint_log_dir)
    lint_manager = LintManager(
        input=file_path, git=False, all_packs=False, quiet=False, verbose=1,
        prev_ver='', json_file_path=json_output_file
    )
    lint_manager.run_dev_packages(
        parallel=1, no_flake8=False, no_xsoar_linter=False, no_bandit=False, no_mypy=False,
        no_pylint=True, no_coverage=True, coverage_report='', no_vulture=False, no_test=True, no_pwsh_analyze=True,
        no_pwsh_test=True, keep_container=False, test_xml='', failure_report=lint_log_dir, docker_timeout=60,
    )


def prepare_content_pack_for_validation(filename: str, data: bytes, tmp_directory: str) -> Tuple[str, Dict]:
    # write zip file data to file system
    zip_path = os.path.abspath(os.path.join(tmp_directory, filename))
    with open(zip_path, 'wb') as fp:
        fp.write(data)

    pack_name = get_pack_name(zip_path)
    contrib_converter = ContributionConverter(name=pack_name, contribution=zip_path, base_dir=tmp_directory)
    code_fp_to_row_offset = convert_contribution_to_pack(contrib_converter)
    # Call the standalone function and get the raw response
    os.remove(zip_path)
    return contrib_converter.pack_dir_path, code_fp_to_row_offset


def prepare_single_content_item_for_validation(filename: str, data: bytes, tmp_directory: str) -> Tuple[str, Dict]:
    content = Content(tmp_directory)
    pack_name = 'TmpPack'
    pack_dir = content.path / 'Packs' / pack_name
    # create pack_metadata.json file in TmpPack
    contrib_converter = ContributionConverter(name=pack_name, base_dir=tmp_directory, pack_dir_name=pack_name)
    contrib_converter.create_metadata_file({'description': 'Temporary Pack', 'author': 'xsoar'})
    prefix = '-'.join(filename.split('-')[:-1])
    containing_dir = pack_dir / ENTITY_TYPE_TO_DIR.get(prefix, 'Integrations')
    containing_dir.mkdir(exist_ok=True)
    is_json = filename.casefold().endswith('.json')
    data_as_string = data.decode()
    loaded_data = json.loads(data_as_string) if is_json else yaml.load(data_as_string)
    if is_json:
        data_as_string = json.dumps(loaded_data)
    else:
        buff = io.StringIO()
        yaml.dump(loaded_data, buff)
        data_as_string = buff.getvalue()
    # write content item file to file system
    file_path = containing_dir / filename
    file_path.write_text(data_as_string)
    file_type = find_type(str(file_path))
    file_type = file_type.value if file_type else file_type
    if is_json or file_type in (FileType.PLAYBOOK.value, FileType.TEST_PLAYBOOK.value):
        return str(file_path), {}
    extractor = YmlSplitter(
        input=str(file_path), file_type=file_type, output=containing_dir,
        no_logging=True, no_pipenv=True, no_basic_fmt=True
    )
    # validate the resulting package files, ergo set path_to_validate to the package directory that results
    # from extracting the unified yaml to a package format
    extractor.extract_to_package_format()
    code_fp_to_row_offset = {get_extracted_code_filepath(extractor): extractor.lines_inserted_at_code_start}
    return extractor.get_output_path(), code_fp_to_row_offset


def validate_content(filename: str, data: bytes, tmp_directory: str) -> List:
    json_output_path = os.path.join(tmp_directory, 'validation_res.json')
    lint_output_path = os.path.join(tmp_directory, 'lint_res.json')
    output_capture = io.StringIO()
    code_fp_to_row_offset = None
    with redirect_stdout(output_capture):
        with redirect_stderr(output_capture):
            if filename.endswith('.zip'):
                path_to_validate, code_fp_to_row_offset = prepare_content_pack_for_validation(
                    filename, data, tmp_directory
                )
            else:
                path_to_validate, code_fp_to_row_offset = prepare_single_content_item_for_validation(
                    filename, data, tmp_directory
                )

            run_validate(path_to_validate, json_output_path)
            run_lint(path_to_validate, lint_output_path)

    all_outputs = []
    with open(json_output_path, 'r') as json_outputs:
        outputs_as_json = json.load(json_outputs)
        if outputs_as_json:
            if type(outputs_as_json) == list:
                all_outputs.extend(outputs_as_json)
            else:
                all_outputs.append(outputs_as_json)

    with open(lint_output_path, 'r') as json_outputs:
        outputs_as_json = json.load(json_outputs)
        if outputs_as_json:
            if type(outputs_as_json) == list:
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
        filename: Optional[str] = None,
        data: Optional[str] = None,
        entry_id: Optional[str] = None,
):
    if filename and data:
        return filename, b64decode(data)
    elif entry_id:
        file_object = demisto.getFilePath(entry_id)

        with open(file_object['path'], 'rb') as f:
            file_contents = f.read()
        return file_object['name'], file_contents


def main():
    cwd = os.getcwd()
    content_tmp_dir = TemporaryDirectory()
    try:
        args = demisto.args()
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
                    'Name': validation.get('name'),
                    'Error': validation.get('message'),
                    'Line': validation.get('row'),
                })
        return_results(CommandResults(
            readable_output=tableToMarkdown('Validation Results', outputs, headers=['Name', 'Error', 'Line']),
            outputs_prefix='ValidationResult',
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
