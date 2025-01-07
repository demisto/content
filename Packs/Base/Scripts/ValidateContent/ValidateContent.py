import shutil
import traceback
import types
from datetime import datetime, timedelta

import requests
from ruamel.yaml import YAML
from concurrent.futures import ThreadPoolExecutor, as_completed
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, FileType
from demisto_sdk.commands.split.ymlsplitter import YmlSplitter
from demisto_sdk.commands.common.tools import find_type
from demisto_sdk.commands.common.logger import DEFAULT_CONSOLE_THRESHOLD, logging_setup
from dataclasses import dataclass, asdict
from shutil import copy
from pathlib import Path
from pkg_resources import get_distribution
from base64 import b64decode
from contextlib import contextmanager, redirect_stderr
import zipfile
import git
import io
import os
import re
import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


DEFAULT_CONFIG_CATEGORY = "xsoar_best_practices_path_based_validations"
CONTENT_DIR_PATH = '/tmp/content'
PACKS_DIR_NAME = 'Packs'
CONTENT_REPO_URL = 'https://github.com/demisto/content.git'
CACHED_MODULES_DIR = '/tmp/cached_modules'
PRE_COMMIT_TEMPLATE_PATH = os.path.join(CONTENT_DIR_PATH, '.pre-commit-config_template.yaml')
BRANCH_MASTER = 'master'
DEFAULT_ERROR_PATTERN = {
    'regex': re.compile(r'(\/[\w\/\.-]+):(\d+):(\d+): .* : (.*)'),
    'groups': ['file', 'line', 'column', 'details']
}

HOOK_ID_TO_PATTERN = {
    'xsoar-lint': DEFAULT_ERROR_PATTERN,
    'debug-statements': {
        'regex': re.compile(r'File\s+"(.+)",\s+line\s+(\d+)(?:.*?\n.*?\^+\n)\s+([^\n]+)'),
        'groups': ['file', 'line', 'details']
    },
    'check-ast': {
        'regex': re.compile(r'File\s"(Packs/.*?)",\sline\s(\d+)'),
        'groups': ['file', 'line']
    },
    'mypy': {
        'regex': re.compile(r'(.*?\.py):(\d+): error: ([\s\S]*?)(?=\nPacks\/|\nFound \d+ error)'),
        'groups': ['file', 'line', 'details']
    },
}
FILE_TYPE_TO_ERROR_TYPE = {'py': 'Code', 'ps1': 'Code', 'yml': 'Settings', 'json': 'Settings', 'md': 'Settings'}
ALLOWED_FILE_TYPES = ['py', 'yml', 'yaml', 'json', 'ps1', 'zip']
SKIPPED_HOOKS = [
    'validate-deleted-files',
    'pwsh-test-in-docker',
    'pwsh-analyze-in-docker',
    'coverage-pytest-analyze',
    'merge-pytest-reports',
    'format',
    'validate',
    'validate-content-paths',
    'validate-conf-json',
    'check-merge-conflict',
    'name-tests-test',
    'check-added-large-files',
    'check-case-conflict',
    'poetry-check',
    'autopep8',
    'pycln',
    'ruff',
    'xsoar-lint',
    'check-yaml',
    'check-json',
]


class FormattedResultFields:
    NAME = 'Name'
    ERROR = 'Error'
    LINE = 'Line'
    ERROR_CODE_OR_LINTER = 'Error Code/Linter'


@dataclass
class ValidationResult:
    filePath: str = ''
    fileType: str = ''
    errorCode: str = ''
    errorType: str = ''
    message: str = ''
    name: str = ''
    linter: str = ''
    severity: str = 'error'
    entityType: str = ''
    col: int = 0
    row: int = 0
    relatedField: str = ''
    ui: bool = True

    def to_dict(self):
        return asdict(self)


@contextmanager
def ConstantTemporaryDirectory(path):
    """ Creates a temporary directory with a constant name. """

    def cleanup():
        # Cleanup: Remove the directory if exists.
        if os.path.exists(path):
            shutil.rmtree(path)
            demisto.debug(f"Temporary directory {path} cleaned up.")

    cleanup()
    os.makedirs(path, exist_ok=True)
    yield path


def log_demisto_sdk_version():
    try:
        demisto.debug(f'Using demisto-sdk version {get_distribution("demisto-sdk").version}')
    except Exception as e:
        demisto.debug(f'Could not get demisto-sdk version. Error: {e}')


def setup_proxy(_args: dict):
    if _args.get('use_system_proxy') == 'no':
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']


def strip_ansi_codes(text):
    ansi_escape = re.compile(r'''
        \x1B  # ESC
        \[    # [
        [0-?]* # Parameter bytes
        [ -/]* # Intermediate bytes
        [@-~]  # Final byte
    ''', re.VERBOSE)
    return ansi_escape.sub('', text)


def extract_hook_id(output: str) -> str:
    """
    Extracts the hook id from a pre-commit hook's output.

    Args:
        output (str): The raw output string.

    Returns:
        str: The extracted hook id or None if not found.
    """
    pattern = r"- hook id:\s+([\w-]+)"
    match = re.search(pattern, output)
    return match.group(1) if match else ''


def parse_pre_commit_output(output: str, pattern_obj: dict) -> list[dict]:
    """
    Extracts information from pre-commit hook's output lines based on a given pattern.

    Args:
        output (str): Hook's output string to be processed.
        pattern_obj (str): The regular expression pattern object, including match groups to match against each line.

    Returns:
        dict: Extracted information for a single matching line.
    """
    results = []
    demisto.debug(f'parse_pre_commit_output got {pattern_obj}')
    regex = pattern_obj['regex']
    group_names = pattern_obj['groups']

    for match in re.finditer(regex, output):
        match_data = match.groups()
        # Build the result dictionary based on the group names
        result = {}
        result.update({name: match_data[i] for i, name in enumerate(group_names) if i < len(match_data)})
        if result not in results:
            results.append(result)

    return results


def get_skipped_hooks():
    return SKIPPED_HOOKS


def resolve_entity_type(file_path: str):
    """ Resolve entity type from file path. """
    parts = file_path.split("/")
    if parts[0] == "Packs" and len(parts) > 2 and (entity_type_directory_name := parts[2].lower()):
        entity_type = entity_type_directory_name[:-1] if entity_type_directory_name.endswith('s') else entity_type_directory_name
        return entity_type
    entity_type = "contentpack"
    return entity_type


def get_pack_name(zip_filepath: str) -> str:
    """ Returns the pack name from the zipped contribution file's metadata.json file. """
    with zipfile.ZipFile(zip_filepath) as zipped_contrib, zipped_contrib.open('metadata.json') as metadata_file:
        metadata = json.loads(metadata_file.read())
    if pack_name := metadata.get('name'):
        return pack_name
    demisto.error('Could not find pack name in metadata.json')
    return 'TmpPack'


def _create_pack_base_files(self):
    """
    Creates empty 'README.md', '.secrets-ignore', and '.pack-ignore' files that are expected
    to be in the base directory of a pack
    """
    fp = open(os.path.join(self.pack_dir_path, 'README.md'), 'a')
    fp.close()

    fp = open(os.path.join(self.pack_dir_path, '.secrets-ignore'), 'a')
    fp.close()

    fp = open(os.path.join(self.pack_dir_path, '.pack-ignore'), 'a')
    fp.close()


def content_item_to_package_format(
        self, content_item_dir: str, del_unified: bool = True, source_mapping: dict | None = None,  # noqa: F841
) -> None:
    from demisto_sdk.commands.init.contribution_converter import AUTOMATION, INTEGRATION, SCRIPT, get_child_files

    child_files = get_child_files(content_item_dir)
    for child_file in child_files:
        cf_name_lower = os.path.basename(child_file).lower()
        if cf_name_lower.startswith((SCRIPT, AUTOMATION, INTEGRATION)) and cf_name_lower.endswith('yml'):
            content_item_file_path = child_file
            file_type = find_type(content_item_file_path)
            file_type = file_type.value if file_type else file_type
            try:
                extractor = YmlSplitter(
                    input=content_item_file_path,
                    output=content_item_dir,
                    file_type=file_type,
                )
                extractor.extract_to_package_format()
            except Exception as e:
                err_msg = f'Error occurred while trying to split the unified YAML "{content_item_file_path}" ' \
                          f'into its component parts.\nError: "{e}"'
                self.contrib_conversion_errs.append(err_msg)
            if del_unified:
                os.remove(content_item_file_path)


def convert_contribution_to_pack(contrib_converter):
    """
        Creates or updates a pack in the Content repo from the contents of a contributed zip file.
    Args:
        contrib_converter (ContributionConverter): Contribution contributor object
    """
    from demisto_sdk.commands.init.contribution_converter import INTEGRATIONS_DIR, SCRIPTS_DIR, get_child_directories

    # Only create pack_metadata.json and base pack files if creating a new pack.
    if contrib_converter.create_new:
        if contrib_converter.contribution:
            # Create pack metadata file.
            with (zipfile.ZipFile(contrib_converter.contribution) as zipped_contrib,
                  zipped_contrib.open('metadata.json') as metadata_file):
                metadata = json.loads(metadata_file.read())
                demisto.debug(f'convert_contribution_to_pack {metadata=}')
                contrib_converter.create_metadata_file(metadata)

        # Create base files.
        contrib_converter.create_pack_base_files = types.MethodType(_create_pack_base_files, contrib_converter)
        contrib_converter.create_pack_base_files()

    # Unpack.
    contrib_converter.unpack_contribution_to_dst_pack_directory()

    # Convert.
    unpacked_contribution_dirs = get_child_directories(contrib_converter.pack_dir_path)
    for unpacked_contribution_dir in unpacked_contribution_dirs:
        contrib_converter.convert_contribution_dir_to_pack_contents(unpacked_contribution_dir)

    # Extract to package format.
    for pack_subdir in get_child_directories(contrib_converter.pack_dir_path):
        basename = os.path.basename(pack_subdir)
        if basename in {SCRIPTS_DIR, INTEGRATIONS_DIR}:
            contrib_converter.content_item_to_package_format = types.MethodType(
                content_item_to_package_format, contrib_converter
            )

            contrib_converter.content_item_to_package_format(
                pack_subdir, del_unified=False, source_mapping=None,
            )


def prepare_content_pack_for_validation(filename: str, data: bytes, content_dir_path: str) -> str:
    from demisto_sdk.commands.init.contribution_converter import ContributionConverter

    # Write zip file data to file system.
    zip_path = os.path.abspath(os.path.join(content_dir_path, filename))
    with open(zip_path, 'wb') as fp:
        fp.write(data)

    pack_name = get_pack_name(zip_path)
    contrib_converter = ContributionConverter(name=pack_name, contribution=zip_path, base_dir=content_dir_path)
    convert_contribution_to_pack(contrib_converter)

    os.remove(zip_path)
    return contrib_converter.pack_dir_path


def prepare_single_content_item_for_validation(file_name: str, data: bytes, packs_path: str) -> str:
    from demisto_sdk.commands.init.contribution_converter import ContributionConverter

    pack_name = 'TmpPack'
    pack_path = os.path.join(packs_path, pack_name)
    demisto.debug(f'Pack name: {pack_name}')
    # create pack_metadata.json file in TmpPack
    contrib_converter = ContributionConverter(
        name=pack_name, pack_dir_name=pack_name, contribution=pack_name
    )
    contrib_converter.create_metadata_file({'description': 'Temporary Pack', 'author': 'xsoar'})
    # Determine entity type by filename prefix.
    file_name_prefix = '-'.join(file_name.split('-')[:-1])
    containing_dir = os.path.join(pack_path, ENTITY_TYPE_TO_DIR.get(file_name_prefix, 'Integrations'))
    os.makedirs(containing_dir, exist_ok=True)

    is_json = file_name.casefold().endswith('.json')
    data_as_string = data.decode()
    yaml = YAML()
    loaded_data = json.loads(data_as_string) if is_json else yaml.load(data_as_string)
    if is_json:
        data_as_string = json.dumps(loaded_data)
    else:
        buff = io.StringIO()
        yaml.dump(loaded_data, buff)
        data_as_string = buff.getvalue()

    # Write content item file to file system.
    file_path = Path(os.path.join(containing_dir, file_name))
    file_path.write_text(data_as_string)
    file_type = find_type(str(file_path))
    file_type = file_type.value if file_type else file_type
    if is_json or file_type in (FileType.PLAYBOOK.value, FileType.TEST_PLAYBOOK.value):
        return str(file_path)
    extractor = YmlSplitter(
        input=str(file_path), file_type=file_type, output=containing_dir
    )
    # Validate the resulting package files, ergo set path_to_validate to the package directory that results
    # from extracting the unified yaml to a package format
    extractor.extract_to_package_format()

    output_path = extractor.get_output_path()
    demisto.debug(f'prepare_single_content_item_for_validation {output_path=}')
    return output_path


def run_validate(path_to_validate: str, json_output_file: str) -> int:
    """
    Runs demisto-sdk validations on a specified file path and writes the results to a JSON file.
    Args:
        path_to_validate (str): The path of the file or directory to be validated.
        json_output_file (str): The file path where validation results will be written in JSON format.

    Returns:
        int: An exit code indicating the validation status; 0 for success and non-zero for failures.

    """
    from demisto_sdk.commands.validate.config_reader import ConfigReader
    from demisto_sdk.commands.validate.initializer import Initializer
    from demisto_sdk.commands.validate.validation_results import ResultWriter
    from demisto_sdk.commands.validate.validate_manager import ValidateManager
    from demisto_sdk.commands.common.constants import ExecutionMode

    result_writer = ResultWriter(json_output_file)
    config_reader = ConfigReader(category=DEFAULT_CONFIG_CATEGORY)
    initializer = Initializer(
        staged=False,
        committed_only=False,
        file_path=str(path_to_validate),
        execution_mode=ExecutionMode.SPECIFIC_FILES
    )
    validate_manager = ValidateManager(result_writer, config_reader, initializer, allow_autofix=False)
    demisto.debug(f'run_validate validate_manager initialized. Running validations: {validate_manager.validators=}')
    err_file = io.StringIO()
    with redirect_stderr(err_file):
        exit_code: int = validate_manager.run_validations()
    demisto.debug(f'run_validate {exit_code=}')
    return exit_code


def get_content_modules(content_path: str, verify_ssl: bool = True) -> None:
    """
    Copies the required content modules for validation and pre-commit from the cached dir. The cached dir is updated once a day

    Args:
        content_path (str): Path to Content directory
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
                          'Config/approved_usecases.json',
            'content_path': 'Config',
        },
        {
            'file': 'approved_tags.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Config/approved_tags.json',
            'content_path': 'Config',
        },
        {
            'file': 'approved_categories.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Config/approved_categories.json',
            'content_path': 'Config',
        },
        {
            'file': '.pre-commit-config_template.yaml',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/.pre-commit-config_template.yaml',
            'content_path': '',
        },
        {
            'file': '.pre-commit-config_template.yaml',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/.pre-commit-config_template.yaml',
            'content_path': '',
        }

    ]
    for module in modules:
        demisto.debug(f'get_content_modules getting {module["file"]=}')
        module_path = os.path.join(content_path, module['content_path'])
        os.makedirs(Path(module_path), exist_ok=True)
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
            demisto.debug(f'Copying from {cached_module_path} to {module_path}')
            copy(cached_module_path, module_path)
        except Exception as e:
            fallback_path = f'/home/demisto/{module["file"]}'
            demisto.debug(f'Failed downloading content module {module["github_url"]} - {e}. '
                          f'Copying from {fallback_path}')
            copy(fallback_path, module_path)


def run_pre_commit(output_path: Path) -> int:
    """
    Runs demisto-sdk pre-commit.
    Args:
        output_path (str): The file path where validation results will be written in JSON format.

    Returns:
        int: An exit code indicating the validation status; 0 for success and non-zero for failures.

    """
    from demisto_sdk.commands.pre_commit.pre_commit_command import pre_commit_manager
    os.environ['DEMISTO_SDK_DISABLE_MULTIPROCESSING'] = 'true'
    demisto.debug(f'run_pre_commit | {get_skipped_hooks()=} | {PRE_COMMIT_TEMPLATE_PATH=} | {output_path=}')
    exit_code = pre_commit_manager(
        skip_hooks=get_skipped_hooks(),
        all_files=True,
        run_docker_hooks=False,
        pre_commit_template_path=Path(PRE_COMMIT_TEMPLATE_PATH),
        json_output_path=output_path
    )
    demisto.debug(f'run_pre_commit {exit_code=}')
    return exit_code


def read_json_results(json_path: Path, results: list = None) -> list:
    """
    Process JSON results file and append items to results list.

    Args:
        json_path: JSON file path
        results: Existing results list

    Returns:
        Updated results with 'file_name' added to each result
    """
    if results is None:
        results = []

    content = json.loads(json_path.read_text())
    if not content:
        return results

    file_name = json_path.stem
    if isinstance(content, list):
        for item in content:
            item['file_name'] = file_name
        results.extend(content)
    else:
        content['file_name'] = file_name
        results.append(content)

    return results


def read_validate_results(json_path: Path):
    if not json_path.exists():
        raise DemistoException('Validation Results file does not exist.')
    raw_outputs = read_json_results(json_path)
    demisto.debug(f'read_validate_results: {raw_outputs=}')

    results = []
    for output in raw_outputs:
        for validation in output.get('validations', []):
            file_path = validation.get('file path', '')
            file_type = 'yml' if file_path.endswith(('.yml', '.yaml')) else ''
            error_code = validation.get('error code', '')
            message = validation.get('message', '')
            results.append(
                ValidationResult(
                    filePath=str(Path(file_path).absolute()) if file_path else '',
                    name=Path(file_path).stem,
                    fileType=file_type,
                    errorCode=error_code,
                    errorType='Code' if file_type in {'py', 'ps1'} else 'Settings',
                    entityType=resolve_entity_type(file_path),
                    message=message,
                    linter='validate',
                )
            )

    return results


def read_pre_commit_results(pre_commit_dir: Path):
    results = []
    for output_file in pre_commit_dir.iterdir():
        raw_outputs = read_json_results(output_file)

        for output in raw_outputs:
            stdout: str = strip_ansi_codes(output.get('stdout', ''))
            demisto.debug(f'stripped-output: {stdout}')

            hook_id: str = extract_hook_id(stdout) or output.get('file_name', '')
            pattern_obj: dict = HOOK_ID_TO_PATTERN.get(hook_id, DEFAULT_ERROR_PATTERN)
            parsed_results: list[dict] = parse_pre_commit_output(
                stdout, pattern_obj
            )

            demisto.debug(f'extracted_data={json.dumps(parsed_results, indent=4)}')
            for result in parsed_results:
                file_path = result.get('file', '')
                # Isolating file's extension.
                file_type = '' if not file_path else os.path.splitext(f'{file_path}')[1].lstrip('.')
                error_type = FILE_TYPE_TO_ERROR_TYPE.get(file_type, '')
                # 'check-ast' details value has to be treated individually as regex does not capture it properly.
                if hook_id == 'check-ast':
                    result['details'] = stdout.splitlines()[5:]  # Trimming error metadata info (5 lines of it).
                details = result['details'] if 'details' in result else ''
                results.append(
                    ValidationResult(
                        filePath=file_path,
                        fileType=file_type,
                        name=Path(file_path).stem,
                        entityType=resolve_entity_type(file_path),
                        errorType=error_type,
                        message=details,
                        linter=hook_id,
                        col=result.get('column', 0),
                        row=int(result.get('line', 0)) - 1,  # Normalizing as UI adds a module registration line at row=1.
                    )
                )

    return results


def validate_content(path_to_validate: str) -> tuple[list, list]:
    """
    Validate the content items in the given `path_to_validate`, using demisto-sdk's ValidateManager and PreCommitManager.

    Arguments:
        path_to_validate: Path to the file/directory to validate.

    Returns:
        Tuple[list, list]: Formatted validation results, and raw validation results.
    """
    demisto.info(f'Starting to validate content at {path_to_validate}.')

    output_base_dir = Path('ValidateContentOutput') / f'run-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
    os.makedirs(output_base_dir, exist_ok=True)

    validations_output_path = output_base_dir / 'validation_res.json'
    pre_commit_dir = output_base_dir / 'pre-commit-output/'
    os.makedirs(pre_commit_dir, exist_ok=True)

    # One thread for `validate` execution & one for `pre_commit`.
    with ThreadPoolExecutor(max_workers=2) as executor:
        validate_future = executor.submit(run_validate, path_to_validate, str(validations_output_path))
        demisto.info('Submitting `run_validate` future.')
        pre_commit_future = executor.submit(run_pre_commit, pre_commit_dir)
        demisto.info('Submitting `pre_commit` future.')

        for future in as_completed([validate_future, pre_commit_future]):
            if future == validate_future:
                validate_exit_code = future.result(timeout=60)  # One minute timeout.
                demisto.info(f'Finished running `demisto-sdk validate` with exit code {validate_exit_code}.')
            else:
                pre_commit_exit_code = future.result(timeout=60)  # One minute timeout.
                demisto.info(f'Finished running `demisto-sdk pre-commit` with exit code {pre_commit_exit_code}.')

    # If no errors were found.
    if not (validate_exit_code or pre_commit_exit_code):
        return [], []

    raw_validation_results: list[ValidationResult] = []
    raw_validation_results += read_validate_results(validations_output_path)
    raw_validation_results += read_pre_commit_results(pre_commit_dir)

    demisto.debug(f'{json.dumps([output.to_dict() for output in raw_validation_results], indent=4)}')

    formatted_results = []
    for result in raw_validation_results:
        formatted_results.append({
            FormattedResultFields.NAME: result.name,
            FormattedResultFields.ERROR: result.message,
            FormattedResultFields.LINE: result.row if int(result.row) > 0 else None,
            FormattedResultFields.ERROR_CODE_OR_LINTER: result.errorCode or result.linter
        })

    return formatted_results, [output.to_dict() for output in raw_validation_results]


def setup_content_repo(content_path: str):
    """ Set up local Content git repository to run demisto-sdk commands against. """
    content_repo = git.Repo.init(content_path)
    demisto.debug(f'main created content_repo {os.listdir(content_path)=}')

    # Check if the repository has any commits, make an initial commit if needed.
    if not content_repo.head.is_valid():
        # Make an empty initial commit to create the master branch.
        content_repo.index.commit("Initial commit")

    # Set up the remote branch and fetch it.
    content_repo.create_remote('origin', CONTENT_REPO_URL)
    content_repo.remotes.origin.fetch('master', depth=1)

    # Ensure 'master' branch exists, and checkout.
    if BRANCH_MASTER not in content_repo.heads:
        content_repo.create_head(BRANCH_MASTER)
    content_repo.heads.master.checkout()
    return content_repo


def get_file_name_and_contents(
    filename: str | None = None,
    data: str | None = None,
    entry_id: str | None = None,
):
    if filename and data:
        return filename, b64decode(data)
    elif entry_id:
        file_object = demisto.getFilePath(entry_id)
        demisto.debug(f'{file_object=}')
        with open(file_object['path'], 'rb') as f:
            file_contents = f.read()
        return file_object['name'], file_contents
    return None


def setup_content_dir(file_name: str, file_contents: bytes | str, entry_id: str, verify_ssl=False) -> str:
    """ Sets up the content directory to validate the content items in it. """

    # Set up the content directory path globally, required for demisto-sdk logic.
    os.environ['DEMISTO_SDK_CONTENT_PATH'] = CONTENT_DIR_PATH

    packs_path = os.path.join(CONTENT_DIR_PATH, PACKS_DIR_NAME)
    Path.mkdir(Path(packs_path))
    demisto.debug(f"created packs directory in {packs_path}")

    content_repo = setup_content_repo(CONTENT_DIR_PATH)
    file_name, file_contents = get_file_name_and_contents(file_name, str(file_contents), entry_id)
    file_type = file_name.split('.')[-1]
    if file_type not in ALLOWED_FILE_TYPES:
        demisto.debug(f'resolved {file_type=}')
        raise DemistoException(f'{file_name} does not define a content item. Files defining content items can be of '
                               f'types: {ALLOWED_FILE_TYPES}')

    if isinstance(file_contents, str):
        size_in_bytes = len(file_contents.encode("utf-8"))
    else:  # Assuming it's already bytes
        size_in_bytes = len(file_contents)

    demisto.debug(
        f'setup_content_dir preparing content_items for validateion: '
        f'{file_name=}\n|'
        f' file_content size in bytes={size_in_bytes} \n|'
        f' {packs_path if packs_path else CONTENT_DIR_PATH}'
    )
    if file_name.endswith('.zip'):
        path_to_validate = prepare_content_pack_for_validation(
            file_name, file_contents, CONTENT_DIR_PATH
        )
    else:
        path_to_validate = prepare_single_content_item_for_validation(
            file_name, file_contents, packs_path
        )
    demisto.debug(f'setup_content_dir {path_to_validate=}')
    # "git add packs_path"
    content_repo.index.add(os.path.join(packs_path))

    os.makedirs(CACHED_MODULES_DIR, exist_ok=True)
    get_content_modules(CONTENT_DIR_PATH, verify_ssl=verify_ssl)
    return path_to_validate


def setup_envvars():
    os.environ['DEMISTO_SDK_IGNORE_CONTENT_WARNING'] = "false"
    os.environ['DEMISTO_SDK_OFFLINE_ENV'] = 'False'
    os.environ['ARTIFACTS_FOLDER'] = '/tmp/artifacts'
    os.environ['DEMISTO_SDK_LOG_NO_COLORS'] = 'true'
    demisto.debug(f'setup_envvars: {os.environ}')


def main():
    setup_envvars()
    # Save working directory for later return, as working directory changes during runtime.
    cwd = os.getcwd()
    demisto.debug(f'{cwd=}')

    try:
        args = demisto.args()
        demisto.debug(f'Got {args=}')

        setup_proxy(args)
        verify_ssl = argToBoolean(args.get('trust_any_certificate'))

        # Whether `filename` & `data` will be provided, or an `entry_id`.
        filename: str = args.get('filename', '')
        data: bytes | str = args.get('data', b'')
        entry_id: str = args.get('entry_id', '')

        with ConstantTemporaryDirectory(CONTENT_DIR_PATH) as tmp_dir:
            demisto.info('Setting up content validation environment.')
            demisto.debug(f"created {tmp_dir=}")

            # Setup Demisto SDK's logging.
            logging_setup(
                calling_function='ValidateContent',
                console_threshold='DEBUG' if is_debug_mode() else DEFAULT_CONSOLE_THRESHOLD,
                propagate=True
            )
            demisto.debug("Finished setting logger.")

            path_to_validate: str = setup_content_dir(filename, data, entry_id, verify_ssl)
            demisto.debug("Finished setting content dir.")

            # Got to be in content dir when running demisto-sdk commands.
            os.chdir(CONTENT_DIR_PATH)
            validation_results, raw_outputs = validate_content(path_to_validate)
            os.chdir(cwd)

            if not raw_outputs:
                readable_output = 'All validations passed.'
            else:
                readable_output = tableToMarkdown(
                    name='Validation Results',
                    t=validation_results,
                    headers=[
                        FormattedResultFields.NAME,
                        FormattedResultFields.ERROR,
                        FormattedResultFields.LINE,
                        FormattedResultFields.ERROR_CODE_OR_LINTER
                    ]
                )
            return_results(CommandResults(
                readable_output=readable_output,
                outputs_prefix='ValidationResult',
                outputs=validation_results,
                raw_response=raw_outputs,
            ))

        demisto.info('Finished validating content.')
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute ValidateContent. Error: {str(e)}')
    finally:
        os.chdir(cwd)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    log_demisto_sdk_version()
    main()
