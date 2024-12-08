import json
import os

os.environ['DEMISTO_SDK_MAX_CPU_CORES'] = "1"  # TODO - Consider not specifying and use as much as available

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io
import git
import zipfile
from contextlib import contextmanager
from base64 import b64decode
from pkg_resources import get_distribution
from pathlib import Path
from shutil import copy

from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from demisto_sdk.commands.common.logger import DEFAULT_CONSOLE_THRESHOLD, logging_setup

from demisto_sdk.commands.common.tools import find_type

from demisto_sdk.commands.split.ymlsplitter import YmlSplitter
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, TYPE_TO_EXTENSION, FileType
from ruamel.yaml import YAML
import shutil

CONTENT_DIR_PATH = '/tmp/content'
PACKS_DIR_NAME = 'Packs'
CONTENT_REPO_URL = 'https://github.com/demisto/content.git'
CACHED_MODULES_DIR = '/tmp/cached_modules'
PRE_COMMIT_TEMPLATE_PATH = os.path.join(CONTENT_DIR_PATH, '.pre-commit-config_template.yaml')
BRANCH_MASTER = 'master'
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
    'check-ast',
    'name-tests-test',
    'check-added-large-files',
    'check-case-conflict',
    'poetry-check',
    'autopep8'
]


def extract_file_and_line(output):
    file_line_pattern = re.compile(r"(.+):(\d+):(\d+)?")  # Example: file.py:123:45
    issues = []
    demisto.debug(f'Extract file{file_line_pattern}')
    for line in output.splitlines():
        match = file_line_pattern.search(line)
        if match:
            file_path = match.group(1)
            line_number = int(match.group(2))
            column_number = int(match.group(3)) if match.group(3) else None
            issues.append({
                "file": file_path,
                "line": line_number,
                "column": column_number,
                "details": line  # Store the full line for context
            })

    return issues


@dataclass
class ValidationResult:
    filePath: str
    fileType: str
    errorType: str
    message: str
    name: str
    linter: str
    severity: str
    entityType: str
    col: int
    row: int
    relatedField: str

    def to_json(self):
        return json.dumps(asdict(self), indent=2)

def get_skipped_hooks():
    global SKIPPED_HOOKS
    return SKIPPED_HOOKS


@contextmanager
def ConstantTemporaryDirectory(path):
    """ Creates a temporary directory with a constant name. """

    def cleanup():
        # Cleanup: Remove the directory if exists.
        if os.path.exists(path):
            shutil.rmtree(path)
            demisto.debug(f"Temporary directory {path} cleaned up.")

    try:
        cleanup()
        os.makedirs(path, exist_ok=True)
        yield path
    finally:
        pass


def log_demisto_sdk_version():
    try:
        demisto.debug(f'Using demisto-sdk version {get_distribution("demisto-sdk").version}')
    except Exception as e:
        demisto.debug(f'Could not get demisto-sdk version. Error: {e}')


def set_pre_commit_template_path(value):
    global pre_commit_template_path
    pre_commit_template_path = value


def get_pre_commit_template_path() -> Optional[str]:
    return pre_commit_template_path


def setup_proxy(_args: dict):
    if _args.get('use_system_proxy') == 'no':
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']


def get_pack_name(zip_fp: str) -> str:
    """ Returns the pack name from the zipped contribution file's metadata.json file. """
    with zipfile.ZipFile(zip_fp) as zipped_contrib:
        with zipped_contrib.open('metadata.json') as metadata_file:
            metadata = json.loads(metadata_file.read())
    return metadata.get('name', 'ServerSidePackValidationDefaultName')


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
    from demisto_sdk.commands.init.contribution_converter import AUTOMATION, INTEGRATION, SCRIPT, get_child_files

    child_files = get_child_files(content_item_dir)
    for child_file in child_files:
        cf_name_lower = os.path.basename(child_file).lower()
        if cf_name_lower.startswith((SCRIPT, AUTOMATION, INTEGRATION)) and cf_name_lower.endswith('yml'):
            content_item_file_path = child_file
            file_type = find_type(content_item_file_path)
            file_type = file_type.value if file_type else file_type
            try:
                extractor = find_type(path=content_item_file_path, file_type=file_type)
                extractor.extract_to_package_format()
                code_fp = get_extracted_code_filepath(extractor)
                code_fp_to_row_offset[code_fp] = extractor.lines_inserted_at_code_start
            except Exception as e:
                err_msg = f'Error occurred while trying to split the unified YAML "{content_item_file_path}" ' \
                          f'into its component parts.\nError: "{e}"'
                self.contrib_conversion_errs.append(err_msg)
            if del_unified:
                os.remove(content_item_file_path)


def convert_contribution_to_pack(contrib_converter: "ContributionConverter") -> Dict:
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
            with zipfile.ZipFile(contrib_converter.contribution) as zipped_contrib:
                with zipped_contrib.open('metadata.json') as metadata_file:
                    metadata = json.loads(metadata_file.read())
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
    code_fp_to_row_offset: Dict[str, int] = {}
    for pack_subdir in get_child_directories(contrib_converter.pack_dir_path):
        basename = os.path.basename(pack_subdir)
        if basename in {SCRIPTS_DIR, INTEGRATIONS_DIR}:
            contrib_converter.content_item_to_package_format = types.MethodType(
                content_item_to_package_format, contrib_converter
            )
            contrib_converter.content_item_to_package_format(
                pack_subdir, del_unified=True, source_mapping=None, code_fp_to_row_offset=code_fp_to_row_offset
            )
    return code_fp_to_row_offset


def prepare_content_pack_for_validation(filename: str, data: bytes, tmp_directory: str) -> Tuple[str, Dict]:
    from demisto_sdk.commands.init.contribution_converter import ContributionConverter

    # Write zip file data to file system.
    zip_path = os.path.abspath(os.path.join(tmp_directory, filename))
    with open(zip_path, 'wb') as fp:
        fp.write(data)

    pack_name = get_pack_name(zip_path)
    contrib_converter = ContributionConverter(name=pack_name, contribution=zip_path)
    code_fp_to_row_offset = convert_contribution_to_pack(contrib_converter)

    # Call the standalone function and get the raw response
    os.remove(zip_path)
    return contrib_converter.pack_dir_path, code_fp_to_row_offset


def prepare_single_content_item_for_validation(file_name: str, data: bytes, packs_path: str) -> Tuple[str, Dict]:
    from demisto_sdk.commands.init.contribution_converter import ContributionConverter

    pack_name = 'TmpPack'
    pack_dir = os.path.join(packs_path, pack_name)
    demisto.debug(f'Pack name: {pack_name}')
    # create pack_metadata.json file in TmpPack
    contrib_converter = ContributionConverter(
        name=pack_name, pack_dir_name=pack_name, contribution=pack_name
    )
    contrib_converter.create_metadata_file({'description': 'Temporary Pack', 'author': 'xsoar'})
    # Determine entity type by filename prefix.
    file_name_prefix = '-'.join(file_name.split('-')[:-1])
    containing_dir = os.path.join(pack_dir, ENTITY_TYPE_TO_DIR.get(file_name_prefix, 'Integrations'))
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
        return str(file_path), {}
    extractor = YmlSplitter(
        input=str(file_path), file_type=file_type, output=containing_dir,
        no_logging=True, no_pipenv=True, no_basic_fmt=True
    )
    # Validate the resulting package files, ergo set path_to_validate to the package directory that results
    # from extracting the unified yaml to a package format
    extractor.extract_to_package_format()
    code_fp_to_row_offset = {get_extracted_code_filepath(extractor): extractor.lines_inserted_at_code_start}

    output_path = extractor.get_output_path()
    demisto.debug(f'prepare_single_content_item_for_validation {output_path=} | {code_fp_to_row_offset=}')
    return output_path, code_fp_to_row_offset


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
    config_reader = ConfigReader(category="xsoar_best_practices_path_based_validations")
    initializer = Initializer(
        staged=False,
        committed_only=False,
        file_path=str(path_to_validate),
        execution_mode=ExecutionMode.SPECIFIC_FILES
    )
    validate_manager = ValidateManager(result_writer, config_reader, initializer, allow_autofix=False)
    demisto.debug(f'run_validate validate_manager initialized. Running validations: {validate_manager.validators=}')
    exit_code = validate_manager.run_validations()
    demisto.debug(f'run_validate {exit_code=}')
    return exit_code


def get_content_modules(content_path: str, verify_ssl: bool = True) -> None:
    """
    TODO - Update docstring.
    Copies the required content modules for linting from the cached dir. The cached dir is updated once a day

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
            'file': '.pre-commit-config.yaml',
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
            # Check if '.pre-commit-config_template.yaml' exists.
            if module['file'] == PRE_COMMIT_TEMPLATE_PATH:
                set_pre_commit_template_path(str(os.path.join(module_path, module["file"])))
                demisto.debug(f'PRE_COMMIT {get_pre_commit_template_path()=}')
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
    """ <DOCSTRING> """
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



def reformat_validation_outputs(outputs) -> list:
    """ Formats validation results output data. """
    reformatted = []
    for output in outputs[0].get('validations', []) if outputs and isinstance(outputs[0], dict) else []:
        if isinstance(output, dict):
            file_path = Path(output.get('file path'))
            reformatted.append({
                'filePath': str(file_path),
                'fileType': file_path.suffix.lstrip('.'),
                'Name': file_path.stem,
                'Error': output.get('message'),
                "errorCode": output.get('error code'),

            })
    return reformatted

    # if validation.get('ui') or validation.get('fileType') in {'py', 'ps1', 'yml'}:
    #     outputs.append({
    #         'Name': validation.get('name'),
    #         'Error': validation.get('message'),
    #         'Line': validation.get('row'),
    #     })
# {
# 	"filePath": "/tmp/tmp86pknsl2/Packs/TmpPack/Integrations/OpenAiChatGPTV3/OpenAiChatGPTV3.yml",
# 	"fileType": "yml",
# 	"entityType": "integration",
# 	"errorType": "Settings",
# 	"name": "OpenAI GPT",
# 	"linter": "validate",
# 	"severity": "error",
# 	"errorCode": "IN157",
# 	"message": "integration OpenAi ChatGPT v3 contains the nativeimage key in its yml, this key is added only during the upload flow, please remove it.",
# 	"relatedField": "script"
# }

# TODO - Remove

def parse_pre_commit_results(pre_commit_raw_outputs: list[dict]) -> tuple[list, list]:
    """Formats pre-commit results output data."""
    results = []
    errors = []
    demisto.debug("=== Parsing pre-commit results ===")

    line_counter = 1
    for hook_result in pre_commit_raw_outputs:
        returncode = hook_result.get("returncode", 0)
        file_name = hook_result.get("file_name", "")

        # Skip if no error or if it's the 'install-hooks' entry
        if returncode == 0 or file_name == 'install-hooks':
            continue

        parsed = extract_file_and_line(hook_result.get('stdout', ''))
        demisto.debug(f'Parsed hook {file_name} issues: {parsed=}')
        # Here you could integrate parsed data into your results if needed.

        reformatted_output = {
            'filePath': file_name,
            'linter': file_name,
            'return-code': returncode,
            'Error': hook_result.get("stdout", ""),
            'Line': line_counter,
        }

        errors.append(hook_result.get("stderr", ""))
        demisto.debug(json.dumps(hook_result, indent=4))
        results.append(reformatted_output)
        line_counter += 1

    demisto.debug("=== Finished parsing pre-commit results ===")
    return results, errors


# validation_results.append(ValidationResult(
#     # TODO - filePath=,
#     # TODO - fileType=,
#     errorType= 'Code' if fileType == 'py' else 'Settings',
#     message=,
#     name=,
#     linter=,
#     # severity: str
#     # entityType: str
#     col=,
#     row=,
#     # relatedField: str
#
#     )
# )

# {
# 	"filePath": "/tmp/tmp86pknsl2/Packs/TmpPack/Integrations/OpenAiChatGPTV3/OpenAiChatGPTV3.yml",
# 	"fileType": "yml",
# 	"entityType": "integration",
# 	"errorType": "Settings",
# 	"name": "OpenAI GPT",
# 	"linter": "validate",
# 	"severity": "error",
# 	"errorCode": "IN157",
# 	"message": "integration OpenAi ChatGPT v3 contains the nativeimage key in its yml, this key is added only during the upload flow, please remove it.",
# 	"relatedField": "script"
# }

def validate_content(path_to_validate: str) -> Tuple[list, list, list]:
    """
    Validate the content items in the given `path_to_validate`, using demisto-sdk's ValidateManager and PreCommitManager.

    Arguments:
        path_to_validate: Path to the file/directory to validate.

    Returns:
        TODO - Complete
    """

    output_base_dir = Path('ValidateContentOutput') / f'run-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
    os.makedirs(output_base_dir, exist_ok=True)

    validations_output_path = output_base_dir / 'validation_res.json'
    pre_commit_dir = output_base_dir / 'pre-commit-output/'
    os.makedirs(pre_commit_dir, exist_ok=True)

    validate_exit_code = run_validate(path_to_validate, str(validations_output_path))
    pre_commit_exit_code = run_pre_commit(pre_commit_dir)

    # If no errors were found
    if not (validate_exit_code or pre_commit_exit_code):
        return [], [], []

    if not validations_output_path.exists():
        raise DemistoException('Validation Results file does not exist.')

    # Read validate results.
    raw_outputs = read_json_results(validations_output_path)
    demisto.debug(f'Demisto-SDK Validate Results: {raw_outputs=}')
    reformatted_outputs = reformat_validation_outputs(raw_outputs)

    # Read pre-commit results.
    pre_commit_raw_outputs = []
    for output_file in pre_commit_dir.iterdir():
        read_json_results(output_file, pre_commit_raw_outputs)
    pre_commit_raw_outputs = [res for res in pre_commit_raw_outputs if res.get('returncode', 0) != 0]

    demisto.debug(f'Demisto-SDK Pre-Commit Results: {pre_commit_raw_outputs=}')
    pre_commit_results, errors = parse_pre_commit_results(pre_commit_raw_outputs)

    # raw_outputs.extend(pre_commit_raw_outputs)
    # all_res = []
    # for result in raw_outputs:
    #     if result.get('filePath') or validation.get('fileType') in {'py', 'ps1', 'yml'}:
    #         outputs.append({
    #             'Name': validation.get('name'),
    #             'Error': validation.get('message'),
    #             'Line': validation.get('row'),
    #         })

    # return reformatted_outputs, [], raw_outputs
    return reformatted_outputs, pre_commit_results, raw_outputs


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


#
def get_file_name_and_contents(
    filename: Optional[str] = None,
    data: Optional[str] = None,
    entry_id: Optional[str] = None,
):
    if filename and data:
        return filename, b64decode(data)
    elif entry_id:
        file_object = demisto.getFilePath(entry_id)
        demisto.debug(f'{file_object=}')
        with open(file_object['path'], 'rb') as f:
            file_contents = f.read()
        return file_object['name'], file_contents


def setup_content_dir(file_name: str, file_contents: str, entry_id: str, verify_ssl=False) -> Tuple[str, str]:
    """ Sets up the content directory to validate the content items in it. """

    # Set up the content directory path globally, required for demisto-sdk logic.
    os.environ['DEMISTO_SDK_CONTENT_PATH'] = CONTENT_DIR_PATH

    packs_path = os.path.join(CONTENT_DIR_PATH, PACKS_DIR_NAME)
    os.mkdir(packs_path)
    demisto.debug(f"created packs directory in {packs_path}")

    content_repo = setup_content_repo(CONTENT_DIR_PATH)
    file_name, file_contents = get_file_name_and_contents(file_name, file_contents, entry_id)

    if file_name.endswith('.zip'):
        path_to_validate, code_fp_to_row_offset = prepare_content_pack_for_validation(
            file_name, file_contents, CONTENT_DIR_PATH
        )
    else:
        path_to_validate, code_fp_to_row_offset = prepare_single_content_item_for_validation(
            file_name, file_contents, packs_path
        )
    demisto.debug(f'setup_content_dir {path_to_validate=}')

    content_repo.index.add(os.path.join(packs_path))

    if os.path.isdir(path_to_validate):
        demisto.debug(f'setup_content_dir {os.listdir(path_to_validate)=}')

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
    cwd = os.getcwd()
    demisto.debug(f'{cwd=}')

    try:
        args = demisto.args()
        demisto.debug(f'Got {args=}')

        setup_proxy(args)
        verify_ssl = argToBoolean(args.get('trust_any_certificate'))

        filename: str = args.get('filename', '')
        data: bytes | str = args.get('data', bytes())
        entry_id: str = args.get('entry_id', '')
        with ConstantTemporaryDirectory(CONTENT_DIR_PATH) as tmp_dir:
            demisto.debug(f"created {tmp_dir=}")
            # Setup Demisto SDK's logging.
            logging_setup(
                calling_function='ValidateContent',
                console_threshold='DEBUG' if is_debug_mode() else DEFAULT_CONSOLE_THRESHOLD,
                propagate=True
            )
            demisto.debug(f"Finished setting logger.")

            path_to_validate = setup_content_dir(filename, data, entry_id, verify_ssl)
            os.chdir(CONTENT_DIR_PATH)
            # todo - unify validate and pre_commit results
            validate_results, pre_commit_results, raw_outputs = validate_content(path_to_validate)
            os.chdir(cwd)
            demisto.debug(f'{json.dumps(validate_results, indent=4)} | \n\n {json.dumps(pre_commit_results, indent=4)}')
            if not validate_results and not pre_commit_results:
                return_results(CommandResults(readable_output='All validations passed.'))

            return_results(CommandResults(
                readable_output=tableToMarkdown(
                    'Validation Results', validate_results
                    # 'Validation Results', validate_results, headers=['Error Code', 'Error', 'File']
                ) + tableToMarkdown('', pre_commit_results),
                outputs_prefix='ValidationResult',
                outputs=validate_results.extend(pre_commit_results),
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
