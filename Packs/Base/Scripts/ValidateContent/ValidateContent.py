import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io
import git
import zipfile
import sys
from contextlib import contextmanager
from base64 import b64decode
from pkg_resources import get_distribution
from pathlib import Path
from shutil import copy

from typing import Dict, Optional, Tuple
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
PRE_COMMIT_TEMPLATE_PATH = '.pre-commit-config_template.yaml'
BRANCH_MASTER = 'master'

pre_commit_template_path = None

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
        cleanup()


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
    """Copies the required content modules for linting from the cached dir
    The cached dir is updated once a day

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
        except Exception as e:
            fallback_path = f'/home/demisto/{module["file"]}'
            demisto.debug(f'Failed downloading content module {module["github_url"]} - {e}. '
                          f'Copying from {fallback_path}')
            copy(fallback_path, module_path)




def run_pre_commit(path_to_validate: str, output_path: str, content_path: str) -> int:
    """
    <DOCSTRING>
    """
    # from demisto_sdk.commands.pre_commit.pre_commit_command import pre_commit_manager
    if not (_pre_commit_template_path := get_pre_commit_template_path()):
        demisto.debug(f'run_pre_commit `pre-commit-template-path` does not exist')

    import argparse
    from pre_commit.commands.run import run
    from pre_commit.store import Store

    # exit_code = pre_commit_manager(
    #     skip_hooks=['validate-deleted-files'],
    #     # TODO - Verify if it can be both a folder and files.
    #     input_files=[Path(path_to_validate)],
    #     run_docker_hooks=False,
    #     pre_commit_template_path=Path(get_pre_commit_template_path()),
    #     output_path=Path(output_path)
    # )

    import subprocess
    # subprocess.run(["pre-commit", "install"], check=True)
    import shutil

    # Path to your pre-commit configuration template
    template_config_path = get_pre_commit_template_path()
    repo_config_path = ".pre-commit-config.yaml"

    # Step 1: Copy the template configuration to the repository root
    shutil.copy(template_config_path, repo_config_path)

    # Step 2: Install pre-commit in the current repository
    subprocess.run(["pre-commit", "install"], check=True)

    # Step 3: Run all pre-commit hooks programmatically
    result = subprocess.run(["pre-commit", "run", "--all-files"], capture_output=True, text=True)

    # Print the output
    demisto.debug(result.stdout)

    if result.returncode != 0:
        demisto.debug(result.stderr)

    exit_code = result.returncode
    demisto.debug(f'run_pre_commit {exit_code=}')
    return exit_code


def reformat_validation_outputs(outputs):
    """Formats validation results output data."""
    reformatted = []
    for output in outputs[0].get('validations', []) if outputs and isinstance(outputs[0], dict) else []:
        if isinstance(output, dict):
            reformatted.append({
                'Error Code': output.get('error code'),
                'Error': output.get('message'),
                'File': output.get('file path')
            })
    return reformatted


def validate_content(path_to_validate: str):
    """
    Validate the content items in the given `path_to_validate`, using demisto-sdk's ValidateManager and PreCommitManager.

    Arguments:
        path_to_validate: Path to the file/directory to validate.

    Returns:
        CommandResults objects with validation's & pre-commit's results.

    """

    pre_commit_output_path = 'pre-commit-output/'
    validations_output_path = 'validation_res.json'

    os.environ['DEMISTO_SDK_LOG_NO_COLORS'] = 'true'
    os.environ['LOGURU_DIAGNOSE'] = 'true'

    validate_exit_code = run_validate(path_to_validate, validations_output_path)
    pre_commit_exit_code = 0
    # pre_commit_exit_code = run_pre_commit(path_to_validate, pre_commit_output_path)

    if not (validate_exit_code or pre_commit_exit_code):
        return CommandResults(readable_output='All validations passed.')

    if not Path(validations_output_path).exists():
        raise DemistoException('Validation Results file does not exist.')

    all_outputs = []
    demisto.debug(f'about to read results -> {os.listdir(os.getcwd())}')
    with open(validations_output_path, 'r') as json_outputs:
        raw_outputs = json.load(json_outputs)
        if raw_outputs:
            if type(raw_outputs) is list:
                all_outputs.extend(raw_outputs)
            else:
                all_outputs.append(raw_outputs)

    # TODO - Read pre-commit results.

    # TODO - Remove
    demisto.debug(f'Validation Results: {all_outputs=}')
    reformatted_outputs = reformat_validation_outputs(all_outputs)

    # TODO - Remove
    demisto.debug(f'Validation Results: {reformatted_outputs=}')
    return reformatted_outputs, raw_outputs


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
    content_repo.remotes.origin.fetch()

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

    content_path = CONTENT_DIR_PATH
    # Set up the content directory path globally, required for demisto-sdk logic.
    os.environ['DEMISTO_SDK_CONTENT_PATH'] = content_path

    packs_path = os.path.join(content_path, PACKS_DIR_NAME)
    os.mkdir(packs_path)
    demisto.debug(f"created packs directory in {packs_path}")

    content_repo = setup_content_repo(content_path)
    file_name, file_contents = get_file_name_and_contents(file_name, file_contents, entry_id)

    if file_name.endswith('.zip'):
        path_to_validate, code_fp_to_row_offset = prepare_content_pack_for_validation(
            file_name, file_contents, content_path
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
    get_content_modules(content_path, verify_ssl=verify_ssl)
    return path_to_validate, content_path


def main():
    cwd = os.getcwd()
    demisto.debug(f'{cwd=}')
    os.environ['DEMISTO_SDK_IGNORE_CONTENT_WARNING'] = "false"
    os.environ['DEMISTO_SDK_OFFLINE_ENV'] = "true"
    os.environ['DEMISTO_SDK_MAX_CPU_CORES'] = "1"  # TODO - Consider not specifying and use as much as available
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
                # TODO: Enable console_threshold='DEBUG' if args.get('debug-mode', False) else DEFAULT_CONSOLE_THRESHOLD,
                console_threshold='DEBUG',
                propagate=True
            )

            demisto.debug(f"Finished setting logger.")
            path_to_validate, content_path = setup_content_dir(filename, data, entry_id, verify_ssl)
            os.chdir(content_path)
            results, raw_outputs = validate_content(path_to_validate)
            os.chdir(cwd)
            return_results(CommandResults(
                readable_output=tableToMarkdown(
                    'Validation Results', results, headers=['Error Code', 'Error', 'File']
                ),
                outputs_prefix='ValidationResult',
                outputs=results,
                raw_response=raw_outputs,
            ))

        demisto.info('Finished validating content.')
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute ValidateContent. Error: {str(e)}')
    finally:
        os.chdir(cwd)
        os.environ['DEMISTO_SDK_CONTENT_PATH'] = ''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    log_demisto_sdk_version()
    main()