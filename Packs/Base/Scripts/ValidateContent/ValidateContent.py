import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from pkg_resources import get_distribution
from pathlib import Path
import git
from shutil import copy
from tempfile import TemporaryDirectory

from demisto_sdk.commands.init.contribution_converter import ContributionConverter

CONTENT_DIR_NAME = 'content'
CONTENT_REPO_URL = 'https://github.com/demisto/content.git'
CACHED_MODULES_DIR = '/tmp/cached_modules'
PRE_COMMIT_TEMPLATE_PATH = '.pre-commit-config_template.yaml'
BRANCH_MASTER = 'master'

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


def copy_file_to_content_pack(file_name: str, data=None, file_path=None, content_path=None) -> str:
    """
    Copies or moves a file to a temporary content pack.

    Args:
        file_name (str): The name of the file to copy or move.
        data (bytes, optional): The content to write into the new file if `file_path` is not provided.
        file_path (str, optional): The current path of the file to rename and move.
        content_path (str, optional): Path of Content directory to copy the file into.

    Returns:
        str: The new file path.

    Raises:
        DemistoException: If the file cannot be copied or moved.
    """
    from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR

    if not content_path:
        raise DemistoException(f'copy_file Could not copy file `{file_name}`. No content directory provided.')

    pack_name = 'TmpPack'
    pack_dir = os.path.join(content_path, 'Packs', pack_name)
    contrib_converter = ContributionConverter(
        name=pack_name, base_dir=content_path, pack_dir_name=pack_name, contribution=pack_name
    )
    contrib_converter.create_metadata_file({'description': 'Temporary Pack', 'author': 'xsoar'})
    # Determine entity type by filename prefix.
    file_name_prefix = '-'.join(file_name.split('-')[:-1])
    containing_dir = os.path.join(pack_dir, ENTITY_TYPE_TO_DIR.get(file_name_prefix, 'Integrations'))
    os.makedirs(containing_dir, exist_ok=True)
    new_file_path = os.path.join(containing_dir, file_name)
    demisto.debug(f'copy_file_to_content_pack: {os.listdir(containing_dir)=}')
    try:
        if file_path:
            copy(file_path, new_file_path)
            demisto.debug(f'copy_file Successfully moved `{file_path}` to `{new_file_path}`.')
        else:
            # Write the data to a new file in the filesystem if it doesn't already exist.
            with open(new_file_path, 'wb') as f:
                f.write(data.encode())
            demisto.debug(f'copy_file Successfully created file `{new_file_path}`.')
        return new_file_path
    except FileNotFoundError as e:
        raise DemistoException(f'copy_file Could not copy file `{file_name}` to `{new_file_path}`. Error message: {str(e)}')


def copy_files_to_content_dir(file_name=None, data=None, entry_id=None, content_path=None) -> str:
    """
    Gets the files to be validated and copies them into the local content directory.
    Arguments:
        file_name: Name of the file to copy.
        data: File data.
        entry_id: Entry ID in XSOAR to copy file from.
        content_path: Destination directory path.
    Returns:
        str: path to copied files to be validated.
    """
    # TODO - Handle zips, and other file\'s collection structures.

    if file_name and data:
        demisto.info(f'copy_files got {file_name=} & data.')
        demisto.debug(f'copy_files decoding data into base64.')
        return copy_file_to_content_pack(file_name=file_name, data=data, content_path=content_path)

    elif entry_id:
        demisto.info(f'copy_files getting file with {entry_id=}')
        file_object = demisto.getFilePath(entry_id)
        demisto.debug(f'copy_files got file_object: {file_object=}')

        file_path = file_object['path']
        file_name = file_object['name']
        return copy_file_to_content_pack(file_name=file_name, file_path=file_path, content_path=content_path)


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
        file_path=path_to_validate,
        execution_mode=ExecutionMode.SPECIFIC_FILES
    )
    validate_manager = ValidateManager(result_writer, config_reader, initializer, allow_autofix=False)
    demisto.debug(f'run_validate validate_manager initialized. Running validations: {validate_manager.validators=}')
    exit_code = validate_manager.run_validations()
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
            'github_url': 'https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/pre_commit/'
                          '.pre-commit-config_template.yaml',
            'content_path': '',
        }

    ]
    for module in modules:
        module_path = os.path.join(content_path, module['content_path'])
        os.makedirs(module_path, exist_ok=True)
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
            # check if '.pre-commit-config_template.yaml' exists.
            demisto.debug(f'get_content_modules {Path(os.path.join(module_path, module["file"])).exists()=}')
        except Exception as e:
            fallback_path = f'/home/demisto/{module["file"]}'
            demisto.debug(f'Failed downloading content module {module["github_url"]} - {e}. '
                          f'Copying from {fallback_path}')
            copy(fallback_path, module_path)


def run_pre_commit(path_to_validate: str, json_output_file: str) -> int:
    """
    <DOCSTRING>
    """
    from demisto_sdk.commands.pre_commit.pre_commit_command import pre_commit_manager
    exit_code = pre_commit_manager(
        # TODO - Verify if it can be both a folder and files.
        input_files=[Path(path_to_validate)],
        run_docker_hooks=False,
        pre_commit_template_path=Path(PRE_COMMIT_TEMPLATE_PATH),
    )
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
    validations_output_file = 'validation_res.json'
    pre_commit_output_file = 'pre_commit_res.json'
    demisto.debug(f'validate_content {os.getcwd()=}')

    validate_exit_code = run_validate(path_to_validate, validations_output_file)

    pre_commit_exit_code = run_pre_commit(path_to_validate, pre_commit_output_file)

    if not (validate_exit_code or pre_commit_exit_code):
        return CommandResults(readable_output='All validations passed.')

    all_outputs = []
    with open(validations_output_file, 'r') as json_outputs:
        raw_outputs = json.load(json_outputs)
        if raw_outputs:
            if type(raw_outputs) is list:
                all_outputs.extend(raw_outputs)
            else:
                all_outputs.append(raw_outputs)

    # TODO - Read pre-commit results.

    reformatted_outputs = reformat_validation_outputs(all_outputs)
    return CommandResults(
        readable_output=tableToMarkdown(
            'Validation Results', reformatted_outputs, headers=['Error Code', 'Error', 'File']
        ),
        outputs_prefix='ValidationResult',
        outputs=reformatted_outputs,
        raw_response=raw_outputs,
    )


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


def setup_content_dir(base_dir: str, file_name, file_contents, entry_id, verify_ssl=False) -> tuple[str, str]:
    """ Set up the content directory to validate the content items in."""

    content_path = os.path.join(base_dir, CONTENT_DIR_NAME)
    os.mkdir(content_path)
    demisto.debug(f"created content directory in {content_path}")
    os.environ['DEMISTO_SDK_CONTENT_PATH'] = content_path

    path_to_validate = copy_files_to_content_dir(file_name, file_contents, entry_id, content_path)
    demisto.debug(f'main {path_to_validate=}')

    setup_content_repo(content_path)

    os.makedirs(CACHED_MODULES_DIR, exist_ok=True)
    get_content_modules(content_path, verify_ssl=verify_ssl)
    return content_path, path_to_validate


def main():
    os.environ['DEMISTO_SDK_IGNORE_CONTENT_WARNING'] = "false"
    try:
        args = demisto.args()
        setup_proxy(args)
        verify_ssl = argToBoolean(args.get('trust_any_certificate'))

        demisto.debug(f'Got args {args}')
        filename = args.get('filename', None)
        data = args.get('data', None)
        entry_id = args.get('entry_id', None)

        with TemporaryDirectory() as tmp_dir:
            demisto.debug(f"created {tmp_dir=}")
            content_path, path_to_validate = setup_content_dir(tmp_dir, filename, data, entry_id, verify_ssl)
            return_results(validate_content(path_to_validate))

        demisto.debug(f'Finished validating content.')
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute ValidateContent. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    log_demisto_sdk_version()
    main()
