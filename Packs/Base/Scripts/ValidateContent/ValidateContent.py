import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from pkg_resources import get_distribution

from demisto_sdk.commands.validate.config_reader import ConfigReader
from demisto_sdk.commands.validate.initializer import Initializer
from demisto_sdk.commands.validate.validate_manager import ValidateManager
from demisto_sdk.commands.validate.validation_results import ResultWriter
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, ExecutionMode

from pathlib import Path

os.environ['DEMISTO_SDK_CONTENT_PATH'] = 'content'


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

    return


def copy_file(file_name: str, data=None, file_path=None) -> str:
    """
    Copies or moves a file to a specific directory within a temporary pack.

    Args:
        file_name (str): The name of the file to copy or move.
        data (bytes, optional): The content to write into the new file if `file_path` is not provided.
        file_path (str, optional): The current path of the file to rename and move.

    Returns:
        str: The new file path.

    Raises:
        DemistoException: If the file cannot be copied or moved.
    """
    pack_name = 'TmpPack'
    pack_dir = os.path.join('content', 'Packs', pack_name)
    # Determine entity type by filename prefix.
    file_name_prefix = '-'.join(file_name.split('-')[:-1])
    containing_dir = os.path.join(pack_dir, ENTITY_TYPE_TO_DIR.get(file_name_prefix, 'Integrations'))
    os.makedirs(containing_dir, exist_ok=True)
    new_file_path = os.path.join(containing_dir, file_name)

    try:
        new_file_path = new_file_path
        if file_path:
            os.rename(file_path, new_file_path)
            demisto.debug(f'copy_file Successfully renamed `{file_path}` to `{new_file_path}`.')
        else:
            # Write the data to a new file in the filesystem if it doesn't already exist.
            with open(new_file_path, 'wb') as f:
                f.write(data.encode())
            demisto.debug(f'copy_file Successfully created file `{new_file_path}`.')
        return new_file_path
    except FileNotFoundError as e:
        raise DemistoException(f'copy_file Could not copy file `{file_name}` to `{new_file_path}`. Error message: {str(e)}')


def copy_files(file_name=None, data=None, entry_id=None) -> str:
    """
    Gets the files to be validated and copies them into the local filesystem.
    Arguments:
        file_name: Name of the file to copy.
        data: File data.
        entry_id: Entry ID in XSOAR to copy file from.
    Returns:
        str: path to copied files to be validated.
    """
    # TODO - Handle zips, and other file\'s collection structures.
    if file_name and data:
        demisto.info(f'copy_files got {file_name=} & data.')
        demisto.debug(f'copy_files decoding data into base64.')
        return copy_file(file_name, data)

    elif entry_id:
        demisto.info(f'copy_files getting file with {entry_id=}')
        file_object = demisto.getFilePath(entry_id)
        demisto.debug(f'copy_files got file_object: {file_object=}')

        file_path = file_object['path']
        file_name = file_object['name']
        return copy_file(file_name, file_path=file_path)


def run_validate(path_to_validate: str, json_output_file: str) -> int:
    """
    Runs demisto-sdk validations on a specified file path and writes the results to a JSON file.

    Args:
        path_to_validate (str): The path of the file or directory to be validated.
        json_output_file (str): The file path where validation results will be written in JSON format.

    Returns:
        int: An exit code indicating the validation status; 0 for success and non-zero for failures.

    """
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


def validate_content(path_to_validate: str) -> CommandResults:
    """
    <DOCSTRING>
    """
    validations_output_file = 'validation_res.json'
    pre_commit_output_file = 'pre_commit_res.json'

    exit_code = run_validate(path_to_validate, validations_output_file)
    if exit_code == 0:
        return_results(CommandResults(readable_output='All validations passed.'))


    raw_outputs = safe_load_json(validations_output_file)
    demisto.debug(f'validate_content {raw_outputs=}')
    if not raw_outputs:
        return_results(CommandResults(readable_output="No validation results found."))

    reformatted_outputs = reformat_validation_outputs(raw_outputs)
    return_results(CommandResults(
        readable_output=tableToMarkdown(
            'Validation Results', reformatted_outputs, headers=['Error Code', 'Error', 'File']
        ),
        outputs_prefix='ValidationResult',
        outputs=reformatted_outputs,
        raw_response=raw_outputs,
    ))


def main():
    try:
        args = demisto.args()
        setup_proxy(args)

        file_name = args.get('file_name', None)
        file_contents = args.get('file_contents', None)
        entry_id = args.get('entry_id', None)

        path_to_validate = copy_files(file_name, file_contents, entry_id)
        demisto.debug(f'main {path_to_validate=}')

        validate_content(path_to_validate)

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute ValidateContent. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    log_demisto_sdk_version()
    main()
