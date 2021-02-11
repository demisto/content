import io
import tempfile
import types
import zipfile
from base64 import b64decode
from contextlib import redirect_stderr, redirect_stdout

from demisto_sdk.commands.common import tools
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR
from demisto_sdk.commands.common.content import Content
from demisto_sdk.commands.common.content.objects.pack_objects.pack import Pack
from demisto_sdk.commands.common.tools import find_type
from demisto_sdk.commands.init.contribution_converter import (
    AUTOMATION, INTEGRATION, INTEGRATIONS_DIR, SCRIPT, SCRIPTS_DIR,
    ContributionConverter, format_manager, get_child_directories,
    get_child_files)
from demisto_sdk.commands.lint.lint_manager import LintManager
from demisto_sdk.commands.split_yml.extractor import Extractor
from demisto_sdk.commands.validate.validate_manager import ValidateManager
from ruamel.yaml import YAML

import demistomock as demisto
from CommonServerPython import *

yaml = YAML()


def remove_keys(content_entity: Dict, *args: str) -> None:
    for arg in args:
        content_entity.pop(arg, None)


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


def content_item_to_package_format(
        self, content_item_dir: str, del_unified: bool = True, source_mapping: Optional[Dict] = None  # noqa: F841
) -> None:
    child_files = get_child_files(content_item_dir)
    for child_file in child_files:
        cf_name_lower = os.path.basename(child_file).lower()
        if cf_name_lower.startswith((SCRIPT, AUTOMATION, INTEGRATION)) and cf_name_lower.endswith('yml'):
            content_item_file_path = child_file
            file_type = find_type(content_item_file_path)
            file_type = file_type.value if file_type else file_type
            try:
                extractor = Extractor(
                    input=content_item_file_path, file_type=file_type, output=content_item_dir, no_logging=True,
                    no_pipenv=True)
                extractor.extract_to_package_format()
            except Exception as e:
                err_msg = f'Error occurred while trying to split the unified YAML "{content_item_file_path}" ' \
                          f'into its component parts.\nError: "{e}"'
                self.contrib_conversion_errs.append(err_msg)
            if del_unified:
                os.remove(content_item_file_path)


def format_converted_pack(self) -> None:
    """Runs the demisto-sdk's format command on the pack converted from the contribution zipfile"""
    from_version = '6.0.0' if self.create_new else ''
    format_manager(
        input=self.pack_dir_path, from_version=from_version, no_validate=True, update_docker=True, assume_yes=True
    )


def convert_contribution_to_pack(contrib_converter: ContributionConverter) -> None:
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
    for pack_subdir in get_child_directories(contrib_converter.pack_dir_path):
        basename = os.path.basename(pack_subdir)
        if basename in {SCRIPTS_DIR, INTEGRATIONS_DIR}:
            contrib_converter.content_item_to_package_format = types.MethodType(content_item_to_package_format, contrib_converter)
            contrib_converter.content_item_to_package_format(
                pack_subdir, del_unified=True, source_mapping=None
            )


def get_pack_name(zip_fp: str) -> str:
    """returns the pack name from the zipped contribution file's metadata.json file"""
    with zipfile.ZipFile(zip_fp) as zipped_contrib:
        with zipped_contrib.open('metadata.json') as metadata_file:
            metadata = json.loads(metadata_file.read())
    return metadata.get('name', 'ServerSidePackValidationDefaultName')


def run_validate(file_path: str, json_output_file: str) -> None:
    output_capture = io.StringIO()
    with redirect_stdout(output_capture):
        with redirect_stderr(output_capture):
            v_manager = ValidateManager(
                is_backward_check=False, prev_ver=None, use_git=False, only_committed_files=False,
                print_ignored_files=False, skip_conf_json=True, validate_id_set=False, file_path=file_path,
                validate_all=False, is_external_repo=False, skip_pack_rn_validation=False, print_ignored_errors=False,
                silence_init_prints=False, no_docker_checks=False, skip_dependencies=False, id_set_path=None,
                staged=False, json_file_path=json_output_file, skip_schema_check=True)
            v_manager.run_validation()


def run_lint(file_path: str, json_output_file: str) -> None:
    lint_log_dir = os.path.normpath(os.path.join(json_output_file, '..'))
    output_capture = io.StringIO()
    with redirect_stdout(output_capture):
        with redirect_stderr(output_capture):
            lint_manager = LintManager(
                input=file_path, git=False, all_packs=False, quiet=False, verbose=1,
                log_path=lint_log_dir, prev_ver='', json_file_path=json_output_file
            )
            lint_manager.run_dev_packages(
                parallel=1, no_flake8=False, no_xsoar_linter=False, no_bandit=False, no_mypy=False,
                no_vulture=False, keep_container=False, no_pylint=True, no_test=True, no_pwsh_analyze=True,
                no_pwsh_test=True, test_xml='', failure_report=lint_log_dir
            )


def validate_content(filename, data, tmp_directory: str) -> List:
    keys_to_remove = ['contentitemexportablefields', 'pswd', 'sourcemoduleid']
    # case when a pack zip file has been passed
    content = Content(tmp_directory)
    json_output_path = os.path.join(os.path.normpath(content.path / '..'), 'validation_res.json')
    lint_output_path = os.path.join(os.path.normpath(content.path / '..'), 'lint_res.json')
    if filename.endswith('.zip'):
        # write zip file data to file system
        zip_path = os.path.abspath(os.path.join(tmp_directory, filename))
        with open(zip_path, 'wb') as fp:
            fp.write(data)

        pack_name = get_pack_name(zip_path)
        contrib_converter = ContributionConverter(name=pack_name, contribution=zip_path, base_dir=tmp_directory)
        convert_contribution_to_pack(contrib_converter)
        # Call the standalone function and get the raw response
        os.remove(zip_path)
        pack_path = contrib_converter.pack_dir_path
        pack_entity = Pack(pack_path)
        for content_entities in pack_entity.scripts, pack_entity.integrations:
            for content_entity in content_entities:
                remove_keys(content_entity.to_dict(), *keys_to_remove)
                buff = io.StringIO()
                yaml.dump(content_entity.to_dict(), buff)
                content_entity.path.write_text(buff.getvalue())
        path_to_validate = pack_path
    else:
        # a single content item
        pack_name = 'TmpPack'
        pack_dir = content.path / 'Packs' / pack_name
        # create pack_metadata.json file in TmpPack
        contrib_converter = ContributionConverter(name=pack_name, base_dir=tmp_directory, pack_dir_name=pack_name)
        contrib_converter.create_metadata_file({'description': 'Temporary Pack', 'author': 'xsoar'})
        prefix = '-'.join(filename.split('-')[:-1])
        containing_dir = pack_dir / ENTITY_TYPE_TO_DIR.get(prefix, 'Integrations')
        containing_dir.mkdir(exist_ok=True)
        data_as_string = data.decode()
        loaded_data = yaml.load(data_as_string)
        remove_keys(loaded_data, *keys_to_remove)
        buff = io.StringIO()
        yaml.dump(loaded_data, buff)
        data_as_string = buff.getvalue()
        # write yaml integration file to file system
        file_path = containing_dir / filename
        file_path.write_text(data_as_string)
        file_type = find_type(str(file_path))
        file_type = file_type.value if file_type else file_type
        extractor = Extractor(
            input=str(file_path), file_type=file_type, output=containing_dir, no_logging=True, no_pipenv=True)
        # validate the resulting package files, ergo set path_to_validate to the package directory that results
        # from extracting the unified yaml to a package format
        path_to_validate = extractor.get_output_path()
        extractor.extract_to_package_format()

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
                all_outputs.extend(outputs_as_json)
            else:
                all_outputs.append(outputs_as_json)
    return all_outputs


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
    try:
        os.chdir('/var/lib/demisto')
        with tempfile.TemporaryDirectory(None, None, os.path.abspath(os.curdir)) as tmp_directory:
            content_dir = os.path.join(tmp_directory, 'content')
            os.makedirs(content_dir, exist_ok=True)
            tools.run_command('git init', cwd=content_dir)
            tools.run_command('git remote add origin https://github.com/demisto/content.git', cwd=content_dir)
            os.chdir(content_dir)
            args = demisto.args()
            filename, file_contents = get_file_name_and_contents(
                args.get('filename'),
                args.get('data'),
                args.get('entry_id'),
            )
            result = validate_content(filename, file_contents, content_dir)
        return_results(CommandResults(raw_response=result))
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ValidateContent. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
