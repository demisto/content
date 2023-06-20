import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any, Tuple
from demisto_sdk.commands.common.tools import _get_file_id, get_file_displayed_name, find_type, get_file
from pathlib import Path
from collections import defaultdict

import traceback
import tempfile
import tarfile
import json
import os


def update_file_prefix(file_name: str) -> str:
    """
    Custom content scripts are prefixed with automation instead of script.
    Removing the "playbook-" prefix from files name.
    """
    if file_name.startswith('playbook-'):
        return file_name[len('playbook-'):]
    if file_name.startswith('automation-'):
        return file_name.replace('automation-', 'script-')
    return file_name


def get_content_details(tar_file_handler: Any, member_file: Any) -> Tuple[str, dict]:
    """Get content id from tar member file.

    Args:
        tar_file_handler: Tarfile open handler that contains the member file to inspect.
        member_file: The member file in the tar file to inspect.

    Return:
        (entity, file_id_name) of the member file.
    """
    file_type_str = ''
    file_id = None
    with tempfile.TemporaryDirectory() as tmp_dir_name:
        file_name = update_file_prefix(member_file.name.strip('/'))
        file_path = os.path.join(tmp_dir_name, file_name)
        with open(file_path, 'w') as file_desc:
            if extracted_file := tar_file_handler.extractfile(member_file):
                file_desc.write(extracted_file.read().decode('utf-8'))
            else:
                raise Exception(f'Could not extract file {file_name} from tar: {file_path}')

        if not os.path.isfile(file_path):
            raise Exception(f"Could not create file {file_path}")

        file_type = find_type(path=file_path)
        file_type_str = file_type.value if file_type else ''
        if file_type_str == 'automation':
            file_type_str = 'script'

        file_type_str = 'list' if not file_type_str and file_name.startswith('list-') else file_type_str
        file_dict = get_file(file_path, Path(file_name).suffix[1:])
        file_id = _get_file_id(file_type_str, file_dict)
        file_id = file_id if file_id else file_dict.get('id')
        file_name = get_file_displayed_name(file_path)

    file_id_name = {"id": file_id, "name": file_name}
    return file_type_str, file_id_name


def get_custom_content_ids(file_entry_id: Any) -> dict:
    """Get custom content ids from custom content bundle.

    Args:
         file_entry_id (str): The entry id of the custom content zip file.

    Return:
        A dict of custom content ids.
    """
    custom_content_ids: defaultdict[Any, list] = defaultdict(list)
    get_file_path_res = demisto.getFilePath(file_entry_id)
    custom_content_file_path = get_file_path_res.get('path')
    if not custom_content_file_path:
        raise ValueError(f"Could not find file path for entry id {file_entry_id}")
    custom_content_tar_file = tarfile.open(custom_content_file_path)
    custom_content_members = custom_content_tar_file.getmembers()

    for custom_content_member in custom_content_members:
        entity, entity_id_name = get_content_details(custom_content_tar_file, custom_content_member)
        if entity and entity_id_name.get('id'):
            custom_content_ids[entity].append(entity_id_name)
        else:
            raise Exception(f"Could not parse content type and id from file name {custom_content_member.name}")

    return custom_content_ids


''' COMMAND FUNCTION '''


def filter_lists(include: list, exclude: list) -> list:
    return [item for item in include if item.get('id') not in exclude]


def get_included_ids_command(args: Dict[str, Any]) -> CommandResults:
    """Get included ids from installed custom content unless id is excluded.

    Args:
        exclude_ids_list (List[Dict[str:List[str]]]): A list of dicts, each specifies entity ids to exclude.
            (example: [{'integration': ['HelloWorld', 'MyIntegration']}, {'script': ['say_hello']}]
        file_entry_id (str): The entry id of the custom content zip file.

    Return:
        CommandResults Outputs with included ids dict and excluded ids dict, ready to pass to DeleteContent script.
    """
    if excluded_ids_dicts := args.get('exclude_ids_list', []):
        if not isinstance(excluded_ids_dicts, list):
            try:
                excluded_ids_dicts = json.loads(str(args.get('exclude_ids_list')))
            except json.JSONDecodeError as err:
                raise ValueError(f'Failed decoding excluded_ids_list as json: {str(err)}')

    custom_content_ids = get_custom_content_ids(file_entry_id=args.get('file_entry_id'))

    included_custom_ids_names = {}
    excluded_ids: defaultdict[Any, list] = defaultdict(list)
    if excluded_ids_dicts:
        # Merge exclusion dicts
        for excluded_ids_dict in excluded_ids_dicts:
            for excluded_entity in excluded_ids_dict.keys():
                excluded_ids[excluded_entity] += excluded_ids_dict.get(excluded_entity, [])

        # Exclude what is relevant
        for custom_entity in custom_content_ids.keys():
            included_custom_ids_names[custom_entity] = filter_lists(include=custom_content_ids.get(custom_entity, []),
                                                                    exclude=excluded_ids.get(custom_entity, []))

        # Remove included entities from excluded dict
        for entity in included_custom_ids_names:
            if entity in excluded_ids.keys():
                excluded_ids.pop(entity)

    else:
        included_custom_ids_names = custom_content_ids

    included_custom_ids = {key: [value['id'] for value in lst] for key, lst in included_custom_ids_names.items() if lst}
    included_custom_name = {key: [value['name'] for value in lst] for key, lst in included_custom_ids_names.items() if lst}
    return CommandResults(
        outputs_prefix='GetIdsFromCustomContent',
        outputs_key_field='',
        outputs={'included_ids': included_custom_ids,
                 'excluded_ids': {key: value for key, value in excluded_ids.items() if value}},
        readable_output=tableToMarkdown('Included ids', included_custom_name) + tableToMarkdown('Excluded ids', excluded_ids)
    )


def main():  # pragma: no cover
    try:
        return_results(get_included_ids_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute GetIdsFromCustomContent. Error: {str(ex)}\n Traceback: {traceback.format_exc()}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
