from CommonServerPython import *
import demistomock as demisto
''' IMPORTS '''

import io
import urllib3
import uuid
import dateparser
from typing import List, Dict, Any, Tuple, Optional, Union, Callable

from apiclient import discovery
from googleapiclient.http import MediaFileUpload
from googleapiclient.http import MediaIoBaseDownload

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

MESSAGES: Dict[str, str] = {
    'TEST_FAILED_ERROR': 'Test connectivity failed. Check the configuration parameters provided.',
    'DRIVE_CHANGES_FIELDS': 'The argument fields must be either basic or advance.',
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'FETCH_INCIDENT_REQUIRED_ARGS': 'The Parameter Drive Item Search Field and Drive Item Search Value are required'
                                    ' if any one of them is provided.',
    'MAX_INCIDENT_ERROR': 'The parameter Max Incidents must be a positive integer.'
                          ' Accepted values can be in the range of 1-100.',
    'USER_ID_REQUIRED': 'The parameter User ID is required.'
}

HR_MESSAGES: Dict[str, str] = {
    'DRIVE_CREATE_SUCCESS': 'A new shared drive created.',
    'NOT_FOUND': 'No {} found.',
    'LIST_COMMAND_SUCCESS': 'Total Retrieved {}: {}',
    'DELETE_COMMAND_SUCCESS': 'Total Deleted {}: {}',

    'EXCEPTION_LIST_GENERIC': 'Exception searching for {}: {}',

    'EXCEPTION_GENERIC': 'Exception handling a {} request: {}',
}

SCOPES: Dict[str, List[str]] = {
    'TEST_MODULE': ['https://www.googleapis.com/auth/userinfo.email'],
    'DRIVE': ['https://www.googleapis.com/auth/drive']
}

COMMAND_SCOPES: Dict[str, List[str]] = {
    'DRIVE_CHANGES': [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.readonly',
        'https://www.googleapis.com/auth/drive.metadata.readonly',
        'https://www.googleapis.com/auth/drive.appdata',
        'https://www.googleapis.com/auth/drive.metadata',
        'https://www.googleapis.com/auth/drive.photos.readonly'
    ],
    'DRIVE_ACTIVITY': [
        'https://www.googleapis.com/auth/drive.activity',
        'https://www.googleapis.com/auth/drive.activity.readonly'
    ],
    'DRIVES': [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/drive.readonly'
    ],
    'FILES': [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.readonly',
        'https://www.googleapis.com/auth/drive.metadata.readonly',
        'https://www.googleapis.com/auth/drive.appdata',
        'https://www.googleapis.com/auth/drive.metadata',
        'https://www.googleapis.com/auth/drive.photos.readonly'
    ],
    'FILE_REPLACE_EXISTING': [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.appdata',
        'https://www.googleapis.com/auth/drive.scripts',
        'https://www.googleapis.com/auth/drive.,etadata',
    ],
    'FILE_DELETE': [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.appdata'
    ],

    'FILE_PERMISSIONS_LIST': [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive.readonly',
        'https://www.googleapis.com/auth/drive.metadata.readonly',
        'https://www.googleapis.com/auth/drive.metadata',
        'https://www.googleapis.com/auth/drive.photos.readonly',
    ],

    'FILE_PERMISSIONS_CRUD': [
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/drive.file',
    ]

}

URLS: Dict[str, str] = {
    'DRIVE_ACTIVITY': 'https://driveactivity.googleapis.com/v2/activity:query'
}
URL_SUFFIX: Dict[str, str] = {
    'DRIVE_CHANGES': 'drive/v3/changes',
    'DRIVE_CREATE': 'drive/v3/drives',
    'DRIVE_DRIVES': 'drive/v3/drives',
    'DRIVE_DRIVES_ID': 'drive/v3/drives/{}',
    'DRIVE_FILES': 'drive/v3/files',
    'DRIVE_FILES_ID': 'drive/v3/files/{}',

    'FILE_UPLOAD': 'upload/drive/v3/files',
    'FILE_REPLACE_EXISTING': 'upload/drive/v3/files/{}',

    'FILE_PERMISSIONS_LIST': 'drive/v3/files/{}/permissions',
    'FILE_PERMISSION_CREATE': 'drive/v3/files/{}/permissions',
    'FILE_PERMISSION_UPDATE': 'drive/v3/files/{}/permissions/{}',
    'FILE_PERMISSION_DELETE': 'drive/v3/files/{}/permissions/{}',
}

OUTPUT_PREFIX: Dict[str, str] = {
    'GOOGLE_DRIVE_HEADER': 'GoogleDrive.Drive',
    'PAGE_TOKEN': 'PageToken',

    'DRIVE_CHANGES_LIST': 'GoogleDrive.DriveChange(val.time == obj.time && val.fileId == obj.fileId &&'
                          ' val.driveId == obj.driveId && val.userId == obj.userId)',
    'DRIVE_CHANGES_LIST_PAGE_TOKEN': 'GoogleDrive.PageToken.DriveChange(val.driveId == obj.driveId'
                                     ' && val.userId == obj.userId)',

    'DRIVE_ACTIVITY_LIST': 'GoogleDrive.DriveActivity',
    'DRIVE_ACTIVITY_LIST_PAGE_TOKEN': 'GoogleDrive.PageToken.DriveActivity',

    'GOOGLE_DRIVE_DRIVE_HEADER': 'GoogleDrive.Drive',
    'DRIVE': 'Drive',

    'GOOGLE_DRIVE_FILE_HEADER': 'GoogleDrive.File',
    'FILE': 'File',

    'GOOGLE_DRIVE_FILE_PERMISSION_HEADER': 'GoogleDrive.FilePermission',
    'FILE_PERMISSION': 'FilePermission',

}

DATE_FORMAT: str = '%Y-%m-%d'  # sample - 2020-08-23
DATE_FORMAT_TIME_RANGE: str = '%Y-%m-%dT%H:%M:%SZ'

OBJECT_HEADER: str = 'Object'
ACTIVITY_TIME: str = 'Activity Time'
PRIMARY_ACTION: str = 'Primary Action'
NEXT_PAGE_TOKEN: str = '### Next Page Token: {}\n'
COLOR_RGB: str = 'Color RGB'
ACTION_MAPPINGS: Dict[str, str] = {'dlpChange': 'DLPChange'}
DRIVE_ACTIVITY_DETAIL_ACTION: str = 'detail.action_detail_case: {}'


def prepare_markdown_from_dictionary(data: Dict[str, Any], ignore_fields: List[str] = []) -> str:
    """
    Prepares markdown from dictionary.

    :param data: data directory.
    :param ignore_fields: fields to ignore while preparing mark-down from dictionary.

    :return: data in markdown format.
    """
    hr_cell_info: List[str] = []
    for key, value in data.items():
        if key not in ignore_fields:
            hr_cell_info.append(
                '{}: {}'.format(pascalToSpace(key), ', '.join(value) if isinstance(value, list) else value))
    return '\n'.join(hr_cell_info)


def prepare_params_for_drive_changes_list(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Prepares arguments for google-drive-changes-list command.

    :param args: Command arguments.
    :return: Prepared params.
    :raises ValueError: If there any invalid value of argument.
    """
    GSuiteClient.validate_set_boolean_arg(args, 'include_corpus_removals')
    GSuiteClient.validate_set_boolean_arg(args, 'include_items_from_all_drives')
    GSuiteClient.validate_set_boolean_arg(args, 'include_removed')
    GSuiteClient.validate_set_boolean_arg(args, 'restrict_to_my_drive')
    GSuiteClient.validate_set_boolean_arg(args, 'supports_all_drives')

    fields = args.get('fields', 'basic')
    if fields == 'basic':
        fields = ''
    elif fields == 'advance':
        fields = '*'
    else:
        raise ValueError(MESSAGES['DRIVE_CHANGES_FIELDS'])
    page_size = args.get('page_size', '100')
    GSuiteClient.validate_get_int(page_size, MESSAGES['INTEGER_ERROR'].format('page_size'))

    params = {
        'pageToken': args.get('page_token', ''),
        'driveId': args.get('drive_id', ''),
        'includeCorpusRemovals': args.get('include_corpus_removals'),
        'includeItemsFromAllDrives': args.get('include_items_from_all_drives'),
        'includePermissionsForView': args.get('include_permissions_for_view', ''),
        'includeRemoved': args.get('include_removed'),
        'pageSize': int(page_size),
        'restrictToMyDrive': args.get('restrict_to_my_drive'),
        'spaces': args.get('spaces', ''),
        'supportsAllDrives': args.get('supports_all_drives'),
        'fields': fields
    }
    return GSuiteClient.remove_empty_entities(params)


def prepare_drive_changes_output(response: Dict[str, Any], drive_id: str, user_id: str) -> \
        Tuple[Dict[str, Any], List[Dict[str, Optional[Any]]], List[Dict[str, Optional[Any]]]]:
    """
    Prepares context output and human readable for google-drive-changes-list command.

    :param response: Response from API.
    :param drive_id: Drive Id.
    :param user_id: User's primary email address.

    :return: Tuple of output and human readable.
    """
    page_context = {
        'userId': user_id,
        'driveId': drive_id,
        'nextPageToken': response.get('nextPageToken', ''),
        'newStartPageToken': response.get('newStartPageToken', '')
    }
    page_context = GSuiteClient.remove_empty_entities(page_context)

    drive_changes_context = GSuiteClient.remove_empty_entities(response.get('changes', []))

    outputs = {
        OUTPUT_PREFIX['DRIVE_CHANGES_LIST']: drive_changes_context,
        OUTPUT_PREFIX['DRIVE_CHANGES_LIST_PAGE_TOKEN']: page_context
    }
    outputs = GSuiteClient.remove_empty_entities(outputs)

    drive_changes_hr_files: List[Dict[str, Any]] = [{}]
    drive_changes_hr_drives: List[Dict[str, Any]] = [{}]
    for drive_change in drive_changes_context:
        drive_change_file = drive_change.get('file', {})
        drive_changes_hr_files.append({
            'Id': drive_change_file.get('id', ''),
            'Name': drive_change_file.get('name', ''),
            'Modified Time': drive_change_file.get('modifiedTime', ''),
            'Size(bytes)': drive_change_file.get('size', ''),
            'lastModifyingUser': drive_change_file.get('lastModifyingUser', {}).get('displayName', '')
        })

        drive_change_drive = drive_change.get('drive', {})
        drive_changes_hr_drives.append({
            'Id': drive_change_drive.get('id', ''),
            'Name': drive_change_drive.get('name', ''),
            'ThemeId': drive_change_drive.get('themeId', ''),
            COLOR_RGB: drive_change_drive.get('colorRgb', '')
        })

    drive_changes_hr_files = GSuiteClient.remove_empty_entities(drive_changes_hr_files)
    drive_changes_hr_drives = GSuiteClient.remove_empty_entities(drive_changes_hr_drives)

    return outputs, drive_changes_hr_files, drive_changes_hr_drives


def prepare_body_for_drive_activity(args: Dict[str, str]) -> Dict[str, Union[str, int]]:
    """
    To prepare body for drive_activity_list_command.

    :param args: Command arguments.
    :return: Dict of arguments.
    """
    filter_activity = ''
    time_range = args.get('time_range', '')
    action_detail_case_include = args.get('action_detail_case_include', '')
    action_detail_case_remove = args.get('action_detail_case_remove', '')
    if time_range:
        time_range, _ = parse_date_range(time_range, date_format=DATE_FORMAT_TIME_RANGE, utc=True)

        filter_activity += 'time >= "{}"'.format(time_range)

    if action_detail_case_include:
        filter_activity += ' AND ' + DRIVE_ACTIVITY_DETAIL_ACTION.format(
            action_detail_case_include) if time_range else DRIVE_ACTIVITY_DETAIL_ACTION.format(
            action_detail_case_include)

    if action_detail_case_remove:
        filter_activity += ' AND -' + DRIVE_ACTIVITY_DETAIL_ACTION.format(
            action_detail_case_remove) if time_range or action_detail_case_include \
            else ' -' + DRIVE_ACTIVITY_DETAIL_ACTION.format(action_detail_case_remove)

    if args.get('filter', ''):
        filter_activity = args.get('filter', '')

    arguments = {
        'ancestorName': args.get('folder_name', ''),
        'itemName': args.get('item_name', ''),
        'pageToken': args.get('page_token', ''),
        'filter': filter_activity
    }
    return GSuiteClient.remove_empty_entities(arguments)


def set_true_for_empty_dict(d):
    """
    Recursively set value of empty dicts from a dictionary.

    For some of entity G Suite API return {} (blank dictionary) which indicates some actions on resource.
    Eg. Here, new or upload indicates resource is newly created or uploaded on the server.
    {
    "new": {}, // An object was created from scratch.
    "upload": {}, // An object was uploaded into Drive.
    }

    :param d: Input dictionary.
    :return: Dictionary with all empty dictionary's value set as True.
    """
    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [value for value in (set_true_for_empty_dict(value) for value in d)]
    else:
        if d == {}:
            return True
        return {key: True if value == {} else value for key, value in ((key, set_true_for_empty_dict(value))
                                                                       for key, value in d.items())}


def prepare_drive_activity_output(activity: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepares context output for google-drive-activity-list command.

    :param activity: Response from API.

    :return: Context output.
    """
    activity_name = list(activity.get('primaryActionDetail', {}).keys())
    drive_activity_context = {
        'name': activity_name[0] if activity_name else '',
    }
    drive_activity_context.update(activity)
    drive_activity_context = set_true_for_empty_dict(drive_activity_context)

    return GSuiteClient.remove_empty_entities(drive_activity_context)


def prepare_hr_setting_changes_entity(context: Dict[str, Any]) -> str:
    """
    Prepare human readable of setting entity of google-drive-activity-list

    :param context: Prepared context data.
    :return: Restriction changes.
    """
    restriction_changes = ''
    settings_change = [
        {
            'feature': setting.get('feature', ''),
            'newRestriction': setting.get('newRestriction', '')
        } for setting in context.get('primaryActionDetail', {}).get('settingsChange', {}).get('restrictionChanges', [])
    ]
    for restriction in settings_change:
        restriction_changes += prepare_markdown_from_dictionary(restriction) + '\n'
    return restriction_changes


def prepare_target_for_drive_activity(targets_list: List) -> str:
    """

    :param targets_list: Target entity in context data.

    :return: Prepared markdown string.
    """
    targets_data: str = ''
    for target in targets_list:
        drive: Dict[str, Any] = target.get('drive', {})
        file_comment_parent: Dict[str, Any] = target.get('fileComment', {}).get('parent', {})
        drive_item: Dict[str, Any] = target.get('driveItem', {})
        if drive_item:
            targets_data += 'Target: \'' + drive_item.get('title', '') + "'\n"

        elif drive:
            targets_data += 'Target: \'' + drive.get('title', '') + "'\n"

        elif file_comment_parent:
            targets_data += 'Commented on file \'' + file_comment_parent.get('title', '') + "'\n"

    return targets_data


def prepare_drive_activity_human_readable(outputs_context: List[Dict[str, Any]]) -> str:
    """
    Prepares human readable for google-drive-activity-list command.

    :param outputs_context: Context data.

    :return: Human readable.
    """
    drive_hr: List[Dict[str, Any]] = [{}]
    for context in outputs_context:
        primary_action_detail = context.get('primaryActionDetail', {})

        name = context.pop('name', '')
        object_target: str = prepare_target_for_drive_activity(context.get('targets', []))
        time_stamp = context.get('timestamp', '')

        if 'edit' == name:
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Edit',
                             OBJECT_HEADER: object_target})

        elif 'delete' == name:
            delete_type: str = 'Delete Type: ' + primary_action_detail.get('delete', {}).get('type', '') + '\n'
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Delete',
                             OBJECT_HEADER: delete_type + object_target})

        elif 'restore' == name:
            restore_type: str = 'Restore Type: ' + primary_action_detail.get('restore', {}).get('type', '') + '\n'
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Restore',
                             OBJECT_HEADER: restore_type + object_target})

        elif 'dlpChange' == name:
            dlp_type: str = 'DataLeakPreventionChange Type: ' + primary_action_detail.get('dlpChange',
                                                                                          {}).get('type', '') + '\n'
            drive_hr.append(
                {ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'DataLeakPreventionChange',
                 OBJECT_HEADER: dlp_type + object_target})

        elif 'reference' == name:
            reference_type: str = 'Reference Type: ' + primary_action_detail.get('reference', {}).get('type', '') + '\n'

            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Reference',
                             OBJECT_HEADER: reference_type + object_target})

        elif 'rename' == name:
            rename_object: Dict[str, Any] = primary_action_detail.get('rename', {})
            rename_titles: str = 'Old Title: \'' + rename_object.get('oldTitle', '') + "'\n" + 'New Title: \'' + \
                                 rename_object.get('newTitle', '') + "'\n"
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Rename',
                             OBJECT_HEADER: rename_titles})

        elif 'move' == name:
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Move', OBJECT_HEADER: object_target})

        elif 'permissionChange' == name:
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'PermissionChange',
                             OBJECT_HEADER: object_target})

        elif 'settingsChange' == name:
            settings_changes: str = prepare_hr_setting_changes_entity(context)
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'SettingsChange',
                             OBJECT_HEADER: settings_changes + object_target})

        elif 'comment' == name:
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Comment',
                             OBJECT_HEADER: object_target})

        elif 'create' == name:
            created: List = list(primary_action_detail.get('create', {}).keys())
            drive_hr.append({ACTIVITY_TIME: time_stamp, PRIMARY_ACTION: 'Create ' + created[0].capitalize(),
                             OBJECT_HEADER: object_target})

    drive_hr = GSuiteClient.remove_empty_entities(drive_hr)
    drive_activity_hr = tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Drive Activity(s)', len(drive_hr)),
                                        drive_hr,
                                        [ACTIVITY_TIME, PRIMARY_ACTION, OBJECT_HEADER],
                                        headerTransform=pascalToSpace,
                                        removeNull=True)

    return drive_activity_hr


def flatten_user_dict(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten keys of user to populate the grid field.

    :param user: user's dictionary.

    :return: flatten user dictionary.
    """
    known_user = user.get('knownUser', {})
    return GSuiteClient.remove_empty_entities({
        'personName': known_user.get('personName'),
        'isCurrentUser': known_user.get('isCurrentUser'),
        'isDeletedUser': set_true_for_empty_dict(user.get('deletedUser')),
        'isUnknownUser': set_true_for_empty_dict(user.get('unknownUser'))})


def flatten_targets_keys_for_fetch_incident(activity: Dict[str, Any]) -> None:
    """
    Flatten keys of targets to populate the grid field.

    :param activity: dictionary of activity.

    :return: List of targets and actors value.
    """

    def update_drive_item(item):
        owner_user = item.get('owner', {}).get('user', {})
        return GSuiteClient.remove_empty_entities({
            'itemname': item.get('name'),
            'title': item.get('title'),
            'owner': owner_user.get('knownUser', {}).get('personName'),
            'iscurrentuser': owner_user.get('knownUser', {}).get('isCurrentUser'),
            'isdeleteduser': set_true_for_empty_dict(owner_user.get('deletedUser')),
            'isunknownuser': set_true_for_empty_dict(owner_user.get('unknownUser'))
        })

    flatten_targets = []
    activity_targets = activity.get('targets', [])
    for target in activity_targets:
        if 'driveItem' in target:
            flatten_targets.append(update_drive_item(target.get('driveItem', {})))
        elif 'drive' in target:
            flatten_targets.append(update_drive_item(target.get('drive', {}).get('root', {})))
        elif 'fileComment' in target:
            file_parents = update_drive_item(target.get('fileComment', {}).get('parent', {}))
            file_parents['Link'] = target.get('fileComment', {}).get('linkToDiscussion', '')
            flatten_targets.append(file_parents)
    activity['targets'] = flatten_targets


def actors_type_keys_for_fetch_incident(activity: Dict[str, Any]) -> None:
    """
    Actors to populate on incident.

    :param activity: dictionary of activity.

    :return: None.
    """
    actors_list = activity.get('actors', [])
    flatten_actors: str = ''
    for actor in actors_list:
        known_user = actor.get('user', {}).get('knownUser', {})
        if known_user:
            flatten_actors += 'Known User: ' + known_user.get('personName', '')
        elif set_true_for_empty_dict(actor.get('user', {}).get('deletedUser')):
            flatten_actors += 'Deleted User'
        elif set_true_for_empty_dict(actor.get('user', {}).get('unknownUser')):
            flatten_actors += 'Unknown User'
        else:
            flatten_actors += list(actor.keys())[0].capitalize()
        flatten_actors += "\n"
    activity['actors'] = flatten_actors


def flatten_permission_change_keys_for_fetch_incident(permission_change: Dict[str, Any]) -> None:
    """
    Flatten keys of permission change to populate the grid field.

    :param permission_change: dictionary of Permission Change.

    :return: None
    """

    def update_permission(permission):
        permission_group = permission.get('group', {})
        prepared_permission = {
            'role': permission.get('role', ''),
            'allowdiscovery': permission.get('allowDiscovery'),
            'groupemail': permission_group.get('email'),
            'grouptitle': permission_group.get('title'),
            'domainname': permission.get('domain', {}).get('name'),
            'isanyone': set_true_for_empty_dict(permission.get('anyone'))
        }
        prepared_permission.update(flatten_user_dict(permission.get('user', {})))
        return GSuiteClient.remove_empty_entities(prepared_permission)

    if 'addedPermissions' in permission_change:
        permission_change['addedPermissions'] = [update_permission(permission) for permission in
                                                 permission_change['addedPermissions']]
    if 'removedPermissions' in permission_change:
        permission_change['removedPermissions'] = [update_permission(permission) for permission in
                                                   permission_change['removedPermissions']]


def flatten_move_keys_for_fetch_incident(move: Dict[str, Any]) -> None:
    """
    Flatten keys of move to populate the grid field.

    :param move: dictionary of move.

    :return: None
    """

    def update_move_parents(parents):
        parent_drive_item = parents.get('driveItem', {})
        parent_drive = parents.get('drive', {})
        return GSuiteClient.remove_empty_entities({
            'driveitemname': parent_drive_item.get('name'),
            'driveitemtitle': parent_drive_item.get('title'),
            'driveitemisdrivefile': set_true_for_empty_dict(parent_drive_item.get('driveFile')),
            'driveitemfoldertype': parent_drive_item.get('driveFolder', {}).get('type'),
            'drivename': parent_drive.get('name'),
            'drivetitle': parent_drive.get('title')
        })

    if 'addedParents' in move:
        move['addedParents'] = [update_move_parents(parents) for parents in
                                move['addedParents']]
    if 'removedParents' in move:
        move['removedParents'] = [update_move_parents(parents) for parents in
                                  move['removedParents']]


def flatten_comment_mentioned_user_keys_for_fetch_incident(comment: Dict[str, Any]) -> None:
    """
     Flatten keys of mentioned_users to populate the grid field.

    :param comment: list of comment.

    :return: None
    """
    if 'mentionedUsers' in comment:
        comment['mentionedUsers'] = [flatten_user_dict(user) for user in
                                     comment['mentionedUsers']]


def prepare_args_for_fetch_incidents(last_fetch: int, args: Dict[str, Any]) -> Dict[str, Any]:
    """
     Prepares arguments for fetch-incidents.

    :param last_fetch: last fetch time of incident.
    :param args: fetch-incident arguments.

    :return: Prepared request body for fetch-incident.
    """
    if (args.get('drive_item_search_value') and not args.get('drive_item_search_field')) or (
            not args.get('drive_item_search_value') and args.get('drive_item_search_field')):
        raise ValueError(MESSAGES['FETCH_INCIDENT_REQUIRED_ARGS'])

    action_detail_case_include = [action.upper() for action in args.get('action_detail_case_include', [])]

    action_detail_case_str = ''
    if args.get('action_detail_case_include'):
        action_detail_case = ' '.join(action_detail_case_include)
        action_detail_case_str += f" AND detail.action_detail_case: ({action_detail_case})"

    drive_item_search_field = args.get('drive_item_search_field', '')
    if drive_item_search_field == 'folderName':
        drive_item_search_field = 'ancestorName'
    return GSuiteClient.remove_empty_entities({
        'filter': f'time > {last_fetch}{action_detail_case_str}',
        drive_item_search_field: args.get('drive_item_search_value'),
        'pageSize': 100
    })


def validate_params_for_fetch_incidents(params: Dict[str, Any]) -> None:
    """
    Validates parameters for fetch-incidents command.

    :param params: parameters dictionary.

    :return: None
    """
    if not params.get('user_id'):
        raise ValueError(MESSAGES['USER_ID_REQUIRED'])

    params['first_fetch_interval'], _ = parse_date_range(params.get('first_fetch', '10 minutes'), utc=True)

    # Check for depended required parameters.
    if (params.get('drive_item_search_value') and not params.get('drive_item_search_field')) or (
            not params.get('drive_item_search_value') and params.get('drive_item_search_field')):
        raise ValueError(MESSAGES['FETCH_INCIDENT_REQUIRED_ARGS'])

    params['max_fetch'] = GSuiteClient.validate_get_int(params.get('max_fetch', 10), limit=100,
                                                        message=MESSAGES['MAX_INCIDENT_ERROR'])


''' COMMAND FUNCTIONS '''


@logger
def test_module(gsuite_client: 'GSuiteClient', last_run: Dict, params: Dict[str, Any]) -> str:
    """
    Performs test connectivity by valid http response

    :param gsuite_client: client object which is used to get response from api.
    :param last_run: Demisto last run dictionary.
    :param params: configuration parameters.

    :return: raise ValueError if any error occurred during connection
    :raises DemistoException: If there is any other issues while making the http call.
    """
    if params.get('isFetch'):
        fetch_incidents(gsuite_client, last_run, params, is_test=True)
    else:
        with GSuiteClient.http_exception_handler():
            body = prepare_body_for_drive_activity(params)
            user_id = params.get('user_id', '')
            gsuite_client.set_authorized_http(scopes=COMMAND_SCOPES['DRIVE_ACTIVITY'], subject=user_id)
            gsuite_client.http_request(full_url=URLS['DRIVE_ACTIVITY'], method='POST', body=body)

    return 'ok'


@logger
def drive_create_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Creates a new Team Drive. The name argument specifies the name of the Team Drive. The specified user will be the
    first organizer.
    This shared drive/team drive feature is available only with G Suite Enterprise, Enterprise for Education,
    G Suite Essentials, Business, Education, and Nonprofits edition.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """

    client.set_authorized_http(scopes=SCOPES['DRIVE'], subject=args.get('user_id', ''))

    GSuiteClient.validate_set_boolean_arg(args, 'hidden')

    response = client.http_request(url_suffix=URL_SUFFIX['DRIVE_CREATE'],
                                   params={'requestId': str(uuid.uuid4())}, body=args, method='POST')
    response = GSuiteClient.remove_empty_entities(response)

    hr_output_fields = ['id', 'name', 'hidden']

    hr_output = response.copy()

    readable_output = tableToMarkdown(HR_MESSAGES['DRIVE_CREATE_SUCCESS'], hr_output, headerTransform=pascalToSpace,
                                      removeNull=True, headers=hr_output_fields)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['GOOGLE_DRIVE_HEADER'],
        outputs_key_field='id',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def drive_changes_list_command(client: 'GSuiteClient', args: Dict[str, Any]) -> CommandResults:
    """
    Lists the changes for a user or shared drive.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    user_id = args.get('user_id', '')
    params = prepare_params_for_drive_changes_list(args)
    client.set_authorized_http(scopes=COMMAND_SCOPES['DRIVE_CHANGES'], subject=user_id)
    response = client.http_request(url_suffix=URL_SUFFIX['DRIVE_CHANGES'], method='GET',
                                   params=params)

    outputs, drive_changes_hr_files_list, drive_changes_hr_drives_list = \
        prepare_drive_changes_output(response, args.get('drive_id', ''), user_id)
    readable_output = ''
    if response.get('nextPageToken'):
        readable_output += NEXT_PAGE_TOKEN.format(response.get('nextPageToken'))
    if response.get('newStartPageToken'):
        readable_output += '### New Start Page Token: {}\n'.format(response.get('newStartPageToken'))

    readable_output += tableToMarkdown('Files(s)',
                                       drive_changes_hr_files_list,
                                       ['Id', 'Name', 'Size(bytes)', 'Modified Time', 'lastModifyingUser'],
                                       headerTransform=pascalToSpace,
                                       removeNull=True)

    readable_output += tableToMarkdown('Drive(s)', drive_changes_hr_drives_list,
                                       ['Id', 'Name', 'ThemeId', COLOR_RGB],
                                       headerTransform=pascalToSpace,
                                       removeNull=True)
    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def prepare_drives_request(client: 'GSuiteClient', args: Dict[str, str]) -> Dict[str, Any]:
    """
    prepare_drives_request
    Preparing http_request_params and populating the client

    :param client: Client object.
    :param args: Command arguments.

    :return: Objects ready for requests
    """

    http_request_params: Dict[str, str] = assign_params(
        q=args.get('query'),
        pageSize=args.get('page_size'),
        pageToken=args.get('page_token'),
    )

    # user_id can be overridden in the args
    user_id = args.get('user_id') or client.user_id
    client.set_authorized_http(scopes=COMMAND_SCOPES['DRIVES'], subject=user_id)

    return {
        'http_request_params': http_request_params,
        'user_id': user_id,
    }


@logger
def drives_list_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    google-drive-drives-list
    Query drives list in Google Drive.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    # All drives
    prepare_drives_request_res = prepare_drives_request(client, args)
    http_request_params = prepare_drives_request_res['http_request_params']
    http_request_params['useDomainAdminAccess'] = 'true' if argToBoolean(args.get('use_domain_admin_access')) else 'false'
    http_request_params['fields'] = '*'
    url_suffix = URL_SUFFIX['DRIVE_DRIVES']
    response = client.http_request(url_suffix=url_suffix, method='GET', params=http_request_params)
    return handle_response_drive_list(response)


@logger
def drive_get_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    google-drive-drive-get
    Query a single drive in Google Drive.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    # Specific drive
    prepare_drives_request_res = prepare_drives_request(client, args)
    http_request_params = prepare_drives_request_res['http_request_params']
    http_request_params['fields'] = '*'
    url_suffix = URL_SUFFIX['DRIVE_DRIVES_ID'].format(args.get('drive_id'))
    response = client.http_request(url_suffix=url_suffix, method='GET', params=http_request_params)
    return handle_response_single_drive(response, args)


def handle_response_drive_list(response: Dict[str, Any]) -> CommandResults:

    outputs_context = []
    readable_output = ''

    drives_context = set_true_for_empty_dict(response)
    cleaned_drives_context = GSuiteClient.remove_empty_entities(drives_context)
    for current_drive in cleaned_drives_context.get('drives', []):
        outputs_context.append(current_drive)

    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_DRIVE_HEADER']: {
            OUTPUT_PREFIX['DRIVE']: outputs_context,
        },
    }

    drives_hr = prepare_drives_human_readable(outputs_context)
    readable_output += drives_hr if response.get('drives', '') \
        else HR_MESSAGES['NOT_FOUND'].format('Drives')

    if response.get('nextPageToken', ''):
        outputs[OUTPUT_PREFIX['GOOGLE_DRIVE_DRIVE_HEADER']][OUTPUT_PREFIX['PAGE_TOKEN']] = response['nextPageToken']
        readable_output += NEXT_PAGE_TOKEN.format(response.get('nextPageToken'))
    outputs = GSuiteClient.remove_empty_entities(outputs)

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def handle_response_single_drive(response: Dict[str, Any], args: Dict[str, str]):
    drive_context = set_true_for_empty_dict(response)
    outputs_context = GSuiteClient.remove_empty_entities(drive_context)

    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_DRIVE_HEADER']: {
            OUTPUT_PREFIX['DRIVE']: outputs_context,
        },
    }

    outputs = GSuiteClient.remove_empty_entities(outputs)

    readable_output = ''
    drive_hr = prepare_single_drive_human_readable(outputs_context, args)
    readable_output += drive_hr if response.get('id', '') \
        else HR_MESSAGES['NOT_FOUND'].format('Drive')

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def prepare_drives_human_readable(outputs_context: List[Dict[str, Any]]) -> str:
    """
    Prepares human readable for google-drives-list command.

    :param outputs_context: Context data.

    :return: Human readable.
    """

    return tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Drive(s)', len(outputs_context)),
                           GSuiteClient.remove_empty_entities(outputs_context),
                           ['id', 'name', 'createdTime'],
                           headerTransform=pascalToSpace,
                           removeNull=True)


def prepare_single_drive_human_readable(outputs_context: Dict[str, Any], args: Dict[str, str]) -> str:
    """
    Prepares human readable for a single drive in google-drives-list command.

    :param outputs_context: Context data.

    :return: Human readable.
    """

    fields = args.get('fields', 'id, name')
    return tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Drive(s)', 1),
                           GSuiteClient.remove_empty_entities(outputs_context),
                           [x.strip() for x in fields.split(',')],
                           headerTransform=pascalToSpace,
                           removeNull=True)


def prepare_file_read_request(client: 'GSuiteClient', args: Dict[str, str]) -> Dict[str, Any]:
    http_request_params: Dict[str, str] = assign_params(
        q=args.get('query'),
        pageSize=args.get('page_size'),
        pageToken=args.get('page_token'),
        supportsAllDrives=args.get('supports_all_drives'),
    )

    # user_id can be overridden in the args
    user_id = args.get('user_id') or client.user_id
    client.set_authorized_http(scopes=COMMAND_SCOPES['FILES'], subject=user_id)

    return {
        'client': client,
        'http_request_params': http_request_params,
        'user_id': user_id,
    }


@logger
def files_list_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    google-drive-files-list
    Query files list in Google Drive.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    # All files
    prepare_file_read_request_res = prepare_file_read_request(client, args)
    http_request_params = prepare_file_read_request_res['http_request_params']
    http_request_params['fields'] = '*'
    url_suffix = URL_SUFFIX['DRIVE_FILES']
    response = client.http_request(url_suffix=url_suffix, method='GET', params=http_request_params)
    return handle_response_files_list(response)


@logger
def file_get_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    google-drive-file-get
    Query a single file in Google Drive.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    # Specific file
    prepare_file_read_request_res = prepare_file_read_request(client, args)
    http_request_params = prepare_file_read_request_res['http_request_params']
    # Make sure we have the field "id".
    http_request_params['fields'] = 'id, ' + args.get('fields', 'id')
    url_suffix = URL_SUFFIX['DRIVE_FILES_ID'].format(args.get('file_id'))
    response = client.http_request(url_suffix=url_suffix, method='GET', params=http_request_params)
    return handle_response_single_file(response, args)


def handle_response_files_list(response: Dict[str, Any]) -> CommandResults:

    outputs_context = []
    readable_output = ''

    for current_file in response.get('files', []):
        # outputs_context.append(prepare_file_output(current_file))
        outputs_context.append(current_file)

    files_hr = prepare_files_human_readable(outputs_context)

    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_HEADER']: {
            OUTPUT_PREFIX['FILE']: outputs_context,
        },
    }
    readable_output += files_hr if response.get('files', '') \
        else HR_MESSAGES['NOT_FOUND'].format('Files')

    if response.get('nextPageToken', ''):
        outputs[OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_HEADER']][OUTPUT_PREFIX['PAGE_TOKEN']] = response['nextPageToken']
        readable_output += NEXT_PAGE_TOKEN.format(response.get('nextPageToken'))
    outputs = GSuiteClient.remove_empty_entities(outputs)

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def handle_response_single_file(response: Dict[str, Any], args: Dict[str, str]):
    outputs_context = prepare_single_file_output(response)

    file_hr = prepare_single_file_human_readable(outputs_context, args)

    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_HEADER']: {
            OUTPUT_PREFIX['FILE']: outputs_context
        }
    }
    outputs = GSuiteClient.remove_empty_entities(outputs)

    readable_output = file_hr if response.get('id', '') \
        else HR_MESSAGES['NOT_FOUND'].format('File')

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def prepare_files_human_readable(outputs_context: List[Dict[str, Any]]) -> str:
    """
    Prepares human readable for google-files-list command.

    :param outputs_context: Context data.

    :return: Human readable.
    """

    return tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('File(s)', len(outputs_context)),
                           GSuiteClient.remove_empty_entities(outputs_context),
                           ['id', 'name', 'mimeType', 'description', 'size', 'driveId',
                            'createdTime', 'modifiedTime', ],
                           headerTransform=pascalToSpace,
                           removeNull=True)


def prepare_single_file_output(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepares context output for a single file in google-files-list command.

    :param activity: Response from API.

    :return: Context output.
    """

    files_context = set_true_for_empty_dict(response)
    return GSuiteClient.remove_empty_entities(files_context)


def prepare_single_file_human_readable(outputs_context: Dict[str, Any], args: Dict[str, str]) -> str:
    """
    Prepares human readable for a single file in google-files-list command.

    :param outputs_context: Context data.

    :return: Human readable.
    """

    return tableToMarkdown(
        HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('File(s)', 1),
        GSuiteClient.remove_empty_entities(outputs_context),
        [x.strip() for x in args.get('fields', 'id').split(',')],
        headerTransform=pascalToSpace,
        removeNull=False)


def prepare_file_command_request(client: 'GSuiteClient', args: Dict[str, str], scopes: List[str]) -> Dict[str, Any]:

    http_request_params: Dict[str, str] = {}

    # user_id can be overridden in the args
    user_id = args.get('user_id') or client.user_id
    client.set_authorized_http(scopes=scopes, subject=user_id)

    return {
        'http_request_params': http_request_params,
        'user_id': user_id,
    }


@logger
def file_upload_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Upload a file to Google Drive

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    file_entry_id = args.get('entry_id')
    file_path = demisto.getFilePath(file_entry_id)

    version = 'v3'
    service_name = 'drive'
    user_id = args.get('user_id') or client.user_id
    client.set_authorized_http(scopes=COMMAND_SCOPES['FILES'], subject=user_id)
    drive_service = discovery.build(serviceName=service_name, version=version, http=client.authorized_http)
    body: Dict[str, str] = assign_params(
        parents=[args.get('parent')] if 'parent' in args else None,
        name=args.get('file_name'),
    )

    body = GSuiteClient.remove_empty_entities(body)

    media = MediaFileUpload(file_path['path'])
    file = drive_service.files().create(body=body,
                                        media_body=media,
                                        fields='*'
                                        ).execute()
    return handle_response_file_single(file, args)


@logger
def file_download_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Download a file from Google Drive

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    prepare_file_command_request(client, args, scopes=COMMAND_SCOPES['FILES'])

    version = 'v3'
    service_name = 'drive'
    drive_service = discovery.build(serviceName=service_name, version=version, http=client.authorized_http)
    request = drive_service.files().get_media(fileId=args.get('file_id'))
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while done is False:
        status, done = downloader.next_chunk()
    return fileResult(args.get('file_name'), fh.getvalue())


@logger
def file_replace_existing_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Replace an existing file in Google Drive
        google-drive-file-replace-existing

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    file_entry_id = args.get('entry_id')
    file_path = demisto.getFilePath(file_entry_id)

    version = 'v3'
    service_name = 'drive'
    drive_service = discovery.build(serviceName=service_name, version=version, http=client.authorized_http)
    media = MediaFileUpload(file_path['path'])
    file = drive_service.files().update(fileId=args.get('file_id', ''),
                                        body={},
                                        media_body=media,
                                        fields='*'
                                        ).execute()
    return handle_response_file_single(file, args)


@logger
def file_delete_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Delete a file in Google Drive

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    prepare_file_command_res = prepare_file_command_request(client, args, scopes=COMMAND_SCOPES['FILE_DELETE'])
    http_request_params = prepare_file_command_res['http_request_params']

    url_suffix = URL_SUFFIX['DRIVE_FILES_ID'].format(args.get('file_id'))
    client.http_request(url_suffix=url_suffix, method='DELETE', params=http_request_params)
    outputs_context = {
        'id': args.get('file_id'),
    }
    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_HEADER']: {
            OUTPUT_PREFIX['FILE']: outputs_context,
        }
    }

    table_hr_md = tableToMarkdown(HR_MESSAGES['DELETE_COMMAND_SUCCESS'].format('File(s)', 1),
                                  outputs_context,
                                  ['id'],
                                  headerTransform=pascalToSpace,
                                  removeNull=False)

    ret_value = CommandResults(
        outputs=outputs,
        readable_output=table_hr_md,
    )
    return ret_value


def handle_response_file_single(response: Dict[str, Any], args: Dict[str, str]) -> CommandResults:

    readable_output = ''

    outputs_context = prepare_file_single_output(response)

    files_hr = prepare_file_single_human_readable(outputs_context, args)

    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_HEADER']: {
            OUTPUT_PREFIX['FILE']: outputs_context
        }
    }
    outputs = GSuiteClient.remove_empty_entities(outputs)
    readable_output += files_hr

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def prepare_file_single_output(file_single: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepares context output for google-drive-file commands.

    :param activity: Response from API.

    :return: Context output.
    """

    ret_value = {}
    ret_value.update(file_single)
    ret_value = set_true_for_empty_dict(ret_value)

    return GSuiteClient.remove_empty_entities(ret_value)


def prepare_file_single_human_readable(outputs_context: Dict[str, Any], args: Dict[str, str]) -> str:
    """
    Prepares human readable for google-drive-file commands.

    :param outputs_context: Context data.

    :return: Human readable.
    """

    return tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('file(s)', 1),
                           GSuiteClient.remove_empty_entities(outputs_context),
                           ['id', 'name', 'mimeType', 'description', 'starred', 'trashed',
                            'parents', 'properties', 'spaces', 'version', 'webContentLink',
                            'webViewLink', 'iconLink', 'hasThumbnail', 'thumbnailLink',
                            'thumbnailVersion', 'viewedByMe', 'viewedByMeTime', 'createdTime',
                            'modifiedTime', 'modifiedByMeTime', 'modifiedByMe', 'sharedWithMeTime',
                            'sharingUser', 'owners', 'teamDriveId', 'driveId', 'lastModifyingUser',
                            'shared', 'ownedByMe', 'capabilities', 'viewersCanCopyContent',
                            'copyRequiresWriterPermission', 'writersCanShare', 'permissions',
                            'permissionIds', 'hasAugmentedPermissions', 'folderColorRgb',
                            'originalFilename', 'fullFileExtension', 'fileExtension', 'md5Checksum',
                            'size', 'quotaBytesUsed', 'headRevisionId', 'contentHints',
                            'isAppAuthorized', 'exportLinks', 'shortcutDetails', 'contentRestrictions',
                            'resourceKey', ],
                           headerTransform=pascalToSpace,
                           removeNull=False)


def prepare_file_permission_request(client: 'GSuiteClient', args: Dict[str, str], scopes: List[str]) -> Dict[str, Any]:
    # user_id can be overridden in the args
    user_id = args.get('user_id') or client.user_id
    client.set_authorized_http(scopes=scopes, subject=user_id)

    # Prepare generic HTTP request params
    http_request_params: Dict[str, str] = assign_params(
        fileId=args.get('file_id'),
        supportsAllDrives=args.get('supports_all_drives'),
        fields='*',
    )

    return {
        'client': client,
        'http_request_params': http_request_params,
        'user_id': user_id,
    }


@logger
def file_permission_list_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    List file permissions

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    # All permissions
    prepare_file_permission_request_res = prepare_file_permission_request(
        client, args, scopes=COMMAND_SCOPES['FILE_PERMISSIONS_LIST'])
    http_request_params: Dict[str, str] = prepare_file_permission_request_res['http_request_params']

    http_request_params.update(
        assign_params(
            pageSize=args.get('page_size'),
            pageToken=args.get('page_token'),
            fields='*'
        )
    )

    response = client.http_request(url_suffix=URL_SUFFIX['FILE_PERMISSIONS_LIST'], method='GET', params=http_request_params)
    return handle_response_permissions_list(response, args)


@logger
def file_permission_create_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Create file permissions

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    prepare_file_permission_request_res = prepare_file_permission_request(
        client, args, scopes=COMMAND_SCOPES['FILE_PERMISSIONS_CRUD'])
    http_request_params: Dict[str, str] = prepare_file_permission_request_res['http_request_params']

    http_request_params.update(
        assign_params(
            sendNotificationEmail=args.get('send_notification_email'),
        )
    )

    body: Dict[str, str] = assign_params(
        role=args.get('role'),
        type=args.get('type'),
        domain=args.get('domain'),
        emailAddress=args.get('email_address'),
    )

    url_suffix = URL_SUFFIX['FILE_PERMISSION_CREATE'].format(args.get('file_id'))
    response = client.http_request(url_suffix=url_suffix, method='POST', params=http_request_params, body=body)
    return handle_response_permission_single(response, args)


@logger
def file_permission_update_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Update file permissions

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    prepare_file_permission_request_res = prepare_file_permission_request(
        client, args, scopes=COMMAND_SCOPES['FILE_PERMISSIONS_CRUD'])
    http_request_params = prepare_file_permission_request_res['http_request_params']

    body: Dict[str, str] = assign_params(
        role=args.get('role'),
        expirationTime=args.get('expiration_time'),
    )

    url_suffix = URL_SUFFIX['FILE_PERMISSION_UPDATE'].format(args.get('file_id'), args.get('permission_id'))
    response = client.http_request(url_suffix=url_suffix, method='PATCH', params=http_request_params, body=body)
    return handle_response_permission_single(response, args)


@logger
def file_permission_delete_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Delete file permissions

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """

    prepare_file_permission_request_res = prepare_file_permission_request(
        client, args, scopes=COMMAND_SCOPES['FILE_PERMISSIONS_CRUD'])
    http_request_params = prepare_file_permission_request_res['http_request_params']

    url_suffix = URL_SUFFIX['FILE_PERMISSION_DELETE'].format(args.get('file_id'), args.get('permission_id'))
    client.http_request(url_suffix=url_suffix, method='DELETE', params=http_request_params)

    outputs_context: Dict = {
        'fileId': args.get('file_id'),
        'id': args.get('permission_id'),
    }
    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_PERMISSION_HEADER']: {
            OUTPUT_PREFIX['FILE_PERMISSION']: outputs_context,
        }
    }

    table_hr_md = tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Permission(s)', 1),
                                  outputs_context,
                                  ['fileId', 'id'],
                                  headerTransform=pascalToSpace,
                                  removeNull=False)

    return CommandResults(
        outputs=outputs,
        readable_output=table_hr_md,
    )


def handle_response_permissions_list(response: Dict[str, Any], args: Dict[str, str]) -> CommandResults:

    outputs_context = []
    readable_output = ''

    for current_permission in response.get('permissions', []):
        outputs_context.append(prepare_permission_output(current_permission))

    files_hr = prepare_permissions_human_readable(outputs_context, args)

    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_PERMISSION_HEADER']: {
            OUTPUT_PREFIX['FILE_PERMISSION']: outputs_context,
        },
    }
    readable_output += files_hr if response.get('permissions', '') \
        else HR_MESSAGES['NOT_FOUND'].format('Permissions')

    if response.get('nextPageToken', ''):
        outputs[OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_PERMISSION_HEADER']][OUTPUT_PREFIX['PAGE_TOKEN']] = response['nextPageToken']
        readable_output += NEXT_PAGE_TOKEN.format(response.get('nextPageToken'))
    outputs = GSuiteClient.remove_empty_entities(outputs)

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def prepare_permissions_human_readable(outputs_context: List[Dict[str, Any]], args: Dict[str, str]) -> str:
    """
    Prepares human readable for google-drive-file-permissions-list command.

    :param outputs_context: Context data.

    :return: Human readable.
    """

    return tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Permission(s)', len(outputs_context)),
                           GSuiteClient.remove_empty_entities(outputs_context),
                           ['id', 'type', 'role', 'emailAddress', 'displayName', 'deleted'],
                           headerTransform=pascalToSpace,
                           removeNull=False)


def handle_response_permission_single(response: Dict[str, Any], args: Dict[str, str]) -> CommandResults:

    readable_output = ''

    outputs_context = prepare_permission_output(response)

    files_hr = prepare_permission_human_readable(outputs_context, args)

    outputs: Dict = {
        OUTPUT_PREFIX['GOOGLE_DRIVE_FILE_PERMISSION_HEADER']: {
            OUTPUT_PREFIX['FILE_PERMISSION']: outputs_context
        }
    }
    outputs = GSuiteClient.remove_empty_entities(outputs)
    readable_output += files_hr

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def prepare_permission_output(permission: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepares context output for google-drive-file-permissions commands.

    :param activity: Response from API.

    :return: Context output.
    """

    ret_value = {}
    ret_value.update(permission)
    ret_value = set_true_for_empty_dict(ret_value)

    return GSuiteClient.remove_empty_entities(ret_value)


def prepare_permission_human_readable(outputs_context: Dict[str, Any], args: Dict[str, str]) -> str:
    """
    Prepares human readable for google-drive-file-permissions commands.

    :param outputs_context: Context data.

    :return: Human readable.
    """

    return tableToMarkdown(HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Permission(s)', 1),
                           GSuiteClient.remove_empty_entities(outputs_context),
                           ['id', 'type', 'role', 'domain', 'emailAddress', 'displayName', 'deleted'],
                           removeNull=False,
                           headerTransform=pascalToSpace)


@logger
def drive_activity_list_command(client: 'GSuiteClient', args: Dict[str, str]) -> CommandResults:
    """
    Query past activity in Google Drive.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    user_id = args.get('user_id', '')
    body = prepare_body_for_drive_activity(args)

    client.set_authorized_http(scopes=COMMAND_SCOPES['DRIVE_ACTIVITY'], subject=user_id)
    response = client.http_request(full_url=URLS['DRIVE_ACTIVITY'], method='POST', body=body)

    outputs_context = []
    readable_output = ''

    for activity in response.get('activities', []):
        outputs_context.append(prepare_drive_activity_output(activity))

    drive_activity_hr = prepare_drive_activity_human_readable(outputs_context)

    outputs: Dict = {
        OUTPUT_PREFIX['DRIVE_ACTIVITY_LIST']: outputs_context
    }
    if response.get('nextPageToken', ''):
        outputs[OUTPUT_PREFIX['DRIVE_ACTIVITY_LIST_PAGE_TOKEN']] = {'nextPageToken': response['nextPageToken']}
        readable_output += NEXT_PAGE_TOKEN.format(response.get('nextPageToken'))
    outputs = GSuiteClient.remove_empty_entities(outputs)
    readable_output += drive_activity_hr if response.get('activities', '') \
        else HR_MESSAGES['NOT_FOUND'].format('Drive Activity')

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def fetch_incidents(client: 'GSuiteClient', last_run: Dict, params: Dict, is_test: bool = False) -> \
        Tuple[Optional[list], Optional[dict]]:
    """
    Prepares incidents from past activity in Google Drive.

    :param client: Client object.
    :param last_run: A dict with a key containing the latest incident created time we got
        from last fetch
    :param params: arguments for fetch-incident.
    :param is_test: True if fetch-incident is called from test-module.

    :return: A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR.
    """
    # Validating params for fetch-incidents.
    validate_params_for_fetch_incidents(params)

    last_fetch = last_run['last_fetch'] if last_run.get('last_fetch') else date_to_timestamp(
        params.get('first_fetch_interval'))

    body = prepare_args_for_fetch_incidents(last_fetch, params)

    incidents: List[Dict[str, Any]] = []

    client.set_authorized_http(scopes=COMMAND_SCOPES['DRIVE_ACTIVITY'], subject=params.get('user_id'))
    response = client.http_request(body=body, full_url=URLS['DRIVE_ACTIVITY'],
                                   method='POST')

    activities = response.get('activities', [])
    activities = activities[:params.get('max_fetch', 50)]

    for activity in activities:
        # Flatting keys for grid fields.
        flatten_targets_keys_for_fetch_incident(activity)
        actors_type_keys_for_fetch_incident(activity)
        flatten_permission_change_keys_for_fetch_incident(
            activity.get('primaryActionDetail', {}).get('permissionChange', {}))
        flatten_move_keys_for_fetch_incident(activity.get('primaryActionDetail', {}).get('move', {}))
        flatten_comment_mentioned_user_keys_for_fetch_incident(
            activity.get('primaryActionDetail', {}).get('comment', {}))

        # Setting incident name from primary action details.
        action_key = list(activity.get('primaryActionDetail', {}).keys())
        # Activity contain only one primary action as per G-API.
        incident_name = pascalToSpace(ACTION_MAPPINGS.get(action_key[0], action_key[0]) if action_key else '')

        incident = {
            'name': incident_name,
            'occurred': activity.get('timestamp', activity.get('timeRange', {}).get('endTime', '')),
            'rawJSON': json.dumps(activity)
        }
        incidents.append(incident)

        timestamp = int(
            dateparser.parse(  # type: ignore
                activity.get('timestamp', activity.get('timeRange', {}).get('endTime', ''))).timestamp() * 1000)

        if timestamp > last_fetch:
            last_fetch = timestamp
    if is_test:
        return None, None
    return incidents, {'last_fetch': last_fetch}


def main() -> None:
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Commands dictionary
    commands: Dict[str, Callable] = {
        'google-drive-create': drive_create_command,
        'google-drive-changes-list': drive_changes_list_command,
        'google-drive-activity-list': drive_activity_list_command,

        'google-drive-drives-list': drives_list_command,
        'google-drive-drive-get': drive_get_command,

        'google-drive-files-list': files_list_command,
        'google-drive-file-get': file_get_command,

        'google-drive-file-upload': file_upload_command,
        'google-drive-file-download': file_download_command,
        'google-drive-file-replace-existing': file_replace_existing_command,
        'google-drive-file-delete': file_delete_command,

        'google-drive-file-permissions-list': file_permission_list_command,
        'google-drive-file-permission-create': file_permission_create_command,
        'google-drive-file-permission-update': file_permission_update_command,
        'google-drive-file-permission-delete': file_permission_delete_command,
    }
    command = demisto.command()

    try:
        params = demisto.params()
        service_account_dict = GSuiteClient.safe_load_non_strict_json(params.get('user_service_account_json'))
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        headers = {
            'Content-Type': 'application/json'
        }

        # prepare client class object
        gsuite_client = GSuiteClient(service_account_dict,
                                     base_url='https://www.googleapis.com/', verify=verify_certificate, proxy=proxy,
                                     headers=headers,
                                     user_id=params.get('user_id', ''))

        # Trim the arguments
        args = GSuiteClient.strip_dict(demisto.args())

        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            result = test_module(gsuite_client, demisto.getLastRun(), params)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':

            incidents, next_run = fetch_incidents(gsuite_client,
                                                  last_run=demisto.getLastRun(),
                                                  params=params)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](gsuite_client, args))

    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


from GSuiteApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
