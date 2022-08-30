import pytest

from DeleteContent import get_and_delete_needed_ids


XSOAR_IDS_FULL_STATE = {
    'Installed Packs': ['installed_pack_id1', 'installed_pack_id2'],
    'Lists': ['list1', 'list2'],
    'Jobs': ['job1', 'job2']
}


def mock_demisto_responses(command_name, command_args, xsoar_ids_state):
    """Mock function for demisto responses to api calls according to xsoar ids state.

    Args:
        command_name (str): The command name sent to the executeCommand demisto function.
        command_args (dict): The command args sent to the executeCommand demisto function.
        xsoar_ids_state (dict): A representation for the content ids in an xsoar instance.

    Returns:
        status, demisto response
    """
    command_uri = command_args.get('uri')
    if command_uri == '/jobs/search':
        if command_args.get('body', {}).get('size') == 1:
            job_name = command_args.get('body', {}).get('query').split('name:"')[1].split('"')[0]
            if job_name in xsoar_ids_state.get('Jobs'):
                return True, {'data': [{'name': job_name, 'id': job_name}]}
            else:
                return False, 'Id not found'
        else:
            return True, {'data': [{'name': job_name, 'id': job_name} for job_name in xsoar_ids_state.get('Jobs')]}
    elif command_uri.startswith('jobs/') and command_name == 'demisto-api-delete':
        job_name = command_uri.split('jobs/')[1]
        if job_name in xsoar_ids_state.get('Jobs'):
            return True, {'data': [{'name': job_name, 'id': job_name}]}
        else:
            return False, 'Id not found'
    elif command_uri.startswith('/lists/download/') or command_uri == '/lists/delete':
        if command_uri.startswith('/lists/download/'):
            list_name = command_uri.split('/lists/download/')[1]
        else:
            list_name = command_args.get('body').get('id')
        return (True, list_name) if list_name in xsoar_ids_state.get('Lists') else (False, 'Id not found')
    elif command_uri == '/lists/names':
        return True, xsoar_ids_state.get('Lists')
    elif command_uri.startswith('/contentpacks/installed/'):
        pack_name = command_uri.split('/contentpacks/installed/')[1]
        return (True, {'id': pack_name}) if pack_name in xsoar_ids_state.get('Installed Packs') else (False, 'Id not found')
    elif command_uri.startswith('/contentpacks/installed-expired'):
        return True, [{'id': pack_name} for pack_name in xsoar_ids_state.get('Installed Packs')]
    else:
        return False, 'Command Not Mocked.'


@pytest.mark.parametrize('args, xsoar_ids_state, expected_outputs', [
    pytest.param(
        {'dry_run': 'false', 'delete_unspecified': 'true'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': [], 'List': [], 'Pack': []},
            'successfully_deleted': {'Job': ['job1', 'job2'], 'List': ['list1', 'list2'],
                                     'Pack': ['installed_pack_id1', 'installed_pack_id2']},
            'status': 'Completed'}, id='delete everything.'),
    pytest.param(
        {'dry_run': 'false', 'include_job_ids': 'job1',
         'include_list_ids': 'list2',
         'include_pack_ids': 'installed_pack_id1',
         'delete_unspecified': 'false'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': [], 'List': [], 'Pack': []},
            'successfully_deleted': {'Job': ['job1'], 'List': ['list2'], 'Pack': ['installed_pack_id1']},
            'status': 'Completed'}, id='delete only included ids.'),
    pytest.param(
        {'dry_run': 'false', 'exclude_job_ids': 'job1',
         'exclude_list_ids': 'list2',
         'exclude_pack_ids': 'installed_pack_id1',
         'delete_unspecified': 'false'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': ['job1'], 'List': ['list2'], 'Pack': ['installed_pack_id1']},
            'successfully_deleted': {'Job': ['job2'], 'List': ['list1'], 'Pack': ['installed_pack_id2']},
            'status': 'Completed'}, id='dont delete excluded ids.'),
    pytest.param(
        {'dry_run': 'false', 'exclude_job_ids': 'job3', 'delete_unspecified': 'true'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': [], 'List': [], 'Pack': []},
            'successfully_deleted': {'Job': ['job1', 'job2'], 'List': ['list1', 'list2'],
                                     'Pack': ['installed_pack_id1', 'installed_pack_id2']},
            'status': 'Completed'}, id='exclude unfound id'),
    pytest.param(
        {'dry_run': 'false', 'include_job_ids': 'job3', 'delete_unspecified': 'false'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': ['job3'], 'List': [], 'Pack': []},
            'successfully_deleted': {'Job': [], 'List': [], 'Pack': []},
            'status': 'Failed'}, id='include unfound id'),
    pytest.param(
        {'dry_run': 'false', 'include_pack_ids': 'Base', 'delete_unspecified': 'false'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': [], 'List': [], 'Pack': ['Base']},
            'successfully_deleted': {'Job': [], 'List': [], 'Pack': []},
            'status': 'Failed'}, id='try deleting always excluded ids')
])
def test_get_and_delete_needed_ids(mocker, args, xsoar_ids_state, expected_outputs):
    """
    Given:
        Xsoar ids state.
        Include_ids and exclude_ids lists.

    When:
        Running get_and_delete_needed_ids with dry_run set to false.

    Then:
         Assert deleted id lists are correct.
    """
    def execute_command_mock(command_name, command_args, fail_on_error=False):
        status, response = mock_demisto_responses(command_name, command_args, xsoar_ids_state)
        return status, {'response': response}

    mocker.patch("DeleteContent.execute_command", side_effect=execute_command_mock)

    result = get_and_delete_needed_ids(args)
    assert result.outputs.get('not_deleted') == expected_outputs.get('not_deleted')
    assert result.outputs.get('successfully_deleted') == expected_outputs.get('successfully_deleted')
    assert result.outputs.get('status') == expected_outputs.get('status')


@pytest.mark.parametrize('args, xsoar_ids_state, expected_outputs, call_count', [
    pytest.param(
        {'dry_run': 'true'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': [], 'List': [], 'Pack': []},
            'successfully_deleted': {'Job': ['job1', 'job2'], 'List': ['list1', 'list2'],
                                     'Pack': ['installed_pack_id1', 'installed_pack_id2']},
            'status': 'Dry run, nothing really deleted.'}, 9, id='dry run, delete everything.'),
    pytest.param(
        {'dry_run': 'false'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'Job': [], 'List': [], 'Pack': []},
            'successfully_deleted': {'Job': ['job1', 'job2'], 'List': ['list1', 'list2'],
                                     'Pack': ['installed_pack_id1', 'installed_pack_id2']},
            'status': 'Completed'}, 15, id='dry run, delete everything.')
])
def test_dry_run_delete(mocker, args, xsoar_ids_state, expected_outputs, call_count):
    """
    Given:
        Xsoar ids state.
        dry_run flag.

    When:
        Running get_and_delete_needed_ids with dry_run toggled.

    Then:
         Assert deleted id lists are correct.
         Assert call count to executeCommand API does not include calls for actual deletion.
    """
    def execute_command_mock(command_name, command_args, fail_on_error=False):
        status, response = mock_demisto_responses(command_name, command_args, xsoar_ids_state)
        return status, {'response': response}

    execute_mock = mocker.patch("DeleteContent.execute_command", side_effect=execute_command_mock)

    result = get_and_delete_needed_ids(args)
    assert result.outputs.get('not_deleted') == expected_outputs.get('not_deleted')
    assert result.outputs.get('successfully_deleted') == expected_outputs.get('successfully_deleted')
    assert result.outputs.get('status') == expected_outputs.get('status')
    assert execute_mock.call_count == call_count
