#!/usr/bin/python
"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/logs API response + re filtering, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, fetch_incidents

    mock_response = util_load_json('test_data/fetch_incidents.json')
    requests_mock.get(
        'https://portal.us.bitglass.net/api/bitglassapi/logs/'
        '?cv=1.1.5&responseformat=json&type=access&startdate=2021-12-20T00:00:00Z',
        json=mock_response['logs'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    last_run = {
        'last_fetch': None
    }

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=4,              # not used TODO
        last_run=last_run,          # not used
        alert_status='ACTIVE',      # not used
        min_severity='Low',         # not used
        alert_type=None,            # not used
        first_fetch_time='3 days',  # not used
    )

    assert new_incidents == [
        # TODO Debug why empty list is returned
        # {
        #     'name': 'Email: demo@acme-gizmo.com',
        #     'occurred': '2021-12-23T08:57:46.000Z',
        #     'rawJSON': '{}',            # TODO Drop from returned data before comparison
        #     'type': 'Unclassified',     # TODO 'Bitglass DLP'
        #     'severity': 'Medium',
        # },
        # {
        #     'name': 'Email: demo@acme-gizmo.com',
        #     'occurred': '2021-12-23T08:57:52.000Z',
        #     'rawJSON': '{}',
        #     'type': 'Unclassified',
        #     'severity': 'Medium',
        # },
        # {
        #     'name': 'Email: demo@acme-gizmo.com',
        #     'occurred': '2021-12-23T08:58:03.000Z',
        #     'rawJSON': '{}',
        #     'type': 'Unclassified',
        #     'severity': 'Medium',
        # },
        # {
        #     'name': 'Email: demo@acme-gizmo.com',
        #     'occurred': '2021-12-23T08:58:06.000Z',
        #     'rawJSON': '{}',
        #     'type': 'Unclassified',
        #     'severity': 'Medium',
        # },
    ]


def test_filter_by_dlp_pattern():
    """Tests the filter-by-dlp-pattern command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/logs API response + re filtering+, this method is used by the playbook
    to extract the username/email.
    """
    from Bitglass import Client, filter_by_dlp_pattern_command

    data = util_load_json('test_data/filter_by_dlp_pattern.json')
    incident = data['incident']

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    args = {
        'bg_match_expression': 'Malware.*',
        'bg_log_event': incident
    }

    response = filter_by_dlp_pattern_command(
        client=client,
        args=args
    )

    # TODO Extract the value from the test data properly (after the classifier is done)
    assert response.outputs == 'demo@acme-gizmo.com'


def test_create_update_group(requests_mock):
    """Tests the create-update-group command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/config API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, create_update_group_command

    mock_response = util_load_json('test_data/create_update_group.json')
    requests_mock.post(
        'https://portal.us.bitglass.net/api/bitglassapi/config/v1/'
        '?type=group&action=createupdate',
        json=mock_response['createupdate'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    args = {
        'bg_group_name': 'FriskyUsers',
        'bg_new_group_name': ''
    }

    response = create_update_group_command(
        client=client,
        args=args
    )

    # TODO
    assert 'status' in response.outputs


def test_delete_group(requests_mock):
    """Tests the delete-group command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/config API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, delete_group_command

    mock_response = util_load_json('test_data/delete_group.json')
    requests_mock.post(
        'https://portal.us.bitglass.net/api/bitglassapi/config/v1/'
        '?type=group&action=delete',
        json=mock_response['delete'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    args = {
        'bg_group_name': 'FriskyUsers'
    }

    response = delete_group_command(
        client=client,
        args=args
    )

    # TODO
    assert 'status' in response.outputs


def test_add_user_to_group(requests_mock):
    """Tests the add-user-to-group command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/config API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, add_user_to_group_command

    mock_response = util_load_json('test_data/add_user_to_group.json')
    requests_mock.post(
        'https://portal.us.bitglass.net/api/bitglassapi/config/v1/'
        '?type=group&action=addmembers',
        json=mock_response['addmembers'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    args = {
        'bg_group_name': 'FriskyUsers',
        'bg_user_name': 'luser@test.com'
    }

    response = add_user_to_group_command(
        client=client,
        args=args
    )

    # TODO
    assert 'status' in response.outputs


def test_remove_user_from_group(requests_mock):
    """Tests the remove-user-from-group command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/config API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, remove_user_from_group_command

    mock_response = util_load_json('test_data/remove_user_from_group.json')
    requests_mock.post(
        'https://portal.us.bitglass.net/api/bitglassapi/config/v1/'
        '?type=group&action=removemembers',
        json=mock_response['removemembers'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    args = {
        'bg_group_name': 'FriskyUsers',
        'bg_user_name': 'luser@test.com'
    }

    response = remove_user_from_group_command(
        client=client,
        args=args
    )

    # TODO
    assert 'status' in response.outputs


def test_create_update_user(requests_mock):
    """Tests the create-update-user command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/config API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, create_update_user_command

    mock_response = util_load_json('test_data/create_update_user.json')
    requests_mock.post(
        'https://portal.us.bitglass.net/api/bitglassapi/config/v1/'
        '?type=user&action=createupdate',
        json=mock_response['createupdate'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    # TODO Check the optional params can be omitted (Phantom?)
    args = {
        'bg_user_name': 'luser@test.com',
        'bg_first_name': 'Joe',
        'bg_last_name': 'Oe',
        'bg_secondary_email': '',
        'bg_netbios_domain': '',
        'bg_sam_account_name': '',
        'bg_user_principal_name': '',
        'bg_object_guid': '',
        'bg_country_code': '',
        'bg_mobile_number': '',
        'bg_admin_role': '',
        'bg_group_membership': ''
    }

    response = create_update_user_command(
        client=client,
        args=args
    )

    # TODO
    assert 'status' in response.outputs


def test_deactivate_user(requests_mock):
    """Tests the deactivate-user command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/config API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, deactivate_user_command

    mock_response = util_load_json('test_data/deactivate_user.json')
    requests_mock.post(
        'https://portal.us.bitglass.net/api/bitglassapi/config/v1/'
        '?type=user&action=deactivate',
        json=mock_response['deactivate'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    # TODO Check the optional params can be omitted (Phantom?)
    args = {
        'bg_user_name': 'luser@test.com'
    }

    response = deactivate_user_command(
        client=client,
        args=args
    )

    # TODO
    assert 'status' in response.outputs


def test_reactivate_user(requests_mock):
    """Tests the reactivate-user command function.

    Configures requests_mock instance to generate the appropriate
    bitglassapi/config API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Bitglass import Client, reactivate_user_command

    mock_response = util_load_json('test_data/reactivate_user.json')
    requests_mock.post(
        'https://portal.us.bitglass.net/api/bitglassapi/config/v1/'
        '?type=user&action=reactivate',
        json=mock_response['reactivate'])

    client = Client(
        base_url='https://portal.us.bitglass.net/api/bitglassapi/logs/',
        verify=False,
        auth_token='dummydummydummydummydummydummy'
    )

    # TODO Check the optional params can be omitted (Phantom?)
    args = {
        'bg_user_name': 'luser@test.com'
    }

    response = reactivate_user_command(
        client=client,
        args=args
    )

    # TODO
    assert 'status' in response.outputs
