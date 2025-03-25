import demistomock as demisto  # noqa: F401
import json
import pytest

from Workday_IAM import Client, fetch_incidents, LAST_DAY_OF_WORK_FIELD, EMPLOYMENT_STATUS_FIELD, \
    PREHIRE_FLAG_FIELD, REHIRED_EMPLOYEE_FIELD, AD_ACCOUNT_STATUS_FIELD, HIRE_DATE_FIELD, TERMINATION_TRIGGER_FIELD, \
    CONVERSION_HIRE_FIELD, EMAIL_ADDRESS_FIELD, EMPLOYEE_ID_FIELD, REHIRE_USER_EVENT_TYPE, SOURCE_PRIORITY_FIELD
from test_data.event_results import events_result

EVENT_RESULTS = events_result


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - raw response of report results
    When
    - mock the demisto map object
    - mock getting demisto indicators
    Then
    - validate the incidents values
    """
    client_response = util_load_json('test_data/json_raw_response.json')
    mapped_user = util_load_json('test_data/mapped_user.json')

    mocker.patch.object(Client, 'get_full_report', return_value=client_response.get('Report_Entry'))
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=({}, {}, {}))
    mocker.patch.object(demisto, 'mapObject', return_value=mapped_user)
    client = Client(base_url="", verify="verify", headers={}, proxy=False, ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "", "%m/%d/%Y", LAST_DAY_OF_WORK_FIELD, None, None, 1)
    assert fetch_events == EVENT_RESULTS


def test_fetch_incidents_email_change(requests_mock, mocker):
    """
    Given
    - A workday full report of employees.
    When
    - An email address change is detected for the user rrahardj@paloaltonetworks.com.
    Then
    - Make sure the IAM - Update User event is returned as expected.
    """
    from test_data.fetch_incidents_email_change_mock_data import full_report, mapped_workday_user, \
        employee_id_to_user_profile, email_to_user_profile, event_data

    requests_mock.get('https://test.com', json=full_report)
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=({}, employee_id_to_user_profile,
                                                                    email_to_user_profile))
    mocker.patch.object(demisto, 'mapObject', return_value=mapped_workday_user)
    client = Client(base_url="", verify="verify", headers={}, proxy=False, ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "https://test.com", "%m/%d/%Y", LAST_DAY_OF_WORK_FIELD, None, None, 1)
    assert fetch_events == event_data


def test_fetch_incidents_employee_id_change(requests_mock, mocker):
    """
    Given
    - A workday full report of employees.
    When
    - An employee id change is detected for the user rrahardj@paloaltonetworks.com.
    Then
    - Make sure the IAM - Update User event is returned as expected.
    """
    from test_data.fetch_incidents_employee_id_change_mock_data import full_report, mapped_workday_user, \
        employee_id_to_user_profile, email_to_user_profile, event_data

    requests_mock.get('https://test.com', json=full_report)
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=({}, employee_id_to_user_profile,
                                                                    email_to_user_profile))
    mocker.patch.object(demisto, 'mapObject', return_value=mapped_workday_user)
    client = Client(base_url="", verify="verify", headers={}, proxy=False,
                    ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "https://test.com", "%m/%d/%Y", LAST_DAY_OF_WORK_FIELD, None, None, 1)
    assert fetch_events == event_data


def test_fetch_incidents_orphan_user(requests_mock, mocker):
    """
    Given
    - An empty workday report of employees.
    When
    - A user profile with email rrahardjo@paloaltonetworks.com exists on XSOAR.
    Then
    - Ensure an IAM - Terminate User event is returned for this user.
    """
    from test_data.fetch_incidents_orphan_user_mock_data import full_report, email_to_user_profile, event_data

    requests_mock.get('https://test.com', json=full_report)
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=({}, {}, email_to_user_profile))
    client = Client(base_url="", verify="verify", headers={}, proxy=False,
                    ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "https://test.com", "%m/%d/%Y", LAST_DAY_OF_WORK_FIELD, None, None, 1)
    assert fetch_events == event_data


def test_fetch_incidents_source_priority(requests_mock, mocker):
    """
    Given
    - A workday full report of employees.
    When
    - Workday IAM configured source priority is 2.
    - A user profile with email rrahardjo@paloaltonetworks.com has a source priority 1.
    Then
    - Ensure the event for rrahardjo@paloaltonetworks.com is dropped.
    """
    from test_data.fetch_incidents_source_priority_mock_data import full_report, email_to_user_profile, \
        employee_id_to_user_profile, mapped_workday_user, event_data

    requests_mock.get('https://test.com', json=full_report)
    mocker.patch.object(demisto, 'mapObject', return_value=mapped_workday_user)
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=({}, employee_id_to_user_profile,
                                                                    email_to_user_profile))
    client = Client(base_url="", verify="verify", headers={}, proxy=False,
                    ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "https://test.com", "%m/%d/%Y", LAST_DAY_OF_WORK_FIELD, None, None,
                                   source_priority=2)
    assert fetch_events == event_data


def test_fetch_incidents_partial_name_match(requests_mock, mocker):
    """
    Given
    - A workday full report of employees.
    When
    - A new hire is detected with the same display name as an existing active user.
    Then
    - Ensure an "IAM - Sync user" event is detected with the partial name match details.
    """
    from test_data.fetch_incidents_partial_name_match_mock_data import full_report, email_to_user_profile, \
        employee_id_to_user_profile, display_name_to_user_profile, mapped_workday_user, event_data

    requests_mock.get('https://test.com', json=full_report)
    mocker.patch.object(demisto, 'mapObject', return_value=mapped_workday_user)
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=(display_name_to_user_profile,
                                                                    employee_id_to_user_profile,
                                                                    email_to_user_profile))
    mocker.patch('Workday_IAM.get_orphan_users', return_value=[])  # skip the orphan user detection
    client = Client(base_url="", verify="verify", headers={}, proxy=False,
                    ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "https://test.com", "%m/%d/%Y", LAST_DAY_OF_WORK_FIELD, None, None, 1)
    assert fetch_events == event_data


@pytest.mark.parametrize(
    'demisto_user, workday_user, expected_result',
    [
        # a pre-hired employee with no employment status, not synced into XSOAR - should return True
        (None, {PREHIRE_FLAG_FIELD: "True", EMPLOYMENT_STATUS_FIELD: ""}, True),

        # non-terminated, active employee, not synced into XSOAR - should return True
        (None, {EMPLOYMENT_STATUS_FIELD: "active", LAST_DAY_OF_WORK_FIELD: "12/12/2100"}, True),

        # non-empty demisto_user - should return False
        ('mocked_non_empty_demisto_user', 'mocked_workday_user', False),

        # non pre-hired, terminated employee - should return False
        (None, {PREHIRE_FLAG_FIELD: "False", EMPLOYMENT_STATUS_FIELD: "Terminated",
                LAST_DAY_OF_WORK_FIELD: "12/12/2020"}, False)
    ]
)
def test_is_new_hire_event(demisto_user, workday_user, expected_result):
    from Workday_IAM import is_new_hire_event
    assert is_new_hire_event(demisto_user, workday_user, LAST_DAY_OF_WORK_FIELD) == expected_result


@pytest.mark.parametrize(
    'demisto_user, workday_user, expected_result',
    [
        # not a pre-hire, employment status is "terminated" - should return True
        ({'mocked_demisto_user': ''}, {PREHIRE_FLAG_FIELD: "False", EMPLOYMENT_STATUS_FIELD: "Terminated",
                                       LAST_DAY_OF_WORK_FIELD: "12/12/2100"}, True),

        # non terminated but last day of work is in the past - should return True
        ({'mocked_demisto_user': ''}, {EMPLOYMENT_STATUS_FIELD: "active", LAST_DAY_OF_WORK_FIELD: "12/12/2020"}, True),

        # no demisto_user - should return False
        (None, 'mocked_workday_user', False),

        # demisto_user is already disabled in AD - should return False
        ({'adaccountstatus': 'Disabled'}, 'mocked_workday_user', False),

        # active, non pre-hired user with future last day of work - should return False
        ({'mocked_demisto_user': ''}, {PREHIRE_FLAG_FIELD: "False", EMPLOYMENT_STATUS_FIELD: "Active",
                                       LAST_DAY_OF_WORK_FIELD: "12/12/2100"}, False),

        # active, pre-hired user with future last day of work - should return False
        ({'mocked_demisto_user': ''}, {PREHIRE_FLAG_FIELD: "True", EMPLOYMENT_STATUS_FIELD: "Active",
                                       LAST_DAY_OF_WORK_FIELD: "12/12/2100"}, False),

        # pre-hired user with future last day of work - should return False
        ({'mocked_demisto_user': ''}, {PREHIRE_FLAG_FIELD: "True", EMPLOYMENT_STATUS_FIELD: "Terminated",
                                       LAST_DAY_OF_WORK_FIELD: "12/12/2100"}, False)
    ]
)
def test_is_termination_event(demisto_user, workday_user, expected_result):
    from Workday_IAM import is_termination_event
    assert is_termination_event(workday_user, demisto_user, LAST_DAY_OF_WORK_FIELD) == expected_result


@pytest.mark.parametrize(
    'demisto_user, workday_user, changed_fields, expected_result',
    [
        # a pre-hired + rehired employee, non empty changed_fields - should return True
        ({'adaccountstatus': 'Disabled'}, {PREHIRE_FLAG_FIELD: "True",
                                           REHIRED_EMPLOYEE_FIELD: "Yes"}, 'mocked_changed_fields', True),

        # a pre-hired + rehired employee, no changed_fields (already synced into XSOAR) - should return False
        ({'adaccountstatus': 'Disabled'}, {PREHIRE_FLAG_FIELD: "True",
                                           EMPLOYMENT_STATUS_FIELD: ""}, None, False),

        # no demisto_user - should return False
        (None, 'mocked_workday_user', None, False),

        # demisto_user AD status is not disabled - should return False
        ({'adaccountstatus': 'Pending'}, 'mocked_workday_user', None, False),

        # non pre-hired / non rehired employee, non empty changed_fields - should return False
        ({'adaccountstatus': 'Disabled'}, {PREHIRE_FLAG_FIELD: "False",
                                           REHIRED_EMPLOYEE_FIELD: "No"}, 'mocked_changed_fields', False),
    ]
)
def test_is_rehire_event(demisto_user, workday_user, changed_fields, expected_result):
    from Workday_IAM import is_rehire_event
    assert is_rehire_event(demisto_user, workday_user, LAST_DAY_OF_WORK_FIELD) == expected_result


@pytest.mark.parametrize(
    'demisto_user, workday_user, days_before_hire_to_enable_ad, expected_result',
    [
        # a pending demisto user, workday user exceeded threshold to enable AD - should return True
        ({AD_ACCOUNT_STATUS_FIELD: 'Pending'}, {HIRE_DATE_FIELD: "12/12/2020"}, 2, True),

        # a pending demisto user, no threshold to enable AD - should return True
        ({AD_ACCOUNT_STATUS_FIELD: 'Pending'}, {}, None, True),

        # no demisto_user - should return False
        (None, 'mocked_workday_user', None, False),

        # did not exceed threshold date - should return False
        ({AD_ACCOUNT_STATUS_FIELD: 'Pending'}, {HIRE_DATE_FIELD: "12/12/2200"}, 2, False),

        # demisto_user AD status is not pending - should return False
        ({AD_ACCOUNT_STATUS_FIELD: 'Disabled'}, 'mocked_workday_user', None, False)
    ]
)
def test_is_ad_activation_event(demisto_user, workday_user, days_before_hire_to_enable_ad, expected_result):
    from Workday_IAM import is_ad_activation_event
    assert is_ad_activation_event(demisto_user, workday_user, days_before_hire_to_enable_ad) == expected_result


@pytest.mark.parametrize(
    'demisto_user, workday_user, days_before_hire_to_enable_ad, source_priority, expected_result',
    [
        # source priority field is different than Workday's (conversion hire) - should return False
        ({AD_ACCOUNT_STATUS_FIELD: 'Enabled', SOURCE_PRIORITY_FIELD: 2}, {HIRE_DATE_FIELD: "12/12/2035"}, 2, 1, False),

        # A conversion hire field is True - should return False
        ({AD_ACCOUNT_STATUS_FIELD: 'Enabled', CONVERSION_HIRE_FIELD: True, SOURCE_PRIORITY_FIELD: 1},
         {HIRE_DATE_FIELD: "12/12/2035"}, 2, 1, False),

        # Active AD account and hire date did not exceed threshold date - should return True
        ({AD_ACCOUNT_STATUS_FIELD: 'Enabled', SOURCE_PRIORITY_FIELD: 1}, {HIRE_DATE_FIELD: "12/12/2035"}, 2, 1, True),

        # Active AD account, past hire date - should return False
        ({AD_ACCOUNT_STATUS_FIELD: 'Enabled', SOURCE_PRIORITY_FIELD: 1}, {HIRE_DATE_FIELD: "12/12/2020"}, 2, 1, False),

        # Non active AD account - should return False
        ({AD_ACCOUNT_STATUS_FIELD: 'Pending', SOURCE_PRIORITY_FIELD: 1}, {HIRE_DATE_FIELD: "12/12/2035"}, 2, 1, False)
    ]
)
def test_is_ad_deactivation_event(demisto_user, workday_user, days_before_hire_to_enable_ad, source_priority, expected_result):
    from Workday_IAM import is_ad_deactivation_event
    assert is_ad_deactivation_event(demisto_user, workday_user, days_before_hire_to_enable_ad, source_priority) == expected_result


@pytest.mark.parametrize(
    'workday_user, changed_fields, expected_result',
    [
        # a non terminated workday_user with changed fields (hasn't been synced to XSOAR yet) - should return True
        ({EMPLOYMENT_STATUS_FIELD: 'Leave of Absence'}, 'mock_changed_fields', True),

        # a terminated workday_user with changed fields (hasn't been synced to XSOAR yet) - should return False
        ({EMPLOYMENT_STATUS_FIELD: 'Terminated'}, 'mock_changed_fields', False),

        # a non terminated workday_user with no changed fields (already synced to XSOAR) - should return False
        ({EMPLOYMENT_STATUS_FIELD: 'Leave of Absence'}, None, False)
    ]
)
def test_is_update_event(workday_user, changed_fields, expected_result):
    from Workday_IAM import is_update_event
    assert is_update_event(workday_user, changed_fields) == expected_result


@pytest.mark.parametrize(
    'demisto_user, expected_result',
    [
        (None, False),
        ({TERMINATION_TRIGGER_FIELD: 'TUFE'}, True),
        ({TERMINATION_TRIGGER_FIELD: 'Workday IAM'}, False)
    ]
)
def test_is_tufe_user(demisto_user, expected_result):
    from Workday_IAM import is_tufe_user
    assert is_tufe_user(demisto_user) == expected_result


@pytest.mark.parametrize(
    'workday_user, demisto_user, expected_event_type',
    [
        # case 1: non-rehired TUFE user
        (
            {
                EMAIL_ADDRESS_FIELD: 'test@example.com',
                EMPLOYEE_ID_FIELD: '123',
                HIRE_DATE_FIELD: '02/02/2040'
            },
            {
                EMAIL_ADDRESS_FIELD: 'test@example.com',
                EMPLOYEE_ID_FIELD: '123',
                HIRE_DATE_FIELD: '02/02/2040',
                AD_ACCOUNT_STATUS_FIELD: 'Enabled'
            },
            None
        ),

        # case 2: a rehired tufe user
        (
            {
                EMAIL_ADDRESS_FIELD: 'test@example.com',
                EMPLOYEE_ID_FIELD: '123',
                HIRE_DATE_FIELD: 'mock_date_field',
                PREHIRE_FLAG_FIELD: 'True',
                REHIRED_EMPLOYEE_FIELD: 'Yes'
            },
            {
                EMAIL_ADDRESS_FIELD: 'test@example.com',
                EMPLOYEE_ID_FIELD: '123',
                HIRE_DATE_FIELD: 'mock_date_field',
                AD_ACCOUNT_STATUS_FIELD: 'Disabled'
            },
            REHIRE_USER_EVENT_TYPE
        ),
    ]
)
def test_get_event_details__tufe_user(workday_user, demisto_user, expected_event_type):
    """
    Given
    - A TUFE user event process.
    When
    - Calling get_event_details() method.
    Then
    - Ensure None is returned, unless a rehire event is detected.
    """
    from Workday_IAM import get_event_details

    event = get_event_details(
        entry={},
        workday_user=workday_user,
        demisto_user=demisto_user,
        days_before_hire_to_sync=None,
        days_before_hire_to_enable_ad=None,
        deactivation_date_field=LAST_DAY_OF_WORK_FIELD,
        display_name_to_user_profile={},
        email_to_user_profile={},
        employee_id_to_user_profile={},
        source_priority=1
    )
    event_type = event.get('type') if isinstance(event, dict) else None
    assert event_type is expected_event_type
