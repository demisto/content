import json

import demistomock as demisto
from MyToDoTasksWidget import get_open_to_do_tasks_of_current_user, get_clickable_incident_id
import pytest


def test_open_to_do_tasks_of_current_user(mocker):
    '''
    Given:
        - Mock response of 'internalHttpRequest' to '/v2/statistics/widgets/query' that includes an open task and
         a close task
    When:
        - Running the MyToDoTasksWidget script

    Then:
        - Ensure the markdown table was generated correctly and includes only the open task
    '''
    res_body = {
        'data': [
            {
                'assignee': 'admin',
                'completed': '0001-01-01T00:00:00Z',
                'dbotCreatedBy': 'admin',
                'description': 'test_open_task',
                'dueDate': '2021-11-30T15:49:11+02:00',
                'id': '1@2',
                'incidentId': '2',
                'status': 'open',
                'title': 'test open'
            },
            {
                'assignee': 'admin',
                'dbotCreatedBy': 'admin',
                'description': 'test_close_task',
                'dueDate': '2021-11-30T15:49:11+02:00',
                'id': '1@3',
                'incidentId': '3',
                'status': 'close',
                'title': 'test close'
            }
        ]
    }
    mocker.patch.object(
        demisto,
        'internalHttpRequest',
        return_value={
            'statusCode': 200,
            'body': json.dumps(res_body)
        }
    )

    expected_table = [
        {
            'Task Name': 'test open',
            'Task Description': 'test_open_task',
            'Task ID': '1@2',
            'SLA': '2021-11-30 15:49:11+0200',
            'Opened By': 'admin',
            'Incident ID': '[2](#/Custom/caseinfoid/2)'
        }
    ]

    table = get_open_to_do_tasks_of_current_user()

    assert len(table) == 1
    assert table == expected_table


def test_no_open_to_do_tasks(mocker):
    '''
    Given:
        - Mock response of 'internalHttpRequest' to '/v2/statistics/widgets/query' that includes no open todo tasks
    When:
        - Running the MyToDoTasksWidget script

    Then:
        - Ensure the script runs successfully add returns empty response
    '''
    res_body = {
        'data': None
    }
    mocker.patch.object(
        demisto,
        'internalHttpRequest',
        return_value={
            'statusCode': 200,
            'body': json.dumps(res_body)
        }
    )

    table = get_open_to_do_tasks_of_current_user()

    assert len(table) == 0


@pytest.mark.parametrize('is_xsoar_8_or_xsiam', [True, False])
def test_clickable_incident_id(mocker, is_xsoar_8_or_xsiam):
    '''
    Given:
        - incident id to create clickable_incident_id
    When:
        - Running clickable_incident_id in XSIAM/XSOAR 8 and XSOAR 6
    Then:
        - Ensure '#/' is in the created link only in XSOAR 6.
    '''
    import MyToDoTasksWidget
    mocker.patch.object(MyToDoTasksWidget, 'is_xsiam_or_xsoar_saas', return_value=is_xsoar_8_or_xsiam)
    assert ('#/' in get_clickable_incident_id('1234')) == (not is_xsoar_8_or_xsiam)
