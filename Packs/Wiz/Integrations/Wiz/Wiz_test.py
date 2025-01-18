import copy
import random

import pytest
from unittest.mock import patch
import demistomock as demisto

from CommonServerPython import DemistoException

integration_params = {
    'url': 'http://test.io',
    'credentials': {'identifier': 'test', 'password': 'pass'},
    'fetch_time': '7 days',
    'max_fetch': 5
}

integration_params_with_auth_url = copy.deepcopy(integration_params)
integration_params_with_auth_url.update({"auth_endpoint": "https://auth.wiz.io/oauth/token"})

TEST_TOKEN = '123456789'
SIMILAR_COMMANDS = ['wiz-issue-in-progress', 'wiz-reopen-issue', 'wiz-reject-issue', 'wiz-get-issues',
                    'wiz-get-resource', 'wiz-get-issue',
                    'wiz-set-issue-note', 'wiz-clear-issue-note', 'wiz-get-issue-evidence', 'wiz-set-issue-due-date',
                    'wiz-clear-issue-due-date', 'wiz-get-project-team', 'wiz-resolve-issue', 'wiz-copy-to-forensics-account']


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params_with_auth_url)


test_get_issues_response = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "id": "12345678-1234-1234-1234-d25e16359c19",
                    "control": {
                        "id": "12345678-4321-4321-4321-3792e8a03318",
                        "name": "test delete",
                    },
                    "type": "THREAT_DETECTION",
                    "createdAt": "2022-01-02T15:46:34Z",
                    "updatedAt": "2022-01-04T10:40:57Z",
                    "status": "OPEN",
                    "severity": "CRITICAL",
                    "entity": {
                        "bla": "lot more blah was here",
                        "name": "virtualMachine",
                        "type": "virtualMachine"
                    }
                }
            ],
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": ""
            }
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_get_issues_response)
def test_get_filtered_issues(checkAPIerrors):
    from Wiz import get_filtered_issues

    result_response = [
        {
            "id": "12345678-1234-1234-1234-d25e16359c19",
            "control": {
                "id": "12345678-4321-4321-4321-3792e8a03318",
                "name": "test delete",
            },
            "createdAt": "2022-01-02T15:46:34Z",
            "updatedAt": "2022-01-04T10:40:57Z",
            "status": "OPEN",
            "type": "THREAT_DETECTION",
            "severity": "CRITICAL",
            "entity": {
                "bla": "lot more blah was here",
                "name": "virtualMachine",
                "type": "virtualMachine"
            }
        }
    ]

    res = get_filtered_issues('virtualMachine', '', 'CRITICAL', '', 500)
    assert res == result_response


@patch('Wiz.checkAPIerrors', return_value=test_get_issues_response)
def test_get_issue(checkAPIerrors):
    from Wiz import get_issue

    result_response = [
        {
            "id": "12345678-1234-1234-1234-d25e16359c19",
            "control": {
                "id": "12345678-4321-4321-4321-3792e8a03318",
                "name": "test delete",
            },
            "createdAt": "2022-01-02T15:46:34Z",
            "updatedAt": "2022-01-04T10:40:57Z",
            "status": "OPEN",
            "type": "THREAT_DETECTION",
            "severity": "CRITICAL",
            "entity": {
                "bla": "lot more blah was here",
                "name": "virtualMachine",
                "type": "virtualMachine"
            }
        }
    ]

    res = get_issue('d6f7a886-e2f5-44c0-980c-c7c17bbfb7dd')
    assert res == result_response


test_get_resource_response = {
    "data": {
        "graphSearch": {
            "totalCount": 1,
            "maxCountReached": False,
            "pageInfo": {
                "endCursor": "1",
                "hasNextPage": False,
                "__typename": "PageInfo"
            },
            "nodes": [
                {
                    "entities": [
                        {
                            "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
                            "name": "i_am_an_id",
                            "type": "VIRTUAL_MACHINE",
                            "properties": {
                                "blah": "lots_of_blah_here"
                            }
                        }
                    ]
                }
            ]
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_get_resource_response)
def test_get_resource_by_id(checkAPIerrors):
    from Wiz import get_resource
    result_response = {
        "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
        "name": "i_am_an_id",
        "type": "VIRTUAL_MACHINE",
        "properties": {
            "blah": "lots_of_blah_here"
        }
    }

    res = get_resource(resource_id='i_am_an_id', resource_name='')
    assert res == result_response


test_get_resource_response_search = {
    "data": {
        "cloudResources": {
            "nodes": [
                {
                    "id": "16da9341-6c72-46ba-948c-f0c057643e60",
                    "name": "test_name_vm",
                    "type": "VIRTUAL_MACHINE"
                }
            ]
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_get_resource_response_search)
def test_get_resource_by_search(checkAPIerrors):
    from Wiz import get_resource
    res = get_resource(resource_id='', resource_name='test_name_vm')
    assert res == test_get_resource_response_search


def test_get_resource_fail(capfd):
    with capfd.disabled():
        from Wiz import get_resource

        res = get_resource(resource_id='', resource_name='')
        assert res == "You should pass exactly one of resource_name or resource_id"

        res = get_resource(resource_id='12345678-2222-3333-1111-ff5fa2ff7f78', resource_name='test_name_vm')
        assert res == "You should pass exactly one of resource_name or resource_id"


test_reject_issue_response = {
    "data": {
        "updateIssue": {
            "issue": {
                "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
                "note": "blah_note",
                "status": "REJECTED",
                "dueAt": "2022-01-14T20:24:20Z",
                "resolutionReason": "WONT_FIX"
            }
        }
    }
}

# Define the return values
resolve_issues_return_values = [test_get_issues_response, test_reject_issue_response]


# Define a function that will serve as the side effect
def side_effect(*args, **kwargs):
    return resolve_issues_return_values.pop(0)


@patch('Wiz.checkAPIerrors', side_effect=side_effect)
def test_resolve_issue(checkAPIerrors, capfd):
    from Wiz import resolve_issue

    with capfd.disabled():
        res = resolve_issue(None, 1, 2)
        assert 'You should pass' in res

    res = resolve_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'WONT_FIX', 'blah_note')
    assert res == test_reject_issue_response


@patch('Wiz.checkAPIerrors', return_value=test_reject_issue_response)
def test_reject_issue(checkAPIerrors, capfd):
    from Wiz import reject_issue

    with capfd.disabled():
        res = reject_issue(None, 1, 2)
        assert 'You should pass' in res

    res = reject_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'WONT_FIX', 'blah_note')
    assert res == test_reject_issue_response


test_issue_id_not_valid = 'Error details: Resource not found'


@patch('Wiz.checkAPIerrors', return_value=test_issue_id_not_valid)
def test_reject_issue_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import reject_issue

        res = reject_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'WONT_FIX', 'blah_note')
        assert res == 'Error details: Resource not found'


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_reject_issue_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import reject_issue
        try:
            reject_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'WONT_FIX', 'blah_note')
        except DemistoException:
            assert True


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_get_issue_evidence_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import get_issue_evidence
        try:
            get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
        except DemistoException:
            assert True


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_clear_issue_due_date_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import clear_issue_due_date
        try:
            clear_issue_due_date('12345678-2222-3333-1111-ff5fa2ff7f78')
        except DemistoException:
            assert True


test_reopen_issue_response = {
    "data": {
        "updateIssue": {
            "issue": {
                "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
                "note": "blah_note",
                "status": "OPEN",
                "dueAt": "2022-01-14T20:24:20Z",
                "resolutionReason": ""
            }
        }
    }
}


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_reopen_issue_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import reopen_issue
        try:
            reopen_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
        except DemistoException:
            assert True


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_issue_in_progress_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import issue_in_progress
        try:
            issue_in_progress('12345678-2222-3333-1111-ff5fa2ff7f78')
        except DemistoException:
            assert True


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_set_issue_note_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import set_issue_comment
        try:
            set_issue_comment('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
        except DemistoException:
            assert True


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_clear_issue_note_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import clear_issue_note
        try:
            clear_issue_note('12345678-2222-3333-1111-ff5fa2ff7f78')
        except DemistoException:
            assert True


@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_set_issue_date_exception(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import set_issue_due_date
        try:
            set_issue_due_date('12345678-2222-3333-1111-ff5fa2ff7f78', '2022-01-20')
        except DemistoException:
            assert True


@patch('Wiz.return_error', side_effect=Exception('no command'))
def test_main_without_params(return_error, capfd):
    from Wiz import main
    with pytest.raises(Exception) as e:
        main()
    assert str(e.value) == 'no command'
    captured = capfd.readouterr()
    assert 'Unrecognized command' in captured.out


def test_no_command(mocker):
    from Wiz import main
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch('Wiz.get_token', return_value=TEST_TOKEN)
    mocker.patch('Wiz.checkAPIerrors', return_value=test_issue_id_not_valid)
    main()


INVALID_RESPONSE_ERROR = 'blabla error blabla'

VALID_RESPONSE_JSON = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "id": "b00bb5ce-4493-4158-af64-e21c6776331b",
                    "name": "test-1",
                    "createdAt": "2022-07-06T11:21:28.372924Z",
                    "type": "CORTEX_XSOAR",
                    "evidenceQuery": "test_query",
                    "status": "SUCCESS",
                    "notes": [{
                        "id": "test_note_result"
                    }],
                    "project": None,
                    "isAccessibleToAllProjects": True,
                    "params": {
                        "url": "https://bla.bla",
                        "authentication": {
                            "username": "A",
                            "password": "__secret_content__"
                        },
                        "clientCertificate": None,
                        "body": "{}"
                    },
                    "usedByRules": []
                },
                {
                    "id": "123456-test-id-2",
                    "name": "test-2",
                    "createdAt": "2022-07-06T11:21:28.372924Z",
                    "type": "CORTEX_XSOAR",
                    "status": "SUCCESS",
                    "project": None,
                    "isAccessibleToAllProjects": True,
                    "params": {
                        "url": "https://bla.bla",
                        "authentication": {
                            "username": "A",
                            "password": "__secret_content__"
                        },
                        "clientCertificate": None,
                        "body": "{}"
                    },
                    "usedByRules": []
                }
            ],
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": None
            },
            "totalCount": 2
        },
        "graphSearch": {
            "nodes": [{"entities": [{"id": "test_id"}]}]
        },
        "issue": {
            "note": None,
            "control": {
                "query": "blabla"
            },
            "status": "CRITICAL",
            "resolutionReason": "blabla reason"
        },
        "projects": {
            "nodes": [{
                "projectOwners": "owner-test",
                "securityChampions": "champion-test"
            }]
        },
        "cloudResources": {
            "nodes": [{
                "id": "test_id",
                "name": "test_name",
                "type": "test_type",
                "properties": {
                    "test": "test"
                }
            }]
        },
        "copyResourceForensicsToExternalAccount": {
            "systemActivityGroupId": "test_id"
        }
    }
}

DEMISTO_ARGS = {
    'issue_type': 'Publicly exposed VM instance with effective global admin permissions',
    'resource_id': 'test-id',
    'severity': 'CRITICAL',
    'reject_note': 'reject_note_test',
    'issue_id': 123456,
    'reject_reason': 'reject_reason_test',
    'reopen_note': 'reopen_note_test',
    'note': 'test-note',
    'resource_name': 'resource_name'
}


@patch('Wiz.checkAPIerrors', return_value=test_reopen_issue_response)
def test_reopen_issue_direct(checkAPIerrors):
    from Wiz import reopen_issue

    res = reopen_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
    assert res == test_reopen_issue_response


@patch('Wiz.checkAPIerrors', return_value=test_issue_id_not_valid)
def test_set_issue_reopen_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import reopen_issue

        res = reopen_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
        assert res == 'Error details: Resource not found'


test_issue_in_progress_response = {
    "data": {
        "updateIssue": {
            "issue": {
                "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
                "note": "blah_note",
                "status": "IN_PROGRESS",
                "dueAt": "2022-01-14T20:24:20Z",
                "resolutionReason": ""
            }
        }
    }
}


@pytest.mark.parametrize("command_name", SIMILAR_COMMANDS)
def test_main_command(mocker, capfd, command_name):
    from Wiz import main
    with capfd.disabled():
        mocker.patch.object(demisto, 'command', return_value=command_name)
        mocker.patch.object(demisto, 'args', return_value=DEMISTO_ARGS)
        mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
        mocker.patch('CommonServerPython.tableToMarkdown', return_value=[])
        main()


def test_has_next_page(mocker, capfd):
    from Wiz import fetch_issues
    with capfd.disabled():
        valid_json_paging = copy.deepcopy(VALID_RESPONSE_JSON)
        valid_json_paging['data']['issues']['pageInfo']['hasNextPage'] = True
        valid_json_paging['data']['issues']['pageInfo']['endCursor'] = 'test'
        mocker.patch('Wiz.checkAPIerrors', side_effect=[valid_json_paging, VALID_RESPONSE_JSON])
        mocker.patch('CommonServerPython.tableToMarkdown', return_value=[])
        fetch_issues(450)


def test_get_project_team(mocker, capfd):
    from Wiz import get_project_team
    with capfd.disabled():
        mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
        project = get_project_team('test_project')
        assert project['projectOwners'] == 'owner-test'
        assert project['securityChampions'] == 'champion-test'

        mocker.patch('Wiz.checkAPIerrors', side_effect=DemistoException('demisto exception'))
        project = get_project_team('test_project')
        assert not project


@pytest.mark.parametrize("severity", ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'])
def test_get_filtered_issues_good_severity(mocker, capfd, severity):
    from Wiz import get_filtered_issues
    with capfd.disabled():
        valid_json_paging = copy.deepcopy(VALID_RESPONSE_JSON)
        valid_json_paging['data']['issues']['pageInfo']['hasNextPage'] = True
        valid_json_paging['data']['issues']['pageInfo']['endCursor'] = 'test'
        mocker.patch('Wiz.checkAPIerrors', side_effect=[valid_json_paging, VALID_RESPONSE_JSON])
        get_filtered_issues(entity_type='virtualMachine', resource_id='', severity=severity, issue_type='', limit=500)


@pytest.mark.parametrize("severity", ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'])
def test_get_filtered_issues_good_severity_resource(mocker, capfd, severity):
    from Wiz import get_filtered_issues
    with capfd.disabled():
        valid_json_paging = copy.deepcopy(VALID_RESPONSE_JSON)
        valid_json_paging['data']['issues']['pageInfo']['hasNextPage'] = True
        valid_json_paging['data']['issues']['pageInfo']['endCursor'] = 'test'
        mocker.patch('Wiz.checkAPIerrors', side_effect=[valid_json_paging, VALID_RESPONSE_JSON])
        get_filtered_issues(entity_type='', resource_id='test_resource', severity=severity, issue_type='', limit=500)


def test_get_filtered_issues_bad_arguments(mocker, capfd):
    from Wiz import get_filtered_issues
    with capfd.disabled():
        mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
        issue = get_filtered_issues(entity_type='virtualMachine', resource_id='test', severity='BAD', issue_type='', limit=500)
        assert issue == 'You cannot pass entity_type and resource_id together\n'
        issue = get_filtered_issues(entity_type='', resource_id='', severity='', issue_type='', limit=500)
        assert issue == "You should pass (at least) one of the following parameters:\n\tentity_type\n\tresource_id" \
            "\n\tseverity\n\tissue_type\n"
        issue = get_filtered_issues(entity_type='virtualMachine', resource_id='', severity='BAD', issue_type='', limit=500)
        assert issue == 'You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or ' \
                        'INFORMATIONAL in upper or lower case.'


def test_get_issue_bad_arguments(mocker, capfd):
    from Wiz import get_issue
    with capfd.disabled():
        mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
        issue = get_issue(issue_id='virtualMachine')
        assert issue == 'Wrong format: The Issue ID should be in UUID format.'
        issue = get_issue(issue_id='')
        assert issue == 'You should pass an Issue ID.'


@patch('Wiz.checkAPIerrors', return_value=test_issue_in_progress_response)
def test_issue_in_progress(checkAPIerrors):
    from Wiz import issue_in_progress

    res = issue_in_progress('12345678-2222-3333-1111-ff5fa2ff7f78')
    assert res == test_issue_in_progress_response


@patch('Wiz.checkAPIerrors', return_value=test_issue_id_not_valid)
def test_set_issue_in_progress_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import issue_in_progress

        res = issue_in_progress('12345678-2222-3333-1111-ff5fa2ff7f78')
        assert res == "Error details: Resource not found"


test_set_issue_note_response = {
    "data": {
        "issue": {
            "id": "12345678-1234-1234-1234-d25e16359c19",
            "control": {
                "id": "12345678-4321-4321-4321-3792e8a03318",
                "name": "test delete",
            },
            "createdAt": "2022-01-02T15:46:34Z",
            "updatedAt": "2022-01-04T10:40:57Z",
            "status": "OPEN",
            "note": "blah note",
            "severity": "CRITICAL",
            "entity": {
                "bla": "lot more blah was here",
                "name": "virtualMachine",
                "type": "virtualMachine"
            }
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_set_issue_note_response)
def test_set_issue_note(checkAPIerrors):
    from Wiz import set_issue_comment

    res = set_issue_comment('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
    assert res == test_set_issue_note_response


test_set_issue_note_fail_response = {
    "errors": [
        {
            "message": "Resource not found",
            "extensions": {
                "code": "NOT_FOUND",
                "exception": {
                    "message": "Resource not found",
                    "path": [
                        "issue"
                    ]
                }
            }
        }
    ],
    "data": None
}


@patch('Wiz.checkAPIerrors', return_value=test_issue_id_not_valid)
def test_set_issue_note_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import set_issue_comment

        res = set_issue_comment('12345678-2222-3333-1111-ff5fa2ff7f78', "blah")
        assert res == "Error details: Resource not found"


test_clear_issue_note_response = {
    "data": {
        "updateIssue": {
            "issue": {
                "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
                "note": "",
                "status": "REJECTED",
                "dueAt": "2022-01-14T20:24:20Z",
                "resolutionReason": "WONT_FIX"
            }
        }
    }
}

test_clear_issue_note_fail_response = 'Error details: Only the user who created the note, can delete it.\n' \
                                      'Check server.log file for additional information'


@patch('Wiz._get_issue', return_value=VALID_RESPONSE_JSON)
@patch('Wiz.checkAPIerrors', return_value=test_clear_issue_note_fail_response)
def test_clear_issue_note_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import clear_issue_note

        res = clear_issue_note('12345678-2222-3333-1111-ff5fa2ff7f78')
        assert res == 'Error details: Only the user who created the note, can delete it.\n' \
                      'Check server.log file for additional information'


@patch('Wiz._get_issue', return_value=VALID_RESPONSE_JSON)
@patch('Wiz.checkAPIerrors', side_effect=DemistoException('no command'))
def test_get_issue_evidence_failure(checkAPIerrors, _get_issue, capfd):
    with capfd.disabled():
        from Wiz import get_issue_evidence
        with pytest.raises(Exception) as e:
            get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
        assert "Failed getting Issue evidence on ID 12345678-1234-1234-1234-d25e16359c19" in str(e)


test_get_issue_evidence_tdr_response = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "type": "THREAT_DETECTION",
                    "evidenceQuery": {

                    },
                    "threatDetectionDetails": {
                        "data": "data"
                    }
                }
            ]
        }
    }
}


@patch('Wiz._get_issue', return_value=test_get_issue_evidence_tdr_response)
@patch('Wiz.checkAPIerrors', return_value=test_get_issue_evidence_tdr_response)
def test_get_issue_evidence_tdr(checkAPIerrors, _get_issue):
    from Wiz import get_issue_evidence
    res = get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
    assert res == test_get_issue_evidence_tdr_response['data']['issues']['nodes'][0]['threatDetectionDetails']


test_get_issue_evidence_control_response = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "type": "TOXIC_COMBINATION",
                    "evidenceQuery": {
                        "data": "data"
                    },
                    "threatDetectionDetails": None
                }
            ]
        }
    }
}

test_get_evidence_control_response = {
    "data": {
        "graphSearch": {
            "nodes": [
                {
                    "entities": [
                        {
                            "id": "12345678-222"
                        }
                    ]
                }
            ]
        }
    }
}


@patch('Wiz._get_issue', return_value=test_get_issue_evidence_control_response)
@patch('Wiz.checkAPIerrors', return_value=test_get_evidence_control_response)
def test_get_issue_evidence_control(checkAPIerrors, _get_issue):
    from Wiz import get_issue_evidence
    res = get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
    assert res == test_get_evidence_control_response['data']['graphSearch']['nodes'][0]['entities']


test_get_issue_empty_issue_response = {
    "data": {
        "issues": {
            "nodes": []
        }
    }
}


@patch('Wiz._get_issue', return_value=test_get_issue_empty_issue_response)
def test_get_issue_evidence_no_issue(_get_issue):
    from Wiz import get_issue_evidence
    res = get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
    assert res == "Issue not found: 12345678-1234-1234-1234-d25e16359c19"


test_get_issue_response_query_exists = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "type": "TOXIC_COMBINATION",
                    "evidenceQuery": {
                        "data": "data"
                    },
                    "threatDetectionDetails": {
                    }
                }
            ]
        }
    }
}

test_get_evidence_empty = {
    "data": {
        "graphSearch": {
            "nodes": [
            ]
        }
    }
}

test_get_evidence_empty_none = {
    "data": {
        "graphSearch": {
            "nodes": None
        }
    }
}


@patch('Wiz._get_issue', return_value=test_get_issue_response_query_exists)
@patch('Wiz.checkAPIerrors', return_value=test_get_evidence_empty)
def test_get_issue_evidence_no_evidence(checkAPIerrors, _get_issue):
    from Wiz import get_issue_evidence
    res = get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
    assert res == "No Evidence Found"


@patch('Wiz._get_issue', return_value=test_get_issue_response_query_exists)
@patch('Wiz.checkAPIerrors', return_value=test_get_evidence_empty_none)
def test_get_issue_evidence_no_resource(checkAPIerrors, _get_issue):
    from Wiz import get_issue_evidence
    res = get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
    assert res == "Resource Not Found"


test_set_issue_due_data_response = {
    "data": {
        "updateIssue": {
            "issue": {
                "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
                "note": "",
                "status": "OPEN",
                "dueAt": "2022-01-20T00:00:00.000Z",
                "resolutionReason": None
            }
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_set_issue_due_data_response)
def test_set_issue_due_date(checkAPIerrors):
    from Wiz import set_issue_due_date

    res = set_issue_due_date('12345678-2222-3333-1111-ff5fa2ff7f78', '2022-01-20')
    assert res == test_set_issue_due_data_response


@patch('Wiz.checkAPIerrors', return_value="The date format is the incorrect. It should be YYYY-MM-DD")
def test_set_issue_due_date_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import set_issue_due_date

        res = set_issue_due_date('12345678-2222-3333-1111-ff5fa2ff7f78', '01-20-2022')
        assert res == "The date format is the incorrect. It should be YYYY-MM-DD"


@patch('Wiz.checkAPIerrors', return_value="errors blabla")
def test_set_issue_due_date_error(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import set_issue_due_date

        res = set_issue_due_date('12345678-2222-3333-1111-ff5fa2ff7f78', '2022-01-20')
        assert "errors blabla" in res


test_clear_issue_due_data_response = {
    "data": {
        "issue": {
            "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
            "note": "",
            "status": "OPEN",
            "dueAt": None,
            "resolutionReason": None
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_clear_issue_due_data_response)
def test_clear_issue_due_date(checkAPIerrors):
    from Wiz import clear_issue_due_date

    res = clear_issue_due_date('12345678-2222-3333-1111-ff5fa2ff7f78')
    assert res == test_clear_issue_due_data_response


test_clear_issue_due_data_failed_response = {
    "errors": [
        {
            "message": "Resource not found",
            "extensions": {
                "code": "NOT_FOUND",
                "exception": {
                    "message": "Resource not found",
                    "path": [
                        "updateIssue"
                    ]
                }
            }
        }
    ],
    "data": None
}

test_bad_token_response = {
    "error": "access_denied",
    "error_description": "Unauthorized"
}


def mocked_requests_get(json, status):
    class MockResponse:
        def __init__(self, json, status_code):
            self.json_data = json
            self.status_code = status_code

        def json(self):
            return self.json_data

    return MockResponse(json, status)


def test_bad_get_token(capfd):
    with capfd.disabled(), patch('requests.post') as mocked_request, pytest.raises(Exception):
        mocked_request().return_value = test_bad_token_response
        from Wiz import get_token

        res = get_token()
        assert res == test_bad_token_response


def test_generate_auth_urls_fed():
    from Wiz import generate_auth_urls_fed
    prefix = "auth"
    expected_auth_url = "auth.wiz.us/oauth/token"
    expected_http_auth_url = "https://auth.wiz.us/oauth/token"
    auth_url, http_auth_url = generate_auth_urls_fed(prefix)
    assert auth_url == expected_auth_url
    assert http_auth_url == expected_http_auth_url

    prefix = ""
    expected_auth_url = ".wiz.us/oauth/token"
    expected_http_auth_url = "https://.wiz.us/oauth/token"
    auth_url, http_auth_url = generate_auth_urls_fed(prefix)
    assert auth_url == expected_auth_url
    assert http_auth_url == expected_http_auth_url

    prefix = "auth!@#"
    expected_auth_url = "auth!@#.wiz.us/oauth/token"
    expected_http_auth_url = "https://auth!@#.wiz.us/oauth/token"
    auth_url, http_auth_url = generate_auth_urls_fed(prefix)
    assert auth_url == expected_auth_url
    assert http_auth_url == expected_http_auth_url


def test_token_url():
    from Wiz import COGNITO_PREFIX, AUTH0_PREFIX, generate_auth_urls

    cognito_allowlist = [
        "auth.app.wiz.io/oauth/token",
        "https://auth.app.wiz.io/oauth/token",
        "auth.gov.wiz.io/oauth/token",
        "https://auth.gov.wiz.io/oauth/token",
        "auth.test.wiz.io/oauth/token",
        "https://auth.test.wiz.io/oauth/token"
    ]
    auth0_allowlist = [
        "auth.wiz.io/oauth/token",
        "https://auth.wiz.io/oauth/token",
        "auth0.gov.wiz.io/oauth/token",
        "https://auth0.gov.wiz.io/oauth/token",
        "auth0.test.wiz.io/oauth/token",
        "https://auth0.test.wiz.io/oauth/token"
    ]

    cognito_list = []
    for cognito_prefix in COGNITO_PREFIX:
        cognito_list.extend(generate_auth_urls(cognito_prefix))
    assert cognito_list.sort() == cognito_allowlist.sort()

    auth0_list = []
    for auth0_prefix in AUTH0_PREFIX:
        auth0_list.extend(generate_auth_urls(auth0_prefix))
    assert auth0_list.sort() == auth0_allowlist.sort()


def test_good_token(capfd, mocker):
    with capfd.disabled():
        good_token = str(random.randint(1, 1000))
        mocker.patch('requests.post', return_value=mocked_requests_get({"access_token": good_token}, 200))

        from Wiz import get_token, set_authentication_endpoint, generate_auth_urls, AUTH_DEFAULT
        set_authentication_endpoint('https://auth.wiz.io/oauth/token')
        res = get_token()
        assert res == good_token

        set_authentication_endpoint(generate_auth_urls(AUTH_DEFAULT)[1])
        res = get_token()
        assert res == good_token

        set_authentication_endpoint('auth.wiz.io/oauth/token')
        res = get_token()
        assert res == good_token

        set_authentication_endpoint('bad')
        from Wiz import get_token
        with pytest.raises(Exception) as e:
            get_token()
        assert str(e.value) == 'Not a valid authentication endpoint'


def test_token_no_access(capfd, mocker):
    with capfd.disabled():
        mocker.patch('requests.post', return_value=mocked_requests_get({}, 200))
        from Wiz import get_token, set_authentication_endpoint
        with pytest.raises(Exception) as e:

            set_authentication_endpoint('auth.app.wiz.io/oauth/token')
            get_token()
        assert 'Could not retrieve token from Wiz' in str(e.value)


def test_check_api_access(capfd, mocker):
    with capfd.disabled():
        good_token = str(random.randint(1, 1000))
        mocker.patch('requests.post', return_value=mocked_requests_get({"access_token": good_token}, 200))
        from Wiz import checkAPIerrors
        checkAPIerrors(query='test', variables='test')

        mocker.patch('Wiz.get_token', return_value=TEST_TOKEN)
        mocker.patch('requests.post', side_effect=Exception('bad request'))
        with pytest.raises(Exception) as e:
            checkAPIerrors(query='test', variables='test')
        assert str(e.value) == 'bad request'


def test_check_api_access_bad_gw(capfd, mocker):
    with capfd.disabled():
        from Wiz import checkAPIerrors
        mocker.patch('requests.post', side_effect=Exception('502: Bad Gateway'))

        with pytest.raises(Exception) as e:
            checkAPIerrors(query='test', variables='test')
        assert '502: Bad Gateway' in str(e.value)


test_issue_severity_crit_response = {
    "id": "12345678-2222-3333-1111-ff5fa2ff7f71",
    "note": "",
    "severity": "CRITICAL",
    "status": "OPEN",
    "dueAt": None,
    "resolutionReason": None
}


def test_translate_severity_crit(capfd):
    with capfd.disabled():
        from Wiz import translate_severity

        res = translate_severity(test_issue_severity_crit_response)
        assert res == 4


test_issue_severity_high_response = {
    "id": "12345678-2222-3333-1111-ff5fa2ff7f71",
    "note": "",
    "severity": "HIGH",
    "status": "OPEN",
    "dueAt": None,
    "resolutionReason": None
}


def test_translate_severity_high(capfd):
    with capfd.disabled():
        from Wiz import translate_severity

        res = translate_severity(test_issue_severity_high_response)
        assert res == 3


test_issue_severity_med_response = {
    "id": "12345678-2222-3333-1111-ff5fa2ff7f71",
    "note": "",
    "severity": "MEDIUM",
    "status": "OPEN",
    "dueAt": None,
    "resolutionReason": None
}


def test_translate_severity_med(capfd):
    with capfd.disabled():
        from Wiz import translate_severity

        res = translate_severity(test_issue_severity_med_response)
        assert res == 2


test_issue_severity_low_response = {
    "id": "12345678-2222-3333-1111-ff5fa2ff7f71",
    "note": "",
    "severity": "LOW",
    "status": "OPEN",
    "dueAt": None,
    "resolutionReason": None
}


def test_translate_severity_low(capfd):
    with capfd.disabled():
        from Wiz import translate_severity

        res = translate_severity(test_issue_severity_low_response)
        assert res == 1


test_issue_severity_info_response = {
    "id": "12345678-2222-3333-1111-ff5fa2ff7f71",
    "note": "",
    "severity": "INFORMATIONAL",
    "status": "OPEN",
    "dueAt": None,
    "resolutionReason": None
}


def test_translate_severity_info(capfd):
    with capfd.disabled():
        from Wiz import translate_severity

        res = translate_severity(test_issue_severity_info_response)
        assert res == 0.5


test_build_incidents_response = None


def test_build_incidents_none(capfd):
    with capfd.disabled():
        from Wiz import build_incidents

        res = build_incidents(test_build_incidents_response)
        assert res == {}


test_copy_to_forensics_account_response = {
    "data": {
        "copyResourceForensicsToExternalAccount": {
            "systemActivityGroupId": "16dee032-9a56-4331-aca5-0df2a9d47745"
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_copy_to_forensics_account_response)
def test_copy_to_forensics_account(checkAPIerrors):
    from Wiz import copy_to_forensics_account
    res = copy_to_forensics_account('12345678-1234-1234-1234-d25e16359c19')
    assert res == test_copy_to_forensics_account_response


test_get_resource_id_using_arn_response = {
    "data": {
        "cloudResources": {
            "nodes": [
                {
                    "id": "12345678-1234-1234-1234-d25e16359c19"
                }
            ]
        }
    }
}


def test_copy_to_forensics_account_provider_id(mocker):
    from Wiz import copy_to_forensics_account
    mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON, side_effect=[test_get_resource_id_using_arn_response,
                                                                                      test_copy_to_forensics_account_response])
    res = copy_to_forensics_account('arn:aws:ec2:us-east-1:452225563321:instance/i-05r662bfb9708a4e8')
    assert res == test_copy_to_forensics_account_response


test_get_resource_id_using_arn_response_error = {
    "data": None,
    "errors": {
        "message": "Resource not found",
    }
}


def test_copy_to_forensics_account_invalid_id(mocker, capfd):
    from Wiz import copy_to_forensics_account
    with capfd.disabled():
        mocker.patch('Wiz.checkAPIerrors', side_effect=[test_get_resource_id_using_arn_response,
                                                        test_get_resource_id_using_arn_response_error])
        issue = copy_to_forensics_account(resource_id='invalid_uuid')
        assert issue == ("Resource with ID 12345678-1234-1234-1234-d25e16359c19 was not copied to Forensics Account. "
                         "error: {'message': 'Resource not found'}")
