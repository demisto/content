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

TEST_TOKEN = '123456789'
SIMILAR_COMMANDS = ['wiz-issue-in-progress', 'wiz-reopen-issue', 'wiz-reject-issue', 'wiz-get-issues',
                    'wiz-set-issue-note', 'wiz-clear-issue-note', 'wiz-get-issue-evidence', 'wiz-set-issue-due-date',
                    'wiz-clear-issue-due-date', 'wiz-rescan-machine-disk', 'wiz-get-project-team']


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


test_get_filtered_issues_response = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "id": "12345678-1234-1234-1234-d25e16359c19",
                    "control": {
                        "id": "12345678-4321-4321-4321-3792e8a03318",
                        "name": "test delete",
                    },
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


@patch('Wiz.checkAPIerrors', return_value=test_get_filtered_issues_response)
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
            "severity": "CRITICAL",
            "entity": {
                "bla": "lot more blah was here",
                "name": "virtualMachine",
                "type": "virtualMachine"
            }
        }
    ]

    res = get_filtered_issues('virtualMachine', '', 'CRITICAL', 500)
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
def test_get_resource(checkAPIerrors):
    from Wiz import get_resource
    result_response = {
        "id": "12345678-2222-3333-1111-ff5fa2ff7f78",
        "name": "i_am_an_id",
        "type": "VIRTUAL_MACHINE",
        "properties": {
            "blah": "lots_of_blah_here"
        }
    }

    res = get_resource('i_am_an_id')
    assert res == result_response


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


@patch('Wiz.checkAPIerrors', return_value=test_reject_issue_response)
def test_reject_issue(checkAPIerrors):
    from Wiz import reject_issue

    res = reject_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'WONT_FIX', 'blah_note')
    assert res == test_reject_issue_response


test_reject_issue_fail_response = {
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


@patch('Wiz.checkAPIerrors', return_value=test_reject_issue_fail_response)
def test_reject_issue_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import reject_issue

        res = reject_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'WONT_FIX', 'blah_note')
        assert res == ("Could not find Issue with ID 12345678-2222-3333-1111-ff5fa2ff7f78")


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


@patch('Wiz.return_error', side_effect=Exception('no command'))
def test_main_without_params(return_error, capfd):
    from Wiz import main
    try:
        main()
    except Exception as e:
        assert str(e) == 'no command'
    captured = capfd.readouterr()
    assert 'Unrecognized command' in captured.out


def test_no_command(mocker):
    from Wiz import main
    try:
        mocker.patch.object(demisto, 'command', return_value='test-module')
        mocker.patch('Wiz.get_token', return_value=TEST_TOKEN)
        mocker.patch('Wiz.checkAPIerrors', return_value=test_set_issue_reopen_fail_response)
        main()
    except Exception as e:
        assert str(e) == 'no command'


INVALID_RESPONSE_ERROR = 'blabla error blabla'


VALID_RESPONSE_JSON = {
    "data": {
        "issues": {
            "nodes": [
                {
                    "id": "123456-test-id-1",
                    "name": "test-1",
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
        }
    }
}


def test_fetch_incidents(mocker):
    from Wiz import main
    try:
        mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
        mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
        main()
    except Exception as e:
        assert str(e) == 'no command'


DEMISTO_ARGS = {
    'issue_type': 'Publicly exposed VM instance with effective global admin permissions',
    'resource_id': 'test-id',
    'severity': 'CRITICAL',
    'reject_note': 'reject_note_test',
    'issue_id': 123456,
    'reject_reason': 'reject_reason_test',
    'reopen_note': 'reopen_note_test',
    'note': 'test-note'
}


@patch('Wiz.checkAPIerrors', return_value=test_reopen_issue_response)
def test_reopen_issue_direct(checkAPIerrors):
    from Wiz import reopen_issue

    res = reopen_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
    assert res == test_reopen_issue_response


test_set_issue_reopen_fail_response = {
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


@patch('Wiz.checkAPIerrors', return_value=test_set_issue_reopen_fail_response)
def test_set_issue_reopen_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import reopen_issue

        res = reopen_issue('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
        assert res == ("Could not find Issue with ID 12345678-2222-3333-1111-ff5fa2ff7f78")


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
    try:
        with capfd.disabled():
            mocker.patch.object(demisto, 'command', return_value=command_name)
            mocker.patch.object(demisto, 'args', return_value=DEMISTO_ARGS)
            mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
            mocker.patch('CommonServerPython.tableToMarkdown', return_value=[])
            main()

    except Exception as e:
        assert str(e) == 'no command'


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


def test_rescan_machine_disk(mocker, capfd):
    from Wiz import rescan_machine_disk
    with capfd.disabled():
        mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
        machine_disk = rescan_machine_disk('test_id_1234')
        assert machine_disk

        mocker.patch('Wiz.checkAPIerrors', side_effect=DemistoException('demisto exception'))
        machine_disk = rescan_machine_disk('test_id_1234')
        assert not machine_disk


@pytest.mark.parametrize("severity", ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'])
def test_get_filtered_issues_good_severity(mocker, capfd, severity):
    from Wiz import get_filtered_issues
    with capfd.disabled():
        valid_json_paging = copy.deepcopy(VALID_RESPONSE_JSON)
        valid_json_paging['data']['issues']['pageInfo']['hasNextPage'] = True
        valid_json_paging['data']['issues']['pageInfo']['endCursor'] = 'test'
        mocker.patch('Wiz.checkAPIerrors', side_effect=[valid_json_paging, VALID_RESPONSE_JSON])
        get_filtered_issues(issue_type='virtualMachine', resource_id='', severity=severity, limit=500)


@pytest.mark.parametrize("severity", ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'])
def test_get_filtered_issues_good_severity_resource(mocker, capfd, severity):
    from Wiz import get_filtered_issues
    with capfd.disabled():
        valid_json_paging = copy.deepcopy(VALID_RESPONSE_JSON)
        valid_json_paging['data']['issues']['pageInfo']['hasNextPage'] = True
        valid_json_paging['data']['issues']['pageInfo']['endCursor'] = 'test'
        mocker.patch('Wiz.checkAPIerrors', side_effect=[valid_json_paging, VALID_RESPONSE_JSON])
        get_filtered_issues(issue_type='', resource_id='test_resource', severity=severity, limit=500)


def test_get_filtered_issues_bad_severity(mocker, capfd):
    from Wiz import get_filtered_issues
    with capfd.disabled():
        mocker.patch('Wiz.checkAPIerrors', return_value=VALID_RESPONSE_JSON)
        issue = get_filtered_issues(issue_type='virtualMachine', resource_id='test', severity='BAD', limit=500)
        assert issue == 'You should (only) pass either issue_type or resource_id filters'
        issue = get_filtered_issues(issue_type='virtualMachine', resource_id='', severity='BAD', limit=500)
        assert issue == 'You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or ' \
                        'INFORMATIONAL in upper or lower case.'


@patch('Wiz.checkAPIerrors', return_value=test_issue_in_progress_response)
def test_issue_in_progress(checkAPIerrors):
    from Wiz import issue_in_progress

    res = issue_in_progress('12345678-2222-3333-1111-ff5fa2ff7f78')
    assert res == test_issue_in_progress_response


test_set_issue_in_progress_fail_response = {
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


@patch('Wiz.checkAPIerrors', return_value=test_set_issue_in_progress_fail_response)
def test_set_issue_in_progress_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import issue_in_progress

        res = issue_in_progress('12345678-2222-3333-1111-ff5fa2ff7f78')
        assert res == ("Could not find Issue with ID 12345678-2222-3333-1111-ff5fa2ff7f78")


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
    from Wiz import set_issue_note

    res = set_issue_note('12345678-2222-3333-1111-ff5fa2ff7f78', 'blah_note')
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


@patch('Wiz.checkAPIerrors', return_value=test_set_issue_note_fail_response)
def test_set_issue_note_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import set_issue_note

        res = set_issue_note('12345678-2222-3333-1111-ff5fa2ff7f78', "blah")
        assert res == ("Could not find Issue with ID 12345678-2222-3333-1111-ff5fa2ff7f78")


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


@patch('Wiz.checkAPIerrors', return_value=test_clear_issue_note_response)
def test_clear_issue_note(checkAPIerrors):
    from Wiz import clear_issue_note

    res = clear_issue_note('12345678-2222-3333-1111-ff5fa2ff7f78')
    assert res == test_clear_issue_note_response


test_clear_issue_note_fail_response = {
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


@patch('Wiz.checkAPIerrors', return_value=test_clear_issue_note_fail_response)
def test_clear_issue_note_failed(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import clear_issue_note

        res = clear_issue_note('12345678-2222-3333-1111-ff5fa2ff7f78')
        assert res == ("Could not find Issue with ID 12345678-2222-3333-1111-ff5fa2ff7f78")


test_get_issue_evidence_fail_response = {
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
    "data": {
        "issue": None,
        "issueSettings": {
            "requireNoteOnRejection": True
        }
    }
}


@patch('Wiz.checkAPIerrors', return_value=test_get_issue_evidence_fail_response)
def test_get_issue_evidence_failure(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import get_issue_evidence

        res = get_issue_evidence('12345678-1234-1234-1234-d25e16359c19')
        assert res == ("Could not find Issue with ID 12345678-1234-1234-1234-d25e16359c19")


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


@patch('Wiz.checkAPIerrors', return_value=test_clear_issue_due_data_failed_response)
def test_clear_issue_due_date_no_issue_id(checkAPIerrors, capfd):
    with capfd.disabled():
        from Wiz import clear_issue_due_date

        res = clear_issue_due_date('12345678-2222-3333-1111-ff5fa2ff7f71')
        assert res == "Could not find Issue with ID 12345678-2222-3333-1111-ff5fa2ff7f71"


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
    with capfd.disabled():
        with patch('requests.post') as mocked_request:
            with pytest.raises(Exception):
                mocked_request().return_value = test_bad_token_response
                from Wiz import get_token

                res = get_token()
                assert res == test_bad_token_response


def test_good_token(capfd, mocker):
    with capfd.disabled():
        good_token = str(random.randint(1, 1000))
        mocker.patch('requests.post', return_value=mocked_requests_get({"access_token": good_token}, 200))

        from Wiz import get_token
        res = get_token()
        assert res == good_token


def test_token_no_access(capfd, mocker):
    with capfd.disabled():
        mocker.patch('requests.post', return_value=mocked_requests_get({}, 200))
        try:
            from Wiz import get_token
            get_token()
        except Exception as e:
            assert str(e) == 'Could not retrieve token from Wiz: None'


def test_check_api_access(capfd, mocker):
    with capfd.disabled():
        good_token = str(random.randint(1, 1000))
        mocker.patch('requests.post', return_value=mocked_requests_get({"access_token": good_token}, 200))
        from Wiz import checkAPIerrors
        checkAPIerrors(query='test', variables='test')

        try:
            mocker.patch('Wiz.get_token', return_value=TEST_TOKEN)
            mocker.patch('requests.post', side_effect=Exception('bad request'))
            checkAPIerrors(query='test', variables='test')
        except Exception as e:
            assert str(e) == 'bad request'


def test_check_api_access_bad_gw(capfd, mocker):
    with capfd.disabled():
        from Wiz import checkAPIerrors
        mocker.patch('requests.post', side_effect=Exception('502: Bad Gateway'))

        try:
            checkAPIerrors(query='test', variables='test')
        except Exception as e:
            assert '502: Bad Gateway' in str(e)


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
