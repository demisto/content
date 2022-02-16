from unittest.mock import patch

integration_params = {
    'url': 'http://test.io',
    'credentials': {'identifier': 'test', 'password': 'pass'},
    'fetch_time': '7 days',
}

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
