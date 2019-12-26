import demistomock as demisto
import CommonServerPython as csp
from pytest import raises

import json


def test_script(mocker):
    return_data = [
        [
            {
                'Contents':
                    [
                        {
                            'Name': 'Audit Projects',
                            'ID': 123,
                            'ShortName': 'bla bla',
                            'SystemName': 'bla bla'
                        }
                    ]
            }
        ],
        [
            {
                'Contents':
                    [
                        {
                            'DisplayName': 'cool project',
                            'ID': '1'
                        }
                    ]
            }
        ]
    ]
    mocker.patch.object(demisto, 'args', return_value={'task_id': 'This is task', 'project': 'cool project'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=return_data)
    spy = mocker.spy(csp, 'return_outputs')
    from KeylightCreateIssue import main

    main()
    assert json.loads(spy.mock_calls[0][1][0]) == [
        {
            "fieldName": "Task ID",
            "value": "This is task",
            "isLookup": False
        },
        {
            "fieldName": "Audit Project",
            "value": '1',
            "isLookup": True
        }
    ]

    # Can't find the wanted project
    mocker.patch.object(demisto, 'executeCommand', side_effect=return_data)
    mocker.patch.object(demisto, 'args', return_value={'task_id': 'This is task', 'project': 'uncool project'})
    with raises(ValueError):
        main()
