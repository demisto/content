import demistomock as demisto


def test_script(mocker):
    return_data = [
        [
            {'Contents':
                 [
                     {'Name': 'Audit Projects',
                    'ID': 123,
                    'ShortName': 'bla bla',
                    'SystemName': 'bla bla'
                      }
                 ]
            }
        ],
        [
            {'Contents': [{
                'DisplayName': 'cool project',
                'ID': '1'
            }]
             }
        ]
    ]
    mocker.patch.object(demisto, 'args', return_value={'task_id': 'This is task', 'project': 'cool project'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=return_data)
    mocker.patch('return_outputs')
    from KeylightCreateIssue import main
    return_outputs.
    assert data == [
        {
            "fieldName": "Task ID",
            "value": "3",
            "isLookup": False
        },
        {
            "fieldName": "Audit Project",
            "value": 3,
            "isLookup": true
        }
    ]

