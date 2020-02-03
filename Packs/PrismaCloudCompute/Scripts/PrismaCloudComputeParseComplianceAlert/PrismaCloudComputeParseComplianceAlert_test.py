from PrismaCloudComputeParseComplianceAlert import parse_compliance
import pytest
import json


def test_parse_compliance():
    valid_raw_json = json.dumps({
        "_id": "testID",
        "compliance": [
            {
                "description": "testDescription",
                "id": "testID",
                "type": "testType"
            }
        ],
        "kind": "compliance",
        "time": "1970-01-01T00:00:00.000Z",
        "type": "host"
    })

    no_kind_raw_json = json.dumps({
        '_id': 'testID',
        'time': '1970-01-01T00:00:00.000Z'})

    wrong_kind_raw_json = json.dumps({
        '_id': 'testID',
        'time': '1970-01-01T00:00:00.000Z',
        'kind': 'wrongKind'})

    tests = [
        {'input': valid_raw_json,
         'expectedException': False,
         'expectedResult': {
             'readable':
                 r'''### Compliance Information
|time|type|
|---|---|
| 1970-01-01T00:00:00.000Z | host |
### Compliance
|description|id|type|
|---|---|---|
| testDescription | testID | testType |
''',
             'output': {'PrismaCloudCompute.ComplianceAlert': json.loads(valid_raw_json)},
             'raw': valid_raw_json}

         },
        {
            'input': no_kind_raw_json,
            'expectedException': True,
        },
        {
            'input': wrong_kind_raw_json,
            'expectedException': True,
        }
    ]

    for test in tests:
        if test['expectedException']:
            with pytest.raises(Exception) as ex:
                parse_compliance(test['input'])
            assert str(ex.value) == f"Input should be a raw JSON compliance alert, received: {test['input']}"
        else:
            assert parse_compliance(test['input']) == (
                test['expectedResult']['readable'], test['expectedResult']['output'], test['expectedResult']['raw'])
