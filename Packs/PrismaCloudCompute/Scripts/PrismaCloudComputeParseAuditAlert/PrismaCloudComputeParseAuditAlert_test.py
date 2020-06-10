from PrismaCloudComputeParseAuditAlert import parse_audit
import pytest
import json


def test_parse_audit():
    valid_raw_json = json.dumps({
        "_id": "ID",
        "activityType": "",
        "appID": "",
        "category": "cat",
        "command": "",
        "container": "",
        "forensicLink": "",
        "fqdn": "",
        "function": "",
        "host": "host",
        "image": "",
        "interactive": False,
        "kind": "audit",
        "kubernetesResource": "",
        "labels": {},
        "line": "",
        "logfile": "",
        "message": "msg",
        "region": "",
        "rule": "koko",
        "runtime": "",
        "service": "",
        "time": "",
        "type": "hostRuntime",
        "user": ""
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
                 r'''### Audit Information
|_id|activityType|appID|category|command|container|forensicLink|fqdn|function|host|image|interactive|kind|kubernetesResource|labels|line|logfile|message|region|rule|runtime|service|time|type|user|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ID |  |  | cat |  |  |  |  |  | host |  | false | audit |  |  |  |  | msg |  | koko |  |  |  | hostRuntime |  |
''',
             'output': {'PrismaCloudCompute.AuditAlert': json.loads(valid_raw_json)},
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
                parse_audit(test['input'])
            assert str(ex.value) == f"Input should be a raw JSON audit alert, received: {test['input']}"
        else:
            assert parse_audit(test['input']) == (
                test['expectedResult']['readable'], test['expectedResult']['output'], test['expectedResult']['raw'])
