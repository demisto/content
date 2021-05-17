from PrismaCloudComputeParseCloudDiscoveryAlert import parse_cloud_discovery
import pytest
import json


def test_parse_cloud_discovery():
    valid_raw_json = json.dumps({
        "_id": "ID",
        "time": "1970-01-01T00:00:00.000Z",
        "kind": "cloudDiscovery",
        "credentialId": "koko",
        "provider": "aws",
        "serviceType": "aws-ecs",
        "region": "eu-central-1",
        "protected": 0,
        "total": 1,
        "entities": [
            {
                "name": "name",
                "protected": False,
                "lastModified": "1970-01-01T00:00:00.000Z",
                "runtime": "",
                "version": "",
                "activeServicesCount": 5,
                "createdAt": "1970-01-01T00:00:00.000Z",
                "image": "image"
            }
        ]
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
                 r'''### Cloud Discovery Information
|credentialId|protected|provider|region|serviceType|time|total|
|---|---|---|---|---|---|---|
| koko | 0 | aws | eu-central-1 | aws-ecs | 1970-01-01T00:00:00.000Z | 1 |
### Discovered Entities
|activeServicesCount|createdAt|image|lastModified|name|protected|runtime|version|
|---|---|---|---|---|---|---|---|
| 5 | 1970-01-01T00:00:00.000Z | image | 1970-01-01T00:00:00.000Z | name | false |  |  |
''',
             'output': {'PrismaCloudCompute.CloudDiscoveryAlert': json.loads(valid_raw_json)},
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
                parse_cloud_discovery(test['input'])
            assert str(ex.value) == f"Input should be a raw JSON cloud discovery alert, received: {test['input']}"
        else:
            assert parse_cloud_discovery(test['input']) == (
                test['expectedResult']['readable'], test['expectedResult']['output'], test['expectedResult']['raw'])
