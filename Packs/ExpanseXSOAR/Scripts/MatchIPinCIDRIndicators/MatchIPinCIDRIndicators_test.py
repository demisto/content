from MatchIPinCIDRIndicators import match_ip_in_cidr_indicators
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from typing import List, Dict, Any
import json
import io

MOCK_IP = '44.224.1.1'
MOCK_QUERY = (
    'type:CIDR and tags:(AWS OR GCP OR Azure) and ( value:"44.224.1.1/32" or value:"44.224.1.0/31" or value:"44.224.1.0/30" or '
    'value:"44.224.1.0/29" or value:"44.224.1.0/28" or value:"44.224.1.0/27" or value:"44.224.1.0/26" or value:"44.224.1.0/25" '
    'or value:"44.224.1.0/24" or value:"44.224.0.0/23" or value:"44.224.0.0/22" or value:"44.224.0.0/21" or value:"44.224.0.0/2'
    '0" or value:"44.224.0.0/19" or value:"44.224.0.0/18" or value:"44.224.0.0/17" or value:"44.224.0.0/16" or value:"44.224.0.'
    '0/15" or value:"44.224.0.0/14" or value:"44.224.0.0/13" or value:"44.224.0.0/12" or value:"44.224.0.0/11" or value:"44.192'
    '.0.0/10" or value:"44.128.0.0/9" or value:"44.0.0.0/8")'
)
MOCK_RESULT = [
    {
        "CustomFields": {
            "region": "us-west-2",
            "service": "EC2",
            "tags": [
                "AWS",
                "AMAZON",
                "EC2"
            ]
        },
        "expiration": "2020-11-30T21:45:47.508283881Z",
        "expirationStatus": "active",
        "firstSeen": "2020-11-23T22:04:13.912289994Z",
        "id": "70575",
        "lastSeen": "2020-11-23T22:04:54.169032968Z",
        "score": 1,
        "sourceBrands": [
            "AWS Feed"
        ],
        "sourceInstances": [
            "AWS Feed_instance_1"
        ],
        "value": "44.224.0.0/11"
    }
]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_match_ip_in_cidr_indicators(mocker):
    mock_indicator = util_load_json('test_data/indicator.json')

    def executeCommand(name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name == 'findIndicators':
            if 'query' not in args or args['query'] != MOCK_QUERY:
                raise ValueError('Invalid query')
            return [{"Contents": mock_indicator}]

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = match_ip_in_cidr_indicators({
        'ip': MOCK_IP,
        'tags': 'AWS,GCP,Azure',
    })

    assert result.outputs_prefix == "MatchingCIDRIndicator"
    assert result.outputs_key_field == "value"
    assert result.outputs == MOCK_RESULT
    assert result.ignore_auto_extract is True
