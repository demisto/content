from PrismaCloudAttribution import attribution_command
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
import json
import io

MOCK_RESULT = [
    {
        "accountId": "123456",
        "accountName": "aws-user-personal",
        "cloudType": "aws",
        "fqdn": [
            "application-lb-123456.us-east-1.elb.amazonaws.com"
        ],
        "hasAlert": False,
        "id": "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/application-lb/1398164320221c02",
        "ip": None,
        "regionId": "us-east-1",
        "resourceName": "application-lb",
        "resourceType": "Managed Load Balancer",
        "rrn": ("rrn::managedLb:us-east-1:123456:b38d940663c047b02c2116be49695cf353976dff:arn%3Aaws"
                "%3Aelasticloadbalancing%3Aus-east-1%3A123456%3Aloadbalancer%2Fapp%2Fapplication-lb"
                "%2F1398164320221c02"),
        "service": "Amazon Elastic Load Balancing"
    },
    {
        "accountId": "123456",
        "accountName": "aws-user-personal",
        "cloudType": "aws",
        "fqdn": [
            "ec2-35-180-1-1.eu-west-3.compute.amazonaws.com"
        ],
        "hasAlert": False,
        "id": "i-654321b",
        "ip": [
            "35.180.1.1"
        ],
        "regionId": "eu-west-3",
        "resourceName": "testvm",
        "resourceType": "Instance",
        "rrn": "rrn::instance:eu-west-3:123456:9db2db5fdba47606863c8da86d3ae594fb5aee2b:i-654321b",
        "service": "Amazon EC2"
    }
]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_match_ip_in_cidr_indicators(mocker):
    mock_assets = util_load_json('test_data/assets.json')

    result = attribution_command({
        'assets': mock_assets
    })

    assert result.outputs_prefix == "PrismaCloud.Attribution"
    assert result.outputs_key_field == "rrn"
    assert result.outputs == MOCK_RESULT
