from ExpansePrintSuggestions import expanse_print_suggestions
import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
import json
import io


MOCK_IP = "198.51.101.1"
MOCK_PORT = "8888"
MOCK_FQDN = "test.developers.example.com"
MOCK_REGION = "us-west-2"
MOCK_SERVICE = "EC2" 
MOCK_PROVIDER = "Amazon Web Services"
MOCK_BUSINESS_UNITS = "R&D"
MOCK_ISSUE_TAGS = "Engineering,Suspicious"
MOCK_ASSET_TAGS = "Engineering"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())

def util_load_raw(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return f.read()

def test_match_ip_in_cidr_indicators(mocker):
    mock_users = util_load_json('test_data/expanse_users.json')
    mock_ips = util_load_json('test_data/expanse_ips.json')
    mock_devices = util_load_json('test_data/expanse_devices.json')
    mock_prisma = util_load_json('test_data/prisma_cloud.json')
    mock_shadowit = util_load_json('test_data/shadow_it.json')

    mock_markdown_result = util_load_raw('test_data/output.md')

    result = expanse_print_suggestions({
        'ip': MOCK_IP,
        'port': MOCK_PORT,
        'fqdn': MOCK_FQDN,
        'provider': MOCK_PROVIDER,
        'region': MOCK_REGION,
        'service': MOCK_SERVICE,
        'expansebusinessunits': MOCK_BUSINESS_UNITS,
        'expanseissuetags': MOCK_ISSUE_TAGS,
        'expanseassettags': MOCK_ASSET_TAGS,
        'expanseusers': mock_users,
        'expansedevices': mock_devices,
        'expanseips': mock_ips,
        'prismacloudassets': mock_prisma,
        'shadowit': mock_shadowit
    })

    assert result.readable_output == mock_markdown_result

