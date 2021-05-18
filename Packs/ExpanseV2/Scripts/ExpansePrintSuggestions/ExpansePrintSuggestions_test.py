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
    """
    Given:
        - inputs for the report:
          - list of users
          - list of ips
          - list of devices
          - list of prisma cloud observations
          - shadow it reasons suggestions
          - incident data: ip, port, provider
          - public cloud info: cloud provider region and service
          - expanse data: business units, asset tags, issue tags
    When
        - Generating the attribution report in the Expanse Playbook
    Then
        - The proper markdown report is generated
    """
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
        'expanse_business_units': MOCK_BUSINESS_UNITS,
        'expanse_issue_tags': MOCK_ISSUE_TAGS,
        'expanse_asset_tags': MOCK_ASSET_TAGS,
        'expanse_users': mock_users,
        'expanse_devices': mock_devices,
        'expanse_ips': mock_ips,
        'prisma_cloud_assets': mock_prisma,
        'shadow_it': mock_shadowit
    })

    assert result.readable_output == mock_markdown_result
