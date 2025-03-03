import json
import os
import pytest
from CheckPointDome9 import Client
'''MOCK PARAMETERS '''
KEY_SECRET = "key_secret"
KEY_ID = "key_id"
'''CONSTANTS'''
BASE_URL = 'https://api.dome9.com/v2/'


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """

    with open(os.path.join('test_data', file_name), encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client():
    return Client(base_url=BASE_URL, key_id=KEY_ID, key_secret=KEY_SECRET, proxy=False, verify=True)


def test_access_lease_list_command(requests_mock, mock_client):
    """
    Scenario: Get all access lease.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-access-lease-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import access_lease_list_command

    mock_response = load_mock_response('access_lease_list.json')
    url = f'{BASE_URL}AccessLease'

    requests_mock.get(url=url, json=mock_response)

    result = access_lease_list_command(mock_client, {})

    assert result.outputs_prefix == 'CheckPointDome9.AccessLease'
    assert len(result.outputs[0]) == 15
    assert result.outputs[0]['id'] == 'id'


def test_access_lease_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete an access lease.
    Given:
    - User has provided valid credentials.
    - Access lease ID.
    When:
    - dome9-access-lease-delete called.
    Then:
    - Ensure number of items is correct.
    - Ensure outputs prefix is correct.
    - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import access_lease_delete_command

    mock_response = ''
    lease_id = 'lease_id'
    url = f'{BASE_URL}AccessLease/{lease_id}'
    requests_mock.delete(url=url, json=mock_response)

    result = access_lease_delete_command(mock_client, {'lease_id': lease_id})

    assert result.outputs_prefix == 'CheckPointDome9.AccessLease'


def test_access_lease_invitation_list_command(requests_mock, mock_client):
    """
    Scenario: Get all an access lease invitations.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-access-lease-invitation-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import access_lease_invitation_list_command

    mock_response = load_mock_response('access_lease_invitation_list.json')
    invitation_id = 'invitation_id'
    url = f'{BASE_URL}AccessLeaseInvitation/{invitation_id}'

    requests_mock.get(url=url, json=mock_response)

    result = access_lease_invitation_list_command(mock_client, {'invitation_id': invitation_id})

    assert result.outputs_prefix == 'CheckPointDome9.AccessLease.Invitation'
    assert len(result.outputs[0]) == 11
    assert result.outputs[0]['id'] == 'id'


def test_access_lease_invitation_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete an access lease invitation.
    Given:
    - User has provided valid credentials.
    - access lease invitation ID.
    When:
    - dome9-access-lease-invitation-delete called.
    Then:
    - Ensure number of items is correct.
    - Ensure outputs prefix is correct.
    - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import access_lease_invitation_delete_command

    mock_response = ''
    invitation_id = 'invitation_id'
    url = f'{BASE_URL}AccessLeaseInvitation/{invitation_id}'
    requests_mock.delete(url=url, json=mock_response)

    result = access_lease_invitation_delete_command(mock_client, {'invitation_id': invitation_id})

    assert result.outputs_prefix == 'CheckPointDome9.AccessLease.Invitation'


def test_ip_list_create_command(requests_mock, mock_client):
    """
    Scenario: Create IP list.
    Given:
     - User has provided valid credentials.
     - IP list name, description and items (IPs and comments).
    When:
     - dome9-ip-list-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_create_command

    mock_response = load_mock_response('ip_list_create.json')
    url = f'{BASE_URL}IpList'

    requests_mock.post(url=url, json=mock_response)
    args = {'name': 'name', 'description': 'description', 'ip': 'ip', 'comment': 'comment'}
    result = ip_list_create_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.IpList'
    assert len(result.outputs) == 4
    assert result.outputs['id'] == 'id'


def test_ip_list_update_command(requests_mock, mock_client):
    """
    Scenario: Update IP list.
    Given:
     - User has provided valid credentials.
     - IP list ID, description, update mode and items (IPs and comments).
    When:
     - dome9-ip-list-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_update_command

    mock_response = ''
    list_id = 'list_id'
    url = f'{BASE_URL}IpList/{list_id}'

    requests_mock.put(url=url, json=mock_response)
    args = {
        'list_id': list_id,
        'description': 'description',
        'ip': 'ip',
        'comment': 'comment',
        'update_mode': 'replace'
    }
    result = ip_list_update_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.IpList'


def test_ip_list_get_command(requests_mock, mock_client):
    """
    Scenario: Get IP list.
    Given:
     - User has provided valid credentials.
     - IP list ID.
    When:
     - dome9-ip-list-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_get_command

    mock_response = load_mock_response('ip_list_get.json')
    list_id = 'list_id'
    url = f'{BASE_URL}IpList/{list_id}'

    requests_mock.get(url=url, json=mock_response)
    args = {'list_id': list_id}
    result = ip_list_get_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.IpList'
    assert len(result.outputs[0]) == 4
    assert result.outputs[0]['id'] == 'id'


def test_ip_list_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete an IP list.
    Given:
     - User has provided valid credentials.
     - IP list ID.
    When:
     - dome9-ip-list-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_delete_command

    mock_response = ''
    list_id = 'list_id'
    url = f'{BASE_URL}IpList/{list_id}'

    requests_mock.delete(url=url, json=mock_response)
    args = {'list_id': list_id}
    result = ip_list_delete_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.IpList'


def test_ip_list_metadata_create_command(requests_mock, mock_client):
    """
    Scenario: Create IP list metadata.
    Given:
     - User has provided valid credentials.
     - IP list metadata name, description, cidr and classification.
    When:
     - dome9-ip-list-metadata-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_metadata_create_command

    mock_response = load_mock_response('ip_list_metadata_create_update.json')
    url = f'{BASE_URL}IpAddressMetadata'

    requests_mock.post(url=url, json=mock_response)
    args = {'name': 'name', 'cidr': 'cidr', 'classification': 'classification'}
    result = ip_list_metadata_create_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.IpList.Metadata'
    assert len(result.outputs) == 5
    assert result.outputs['id'] == 'id'


def test_ip_list_metadata_update_command(requests_mock, mock_client):
    """
    Scenario: Update IP list metadata.
    Given:
     - User has provided valid credentials.
     - IP list metadata ID, name and classification.
    When:
     - dome9-ip-list-metadata-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_metadata_update_command

    mock_response = load_mock_response('ip_list_metadata_create_update.json')
    url = f'{BASE_URL}IpAddressMetadata'

    requests_mock.put(url=url, json=mock_response)
    args = {
        'list_metadata_id': 'list_metadata_id',
        'classification': 'classification',
        'name': 'name'
    }
    result = ip_list_metadata_update_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.IpList.Metadata'
    assert len(result.outputs) == 5
    assert result.outputs['id'] == 'id'


def test_ip_list_metadata_list_command(requests_mock, mock_client):
    """
    Scenario: Get IP list metadata.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-ip-list-metadata-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_metadata_list_command

    mock_response = load_mock_response('ip_list_metadata_list.json')
    url = f'{BASE_URL}IpAddressMetadata'

    requests_mock.get(url=url, json=mock_response)
    result = ip_list_metadata_list_command(mock_client, {})

    assert result.outputs_prefix == 'CheckPointDome9.IpList.Metadata'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'id'


def test_ip_list_metadata_delete_command(requests_mock, mock_client):
    """
    Scenario: DElete IP list metadata.
    Given:
     - User has provided valid credentials.
     - IP list metadata ID, address and mask.
    When:
     - dome9-ip-list-metadata-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import ip_list_metadata_delete_command

    mock_response = ''
    url = f'{BASE_URL}IpAddressMetadata'

    requests_mock.delete(url=url, json=mock_response)
    args = {'account_id': 'account_id', 'address': 'address', 'mask': 'mask'}
    result = ip_list_metadata_delete_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.IpList.Metadata'


def test_compliance_remediation_create_command(requests_mock, mock_client):
    """
    Scenario: Create compliance remediation.
    Given:
     - User has provided valid credentials.
     - Ruleset ID, Rule logic hash, comment and cloudbots.
    When:
     - dome9-compliance-remediation-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import compliance_remediation_create_command

    mock_response = load_mock_response('compliance_remediation_create_update.json')
    url = f'{BASE_URL}ComplianceRemediation'

    requests_mock.post(url=url, json=mock_response)
    args = {
        'ruleset_id': '1',
        'rule_logic_hash': 'rule_logic_hash',
        'comment': 'comment',
        'cloudbots': 'cloudbots'
    }

    result = compliance_remediation_create_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.ComplianceRemediation'
    assert len(result.outputs) == 10
    assert result.outputs['id'] == 'id'


def test_compliance_remediation_update_command(requests_mock, mock_client):
    """
    Scenario: Update compliance remediation.
    Given:
     - User has provided valid credentials.
     - Remediation ID, Ruleset ID, Rule logic hash, comment and cloudbots.
    When:
     - dome9-compliance-remediation-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import compliance_remediation_update_command

    mock_response = load_mock_response('compliance_remediation_create_update.json')
    url = f'{BASE_URL}ComplianceRemediation'

    requests_mock.put(url=url, json=mock_response)
    args = {
        'remediation_id': 'remediation_id',
        'ruleset_id': '1',
        'rule_logic_hash': 'rule_logic_hash',
        'comment': 'comment',
        'cloudbots': 'cloudbots'
    }
    result = compliance_remediation_update_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.ComplianceRemediation'
    assert len(result.outputs) == 10
    assert result.outputs['id'] == 'id'


def test_compliance_remediation_get_command(requests_mock, mock_client):
    """
    Scenario: Get compliance remediation.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-compliance-remediation-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import compliance_remediation_get_command

    mock_response = load_mock_response('compliance_remediation_get.json')
    url = f'{BASE_URL}ComplianceRemediation'

    requests_mock.get(url=url, json=mock_response)
    result = compliance_remediation_get_command(mock_client, {})

    assert result.outputs_prefix == 'CheckPointDome9.ComplianceRemediation'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'id'


def test_compliance_remediation_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete compliance remediation.
    Given:
     - User has provided valid credentials.
     - Remediation ID.
    When:
     - dome9-compliance-remediation-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import compliance_remediation_delete_command

    mock_response = ''
    remediation_id = 'remediation_id'
    url = f'{BASE_URL}ComplianceRemediation/{remediation_id}'

    requests_mock.delete(url=url, json=mock_response)
    args = {'remediation_id': remediation_id}
    result = compliance_remediation_delete_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.ComplianceRemediation'


def test_compliance_ruleset_list_command(requests_mock, mock_client):
    """
    Scenario: Get compliance ruleset list.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-compliance-ruleset-list-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import compliance_ruleset_list_command

    mock_response = load_mock_response('compliance_ruleset_list.json')
    url = f'{BASE_URL}Compliance/Ruleset/view'

    requests_mock.get(url=url, json=mock_response)
    result = compliance_ruleset_list_command(mock_client, {})

    assert result.outputs_prefix == 'CheckPointDome9.ComplianceRuleset'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'id'


def test_compliance_ruleset_rule_list_command(requests_mock, mock_client):
    """
    Scenario: Get compliance ruleset rule list.
    Given:
     - User has provided valid credentials.
     - Rule ID.
    When:
     - dome9-compliance-ruleset-rule-list-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import compliance_ruleset_rule_list_command

    mock_response = load_mock_response('compliance_ruleset_rule_list.json')
    rule_id = 'rule_id'
    url = f'{BASE_URL}Compliance/Ruleset/{rule_id}'

    requests_mock.get(url=url, json=mock_response)
    result = compliance_ruleset_rule_list_command(mock_client, {'rule_id': rule_id})

    assert result.outputs_prefix == 'CheckPointDome9.ComplianceRuleset.Rule'
    assert len(result.outputs) == 2
    assert result.outputs_key_field == 'name'


def test_global_search_get_command(requests_mock, mock_client):
    """
    Scenario: Get global search list.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-global-search-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import global_search_get_command

    mock_response = load_mock_response('global_search_get.json')
    url = f'{BASE_URL}GlobalSearch'

    requests_mock.get(url=url, json=mock_response)
    result = global_search_get_command(mock_client, {})

    assert result.outputs_prefix == 'CheckPointDome9.GlobalSearch.Alert'
    assert len(result.outputs) == 0
    assert result.outputs_key_field == 'id'


def test_cloud_accounts_list_command(requests_mock, mock_client):
    """
    Scenario: Get cloud accounts list.
    Given:
     - User has provided valid credentials.
     - Account ID.
    When:
     - dome9-cloud-accounts-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import cloud_accounts_list_command

    mock_response = load_mock_response('cloud_accounts_list.json')
    account_id = 'account_id'
    url = f'{BASE_URL}CloudAccounts/{account_id}'

    requests_mock.get(url=url, json=mock_response)
    result = cloud_accounts_list_command(mock_client, {'account_id': account_id})

    assert result.outputs_prefix == 'CheckPointDome9.CloudAccount'
    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'cloud_account_id'


def test_instance_list_command(requests_mock, mock_client):
    """
    Scenario: Get instance list.
    Given:
     - User has provided valid credentials.
     - Instance ID.
    When:
     - dome9-instance-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import instance_list_command

    mock_response = load_mock_response('instance_list.json')
    instance_id = 'instance_id'
    url = f'{BASE_URL}cloudinstance/{instance_id}'

    requests_mock.get(url=url, json=mock_response)
    args = {'instance_id': instance_id, 'page': '1', 'page_size': '5'}

    result = instance_list_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.Instance'
    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'instance_id'


def test_organizational_unit_view_get_command(requests_mock, mock_client):
    """
    Scenario: Get organizational unit view.
    Given:
     - User has provided valid credentials.
     - Instance ID.
    When:
     - dome9-organizational-unit-view-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import organizational_unit_view_get_command

    mock_response = load_mock_response('organizational_unit_view_get.json')
    url = f'{BASE_URL}organizationalunit/view'

    requests_mock.get(url=url, json=mock_response)
    args = {}

    result = organizational_unit_view_get_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.OrganizationalUnitView'
    assert len(result.outputs) == 4
    assert result.outputs_key_field == 'id'


def test_check_ip_list_security_group_attach_command(requests_mock, mock_client):
    """
    Scenario: Get AWS cloud accounts for a specific security group and region
            and check if there is an IP-list that attach to a security group.
    Given:
     - User has provided valid credentials.
     - Security group ID.
    When:
     - dome9-security-group-ip-list-details-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import check_ip_list_security_group_attach_command

    mock_response = load_mock_response('check_ip_list_security_group_attach.json')
    sg_id = 'sg_id'
    url = f'{BASE_URL}CloudSecurityGroup/{sg_id}'

    requests_mock.get(url=url, json=mock_response)
    args = {'sg_id': sg_id}

    result = check_ip_list_security_group_attach_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.SecurityGroup'
    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'security_group_id'


def test_finding_get_command(requests_mock, mock_client):
    """
    Scenario: Get finding by ID.
    Given:
     - User has provided valid credentials.
     - Finding ID.
    When:
     - dome9-finding-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import finding_get_command

    mock_response = load_mock_response('finding_get.json')
    finding_id = 'finding_id'
    url = f'{BASE_URL}Compliance/Finding/{finding_id}'

    requests_mock.get(url=url, json=mock_response)
    args = {'finding_id': finding_id}

    result = finding_get_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.Finding'
    assert len(result.outputs) == 44
    assert result.outputs_key_field == 'id'


def test_findings_search_command(requests_mock, mock_client):
    """
    Scenario: Search findings by severity and region.
    Given:
     - User has provided valid credentials.
     - Findings severity and region.
    When:
     - dome9-findings-search called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import findings_search_command

    mock_response = load_mock_response('findings_search.json')
    url = f'{BASE_URL}Compliance/Finding/search'

    requests_mock.post(url=url, json=mock_response)
    args = {'severity': 'severity', 'region': 'region'}

    result = findings_search_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.Finding'
    assert len(result.outputs) == 2
    assert result.outputs_key_field == 'id'


def test_security_group_list_command(requests_mock, mock_client):
    """
    Scenario: Get security group list.
    Given:
     - User has provided valid credentials.
    When:
     - dome9-security-group-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_list_command

    mock_response = load_mock_response('security_group_list.json')
    url = f'{BASE_URL}AwsSecurityGroup'

    requests_mock.get(url=url, json=mock_response)
    args = {}

    result = security_group_list_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.SecurityGroup'
    assert len(result.outputs) == 2
    assert result.outputs_key_field == 'security_group_id'


def test_security_group_protection_mode_update_command(requests_mock, mock_client):
    """
    Scenario: Change the protection mode for an AWS security group (FullManage or ReadOnly).
    Given:
     - User has provided valid credentials.
     - Security group ID and protection mode.
    When:
     - dome9-security-group-protection-mode-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_protection_mode_update_command

    mock_response = load_mock_response('security_group_protection_mode_update.json')
    sg_id = 'sg_id'
    url = f'{BASE_URL}cloudsecuritygroup/{sg_id}/protection-mode'

    requests_mock.post(url=url, json=mock_response)
    args = {'protection_mode': 'protection_mode', 'sg_id': sg_id}

    result = security_group_protection_mode_update_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.SecurityGroup'
    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'security_group_id'


def test_security_group_service_update_command(requests_mock, mock_client):
    """
    Scenario: Update security group service.
    Given:
     - User has provided valid credentials.
     - Security group ID, policy type, port, protocol type and service name.
    When:
     - dome9-security-group-service-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_service_update_command

    mock_response = load_mock_response('security_group_service_create_update.json')
    sg_id = 'sg_id'
    policy_type = 'policy_type'
    url = f'{BASE_URL}cloudsecuritygroup/{sg_id}/services/{policy_type}'

    requests_mock.put(url=url, json=mock_response)
    args = {
        'sg_id': sg_id,
        'policy_type': 'policy_type',
        'port': '5',
        'protocol_type': 'protocol_type',
        'service_name': 'service_name'
    }

    result = security_group_service_update_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.SecurityGroup.Service'
    assert len(result.outputs) == 10
    assert result.outputs_key_field == 'id'


def test_security_group_service_create_command(requests_mock, mock_client):
    """
    Scenario: Create security group service.
    Given:
     - User has provided valid credentials.
     - Security group ID, policy type, port, protocol type and service name.
    When:
     - dome9-security-group-service-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_service_create_command

    mock_response = load_mock_response('security_group_service_create_update.json')
    sg_id = 'sg_id'
    policy_type = 'policy_type'
    url = f'{BASE_URL}cloudsecuritygroup/{sg_id}/services/{policy_type}'

    requests_mock.post(url=url, json=mock_response)
    args = {
        'sg_id': sg_id,
        'policy_type': 'policy_type',
        'port': '5',
        'protocol_type': 'protocol_type',
        'service_name': 'service_name'
    }

    result = security_group_service_create_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.SecurityGroup.Service'
    assert len(result.outputs) == 10
    assert result.outputs_key_field == 'id'


def test_security_group_service_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete security group service.
    Given:
     - User has provided valid credentials.
     - Security group ID and service ID.
    When:
     - dome9-security-group-service-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_service_delete_command

    mock_response = ''
    sg_id = 'sg_id'
    service_id = 'service_id'
    url = f'{BASE_URL}cloudsecuritygroup/{sg_id}/services/Inbound/{service_id}'

    requests_mock.delete(url=url, json=mock_response)
    args = {'sg_id': sg_id, 'service_id': service_id}

    result = security_group_service_delete_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.SecurityGroup.Service'
    assert result.outputs_key_field == 'id'


def test_security_group_tags_update_command(requests_mock, mock_client):
    """
    Scenario: Create and update security group tags.
    Given:
     - User has provided valid credentials.
     - Security group ID, key and value.
    When:
     - dome9-security-group-tags-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_tags_update_command

    mock_response = load_mock_response('security_group_tags.json')
    sg_id = 'sg_id'
    url = f'{BASE_URL}cloudsecuritygroup/{sg_id}/tags'

    requests_mock.post(url=url, json=mock_response)
    args = {'sg_id': sg_id, 'key': 'key', 'value': 'value'}

    result = security_group_tags_update_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.SecurityGroup.Tag'
    assert len(result.outputs) == 2
    assert result.outputs_key_field == 'key'


def test_security_group_instance_attach_command(requests_mock, mock_client):
    """
    Scenario: Attach security Group to an AWS EC2 Instance.
    Given:
     - User has provided valid credentials.
     - Instance ID, security group ID and nic name.
    When:
     - dome9-security-group-instance-attach called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_instance_attach_command

    mock_response = load_mock_response('security_group_attach_detach.json')
    instance_id = 'instance_id'
    url = f'{BASE_URL}cloudinstance/{instance_id}/sec-groups'

    requests_mock.post(url=url, json=mock_response)
    args = {'sg_id': 'sg_id', 'instance_id': instance_id, 'nic_name': 'nic_name'}

    result = security_group_instance_attach_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.Instance'
    assert result.outputs_key_field == 'id'


def test_security_group_instance_detach_command(requests_mock, mock_client):
    """
    Scenario: Detach security Group to an AWS EC2 Instance.
    Given:
     - User has provided valid credentials.
     - Instance ID, security group ID and nic name.
    When:
     - dome9-security-group-instance-detach called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CheckPointDome9 import security_group_instance_detach_command

    mock_response = load_mock_response('security_group_attach_detach.json')
    instance_id = 'instance_id'
    url = f'{BASE_URL}cloudinstance/{instance_id}/sec-groups'

    requests_mock.delete(url=url, json=mock_response)
    args = {'sg_id': 'sg_id', 'instance_id': instance_id, 'nic_name': 'nic_name'}

    result = security_group_instance_detach_command(mock_client, args)

    assert result.outputs_prefix == 'CheckPointDome9.Instance'
    assert result.outputs_key_field == 'id'


@pytest.mark.parametrize(
    'page_size, page, limit',
    [
        (
            -1, 0, 10
        ),
        (
            5, -1, 5
        ),
        (
            5, 5, -1
        )
    ]
)
def test_validate_pagination_arguments(page_size, page, limit):
    """
    Given:
     - invalid values of page_size, page and limit

    When:
     - executing validate_pagination_arguments function

    Then:
     - Ensure that ValueError is raised
    """

    from CheckPointDome9 import validate_pagination_arguments
    with pytest.raises(ValueError):
        validate_pagination_arguments(page=page, page_size=page_size, limit=limit)


def test_attach_comment_to_ip_no_description():
    """
    Given:
     - no ip list and no description

    When:
     - executing attach_comment_to_ip function

    Then:
     - Ensure that ValueError is raised
    """
    from CheckPointDome9 import attach_comment_to_ip

    with pytest.raises(ValueError):
        attach_comment_to_ip(ip_list=[], comment_list=[])
