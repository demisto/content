import json
import os
from typing import Any

import Fortimail
import pytest
from CommonServerPython import *

TEST_DATA = "test_data"
BASE_URL = "https://www.example.com"
API_URL = urljoin(BASE_URL, "api/v1")
EXAMPLE_COOKIE = {"cookie_name": "cookie_name", "cookie_value": "cookie_value"}
ENTITY_ENDPOINT = {
    "RecipientPolicy": {
        "DELETE": "domain/system/PolicyRcpt/1",
        "GET": "domain/system/PolicyRcpt/1",
    },
    "AccessControl": {
        "DELETE": "MailSetAccessRule/1",
        "GET": "MailSetAccessRule/1",
    },
    "IPPolicy": {
        "DELETE": "PolicyIp/1",
        "GET": "PolicyIp/1",
    },
    "EmailGroupMember": {
        "DELETE": "ProfEmail_address_group/group_name/ProfEmail_address_groupEmailAddressGroupMember/email@email.com",
        "GET": "ProfEmail_address_group/group_name/ProfEmail_address_groupEmailAddressGroupMember/email@email.com",
    },
    "IPGroup": {
        "DELETE": "ProfIp_address_group/name",
        "GET": "ProfIp_address_group/name",
    },
    "IPGroupMember": {
        "DELETE": "ProfIp_address_group/group_name/ProfIp_address_groupIpAddressGroupMember/ip",
        "GET": "ProfIp_address_group/group_name/ProfIp_address_groupIpAddressGroupMember/",
    },
    "EmailGroup": {
        "DELETE": "ProfEmail_address_group/name",
        "GET": "ProfEmail_address_group/name",
    },
    "SystemList": {
        "DELETE": "SenderListV2/system/",
        "GET": "SenderListV2/system/",
    },
}


def load_mock_response(file_name: str) -> dict[str, Any]:
    """Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        dict[str, Any]: Mock file content.
    """
    file_path = os.path.join(TEST_DATA, file_name)

    with open(file_path, encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def mock_client() -> Fortimail.Client:
    """
    Establish a mock connection to the client with a user name and password.

    Returns:
        Client: Mock connection to client.
    """
    set_integration_context(EXAMPLE_COOKIE)
    return Fortimail.Client(
        server_url=BASE_URL,
        user_name="test",
        password="test",
    )


@pytest.mark.parametrize(
    "command_args, endpoint_suffix, outputs_prefix, response_file",
    [
        (
            {
                "command_name": "fortimail-pki-user-list",
                "all_results": True,
                "limit": 50,
            },
            "UserPki",
            "PkiUser",
            "pki_user.json",
        ),
        (
            {
                "command_name": "fortimail-tls-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfTls",
            "TlsProfile",
            "tls_profile.json",
        ),
        (
            {
                "command_name": "fortimail-recipient-policy-list",
                "all_results": True,
                "limit": 50,
            },
            "domain/system/PolicyRcpt",
            "RecipientPolicy",
            "recipient_policy.json",
        ),
        (
            {
                "command_name": "fortimail-ldap-group-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfLdap",
            "LdapGroup",
            "ldap_group.json",
        ),
        (
            {
                "command_name": "fortimail-geoip-group-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfGeoip",
            "GeoipGroup",
            "geoip_group.json",
        ),
        (
            {
                "command_name": "fortimail-antispam-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfAntispam",
            "AntispamProfile",
            "antispam_profile.json",
        ),
        (
            {
                "command_name": "fortimail-antivirus-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfAntivirus",
            "AntivirusProfile",
            "antivirus_profile.json",
        ),
        (
            {
                "command_name": "fortimail-content-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfContent",
            "ContentProfile",
            "content_profile.json",
        ),
        (
            {
                "command_name": "fortimail-ip-pool-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfIp_pool",
            "IPPool",
            "ip_pool.json",
        ),
        (
            {
                "command_name": "fortimail-session-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfSession",
            "SessionProfile",
            "session_profile.json",
        ),
        (
            {
                "command_name": "fortimail-access-control-list",
                "all_results": True,
                "limit": 50,
            },
            "MailSetAccessRule",
            "AccessControl",
            "access_control.json",
        ),
        (
            {
                "command_name": "fortimail-ip-policy-list",
                "all_results": True,
                "limit": 50,
            },
            "PolicyIp",
            "IPPolicy",
            "ip_policy.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-member-list",
                "all_results": True,
                "limit": 50,
                "group_name": "group_name",
            },
            "ProfEmail_address_group/group_name/ProfEmail_address_groupEmailAddressGroupMember",
            "EmailGroupMember",
            "email_group_member.json",
        ),
        (
            {
                "command_name": "fortimail-ip-group-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfIp_address_group",
            "IPGroup",
            "ip_group.json",
        ),
        (
            {
                "command_name": "fortimail-ip-group-member-list",
                "all_results": True,
                "limit": 50,
                "group_name": "group_name",
            },
            "ProfIp_address_group/group_name/ProfIp_address_groupIpAddressGroupMember/",
            "IPGroupMember",
            "ip_group_member.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfEmail_address_group",
            "EmailGroup",
            "email_group.json",
        ),
        (
            {
                "command_name": "fortimail-smtp-auth-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfAuthSmtp",
            "SmtpAuthProfile",
            "smtp_auth_profile.json",
        ),
        (
            {
                "command_name": "fortimail-resource-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfMisc",
            "ResourceProfile",
            "resource_profile.json",
        ),
        (
            {
                "command_name": "fortimail-imap-auth-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfAuthImap",
            "ImapAuthProfile",
            "imap_auth_profile.json",
        ),
        (
            {
                "command_name": "fortimail-radius-auth-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfAuthRadius",
            "RadiusAuthProfile",
            "radius_auth_profile.json",
        ),
        (
            {
                "command_name": "fortimail-pop3-auth-profile-list",
                "all_results": True,
                "limit": 50,
            },
            "ProfAuthPop3",
            "Pop3AuthProfile",
            "pop3_auth_profile.json",
        ),
        (
            {
                "command_name": "fortimail-system-safe-block-list",
                "list_type": "Blocklist",
                "all_results": True,
                "limit": 50,
            },
            "SenderListV2/system/",
            "SystemList",
            "system_safe_block_list.json",
        ),
    ],
)
def test_list_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    endpoint_suffix: str,
    outputs_prefix: str,
    response_file: str,
):
    """
    Scenario:
    - Test retrieving a list of objects.

    Given:
    - command_args, endpoint_suffix, response_file.

    When:
    - "fortimail-pki-user-list"
    - "fortimail-recipient-policy-list"
    - "fortimail-tls-profile-list"
    - "fortimail-ldap-group-list"
    - "fortimail-geoip-group-list"
    - "fortimail-antispam-profile-list"
    - "fortimail-antivirus-profile-list"
    - "fortimail-content-profile-list"
    - "fortimail-ip-pool-list"
    - "fortimail-session-profile-list"
    - "fortimail-access-control-list"
    - "fortimail-ip-policy-list"
    - "fortimail-email-group-member-list"
    - "fortimail-system-safe-block-list"
    - "fortimail-ip-group-list"
    - "fortimail-ip-group-member-list"
    - "fortimail-email-group-list"
    - "fortimail-smtp-auth-profile-list"
    - "fortimail-resource-profile-list"
    - "fortimail-imap-auth-profile-list"
    - "fortimail-radius-auth-profile-list"
    - "fortimail-pop3-auth-profile-list"

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    outputs_key_field = "mkey"
    response = load_mock_response(response_file)
    updated_response = Fortimail.map_api_response_values_to_readable_string(response)
    _, outputs = Fortimail.prepare_outputs_and_readable_output(output=updated_response, command_args=command_args)

    if outputs_prefix == "SystemList":
        requests_mock.post(
            url=urljoin(API_URL, endpoint_suffix),
            json=response,
        )
        outputs_key_field = "item"
    else:
        requests_mock.get(
            url=urljoin(API_URL, endpoint_suffix),
            json=response,
        )

    _, outputs_prefix = Fortimail.get_command_entity(command_name=command_args["command_name"])

    command_results = Fortimail.list_command(mock_client, command_args)

    assert command_results.raw_response == response
    assert command_results.outputs_prefix == f"FortiMail.{outputs_prefix}"
    assert command_results.outputs_key_field == outputs_key_field
    assert command_results.outputs == outputs


@pytest.mark.parametrize(
    "command_args, outputs_prefix, response_file",
    [
        (
            {
                "command_name": "fortimail-recipient-policy-delete",
                "recipient_policy_id": 1,
            },
            "RecipientPolicy",
            "recipient_policy_delete.json",
        ),
        (
            {
                "command_name": "fortimail-access-control-delete",
                "access_control_id": 1,
            },
            "AccessControl",
            "access_control_delete.json",
        ),
        (
            {
                "command_name": "fortimail-ip-policy-delete",
                "policy_id": 1,
            },
            "IPPolicy",
            "ip_policy_delete.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-member-delete",
                "email": "email@email.com",
                "group_name": "group_name",
            },
            "EmailGroupMember",
            "email_group_member_delete.json",
        ),
        (
            {
                "command_name": "fortimail-ip-group-delete",
                "name": "name",
            },
            "IPGroup",
            "ip_group_delete.json",
        ),
        (
            {
                "command_name": "fortimail-ip-group-member-delete",
                "ip": "ip",
                "group_name": "group_name",
            },
            "IPGroupMember",
            "ip_group_member_delete.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-delete",
                "name": "name",
            },
            "EmailGroup",
            "email_group_delete.json",
        ),
        (
            {
                "command_name": "fortimail-system-safe-block-delete",
                "list_type": "Blocklist",
                "values": "1,2,3",
            },
            "SystemList",
            "system_safe_block_delete.json",
        ),
    ],
)
def test_delete_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    outputs_prefix: str,
    response_file: str,
):
    """
    Scenario:
    - Test deleting objects.

    Given:
    - command_args, endpoint_suffix, response_file.

    When:
    - "fortimail-recipient-policy-delete"
    - "fortimail-access-control-delete"
    - "fortimail-ip-policy-delete"
    - "fortimail-email-group-member-delete"
    - "fortimail-system-safe-block-delete"
    - "fortimail-ip-group-delete"
    - "fortimail-ip-group-member-delete"
    - "fortimail-email-group-delete"


    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    response = load_mock_response(response_file)

    requests_mock.get(
        url=urljoin(API_URL, ENTITY_ENDPOINT[outputs_prefix]["GET"]),
        json=response,
    )

    if outputs_prefix == "SystemList":
        requests_mock.post(
            url=urljoin(API_URL, ENTITY_ENDPOINT[outputs_prefix]["DELETE"]),
            json=response,
        )
    else:
        requests_mock.delete(
            url=urljoin(API_URL, ENTITY_ENDPOINT[outputs_prefix]["DELETE"]),
            json=response,
        )
    command_entity_title, _ = Fortimail.get_command_entity(command_name=command_args["command_name"])
    command_results = Fortimail.delete_command(mock_client, command_args)

    assert command_results.readable_output == command_entity_title


@pytest.mark.parametrize(
    "command_args, endpoint_suffix, outputs_prefix, response_file",
    [
        (
            {
                "command_name": "fortimail-ip-group-create",
                "name": "name",
                "comment": "comment",
            },
            "ProfIp_address_group/name/",
            "IPGroup",
            "ip_group.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-create",
                "name": "name",
                "comment": "comment",
            },
            "ProfEmail_address_group/name/",
            "EmailGroup",
            "email_group.json",
        ),
        (
            {
                "command_name": "fortimail-ip-group-update",
                "name": "name",
                "comment": "comment",
            },
            "ProfIp_address_group/name/",
            "IPGroup",
            "ip_group.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-update",
                "name": "name",
                "comment": "comment",
            },
            "ProfEmail_address_group/name/",
            "EmailGroup",
            "email_group.json",
        ),
    ],
)
def test_group_create_update_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    endpoint_suffix: str,
    outputs_prefix: str,
    response_file: str,
):
    """
    Scenario:
    - Test retrieving a create and update of objects.

    Given:
    - command_args, endpoint_suffix, response_file.

    When:
    - "fortimail-ip-group-create"
    - "fortimail-ip-group-update"
    - "fortimail-email-group-create"
    - "fortimail-email-group-update"

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    response = load_mock_response(response_file)
    if command_args["command_name"].split("-")[-1] == "create":
        requests_mock.post(
            url=urljoin(API_URL, endpoint_suffix),
            json=response,
        )
    else:
        requests_mock.put(
            url=urljoin(API_URL, endpoint_suffix),
            json=response,
        )

    command_results = Fortimail.group_create_update_command(mock_client, command_args)

    assert command_results.raw_response == response
    assert command_results.outputs == {
        "mkey": command_args.get("name"),
        "comment": command_args.get("comment"),
    }
    assert command_results.outputs_prefix == f"FortiMail.{outputs_prefix}"
    assert command_results.outputs_key_field == "mkey"


@pytest.mark.parametrize(
    "command_args, endpoint_suffix, response_file",
    [
        (
            {
                "command_name": "fortimail-ip-group-member-add",
                "group_name": "group_name",
                "ip": "1.1.1.1/24",
            },
            "ProfIp_address_group/group_name/ProfIp_address_groupIpAddressGroupMember/1.1.1.1-1.1.1.1",
            "ip_group_member.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-member-add",
                "group_name": "group_name",
                "email": "email@email.com",
            },
            "ProfEmail_address_group/group_name/ProfEmail_address_groupEmailAddressGroupMember/email@email.com",
            "email_group_member.json",
        ),
        (
            {
                "command_name": "fortimail-ip-group-member-replace",
                "group_name": "group_name",
                "ips": ["1.1.1.1/24", "1.1.1.2/24"],
            },
            "ProfIp_address_group/group_name/ProfIp_address_groupIpAddressGroupMember",
            "ip_group_member_replace.json",
        ),
        (
            {
                "command_name": "fortimail-email-group-member-replace",
                "group_name": "group_name",
                "emails": ["email@email.com", "email2@email.com"],
            },
            "ProfEmail_address_group/group_name/ProfEmail_address_groupEmailAddressGroupMember",
            "email_group_member_replace.json",
        ),
    ],
)
def test_group_member_add_replace_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
):
    """
    Scenario:
    - Test retrieving a create and update of objects.

    Given:
    - command_args, endpoint_suffix, response_file.

    When:
    - "fortimail-ip-group-member-add"
    - "fortimail-ip-group-member-replace"
    - "fortimail-email-group-member-add"
    - "fortimail-email-group-member-replace"

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    response = load_mock_response(response_file)
    requests_mock.post(
        url=urljoin(API_URL, endpoint_suffix),
        json=response,
    )
    command_results = Fortimail.group_member_add_replace_command(mock_client, command_args)
    command_name = command_args.pop("command_name")
    command_entity_title, _ = Fortimail.get_command_entity(command_name=command_name)

    assert command_results.readable_output == command_entity_title


def test_add_system_safe_block_command(
    requests_mock,
    mock_client: Fortimail.Client,
):
    """
    Scenario:
    - Test adding system safe/block items.

    When:
    - "fortimail-system-safe-block-add"

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    response = load_mock_response("system_safe_block_add.json")
    requests_mock.post(
        url=urljoin(API_URL, "SenderListV2/system"),
        json=response,
    )

    command_results = Fortimail.add_system_safe_block_command(mock_client, {"list_type": "Bloklist", "values": "1,2"})

    assert command_results.raw_response == response


@pytest.mark.parametrize(
    "command_args, response_file",
    [
        (
            {
                "command_name": "fortimail-ip-policy-move",
                "policy_id": 1,
                "action": "up",
            },
            "ip_policy_move.json",
        ),
        (
            {
                "command_name": "fortimail-access-control-move",
                "access_control_id": 1,
                "action": "down",
            },
            "access_control_move.json",
        ),
        (
            {
                "command_name": "fortimail-recipient-policy-move",
                "recipient_policy_id": 1,
                "action": "after",
                "reference_id": 2,
            },
            "recipient_policy_move.json",
        ),
    ],
)
def test_move_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    response_file: str,
):
    """
    Scenario:
    - Test moving a recipient policy/access control/IP policy location in the policy list.

    Given:
    - Arguments for moving the policy.

    When:
    - "fortimail-ip-policy-move"
    - "fortimail-access-control-move"
    - "fortimail-recipient-policy-move"

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    response = load_mock_response(response_file)
    command_entity_title, outputs_prefix = Fortimail.get_command_entity(command_name=command_args["command_name"])
    endpoint = ENTITY_ENDPOINT[outputs_prefix]["GET"].split("/1")[0]
    requests_mock.post(
        url=urljoin(API_URL, endpoint),
        json=response,
    )

    command_results = Fortimail.move_command(mock_client, command_args)

    assert command_results.readable_output == command_entity_title


@pytest.mark.parametrize(
    "command_args, endpoint, response_file",
    [
        (
            {
                "command_name": "fortimail-recipient-policy-create",
                "status": "enable",
                "type": "Inbound",
                "use_smtp_auth": "enable",
                "smtp_different": "enable",
                "smtp_diff_identity_ldap": "enable",
                "enable_pki": "disable",
                "certificate_validation": "disable",
            },
            "PolicyRcpt/0",
            "recipient_policy_create.json",
        ),
        (
            {
                "command_name": "fortimail-recipient-policy-update",
                "recipient_policy_id": 1,
                "comment": "comment",
            },
            "PolicyRcpt/1",
            "recipient_policy_update.json",
        ),
    ],
)
def test_recipient_policy_create_update_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    endpoint: str,
    response_file: str,
):
    """
    Scenario:
    - Test creating/updating a recipient policy.

    Given:
    - Arguments for creating/updating a recipient policy.

    When:
    - "fortimail-recipient-policy-create"
    - "fortimail-recipient-policy-update"

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    mock_response = load_mock_response(response_file)

    if command_args.get("recipient_policy_id"):
        requests_mock.put(
            url=urljoin(API_URL, endpoint),
            json=mock_response,
        )
    else:
        requests_mock.post(
            url=urljoin(API_URL, endpoint),
            json=mock_response,
        )
    response = Fortimail.map_api_response_values_to_readable_string(mock_response)
    command_results = Fortimail.recipient_policy_create_update_command(mock_client, command_args)

    assert command_results.raw_response == response
    assert command_results.outputs == response
    assert command_results.outputs_prefix == "FortiMail.RecipientPolicy"
    assert command_results.outputs_key_field == "mkey"


@pytest.mark.parametrize(
    "command_args, endpoint, response_file",
    [
        (
            {
                "command_name": "fortimail-access-control-create",
                "status": "enable",
                "sender_type": "External",
                "sender": "*",
                "recipient_type": "External",
                "recipient": "*",
                "action": "Reject",
                "source_type": "IP/Netmask",
                "authentication_status": "Any",
            },
            "MailSetAccessRule/0",
            "access_control_create.json",
        ),
        (
            {
                "command_name": "fortimail-access-control-update",
                "access_control_id": 1,
                "comment": "comment",
            },
            "MailSetAccessRule/1",
            "access_control_update.json",
        ),
    ],
)
def test_access_control_create_update_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    endpoint: str,
    response_file: str,
):
    """
    Scenario:
    - Test creating/updating an access control.

    Given:
    - Arguments for creating/updating an access control.

    When:
    - "fortimail-access-control-create"
    - "fortimail-access-control-update"

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    mock_response = load_mock_response(response_file)

    if command_args.get("access_control_id"):
        requests_mock.put(
            url=urljoin(API_URL, endpoint),
            json=mock_response,
        )
    else:
        requests_mock.post(
            url=urljoin(API_URL, endpoint),
            json=mock_response,
        )
    response = Fortimail.map_api_response_values_to_readable_string(mock_response)
    command_results = Fortimail.access_control_create_update_command(mock_client, command_args)

    assert command_results.raw_response == response
    assert command_results.outputs == response
    assert command_results.outputs_prefix == "FortiMail.AccessControl"
    assert command_results.outputs_key_field == "mkey"


@pytest.mark.parametrize(
    "command_args, endpoint",
    [
        (
            {
                "command_name": "fortimail-ip-policy-create",
                "status": "enable",
                "use_smtp_auth": "enable",
                "smtp_different": "enable",
                "smtp_diff_identity_ldap": "enable",
                "exclusive": "enable",
                "action": "Reject",
            },
            "PolicyIp/0",
        ),
        (
            {
                "command_name": "fortimail-ip-policy-update",
                "ip_policy_id": 1,
                "comment": "comment",
            },
            "PolicyIp/1",
        ),
    ],
)
def test_ip_policy_create_update_command(
    requests_mock,
    mock_client: Fortimail.Client,
    command_args: dict[str, Any],
    endpoint: str,
):
    """
    Scenario:
    - Test creating/updating a IP policy.

    Given:
    - Arguments for creating/updating a IP policy.

    When:
    - "fortimail-ip-policy-create"
    - "fortimail-ip-policy-update"

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    requests_mock.post(
        url=urljoin(API_URL, "AdminLogin/"),
        json=EXAMPLE_COOKIE,
    )
    mock_response = load_mock_response("ip_policy.json")

    if command_args.get("ip_policy_id"):
        requests_mock.put(
            url=urljoin(API_URL, endpoint),
            json=mock_response,
        )
    else:
        requests_mock.post(
            url=urljoin(API_URL, endpoint),
            json=mock_response,
        )
    response = Fortimail.map_api_response_values_to_readable_string(mock_response)
    command_results = Fortimail.ip_policy_create_update_command(mock_client, command_args)

    assert command_results.raw_response == response
    assert command_results.outputs == response
    assert command_results.outputs_prefix == "FortiMail.IPPolicy"
    assert command_results.outputs_key_field == "mkey"


# Test Helper Functions #


def test_prepare_outputs_and_readable_output():
    """
    Scenario:
    - Test retrieving updated response.

    Given:
    - API response.

    Then:
    - Ensure that the return response is correct.

    """
    output = [{"mkey": "value1", "level": "high"}, {"mkey": "value2", "level": "low"}]
    result, _ = Fortimail.prepare_outputs_and_readable_output(output, {})
    expected_result = [
        {"Name": "value1", "TLS level": "high"},
        {"Name": "value2", "TLS level": "low"},
    ]
    assert remove_empty_elements(result) == expected_result


def test_modify_group_member_args_before_replace():
    """
    Scenario:
    - Test retrieving payload to replace group members.

    Given:
    - Command arguments.

    Then:
    - Ensure that the return payload is correct.

    """
    group_members = ["member1", "member2"]
    result = Fortimail.modify_group_member_args_before_replace(group_members)
    expected_result = {"mkey_0": "member1", "mkey_1": "member2", "reqObjCount": 2}
    assert result == expected_result


@pytest.mark.parametrize(
    "command_args, expected_result",
    [
        (
            {"ips": ["192.168.0.1", "192.168.0.2"]},
            {"ips": {"mkey_0": "192.168.0.1-192.168.0.1", "mkey_1": "192.168.0.2-192.168.0.2", "reqObjCount": 2}},
        ),
        (
            {"emails": ["test1@example.com", "test2@example.com"]},
            {"emails": {"mkey_0": "test1@example.com", "mkey_1": "test2@example.com", "reqObjCount": 2}},
        ),
    ],
)
def test_update_group_member_args(command_args: dict[str, Any], expected_result: dict[str, Any]):
    """
    Scenario:
    - Test retrieving updated group member arguments.

    Given:
    - Command arguments.

    Then:
    - Ensure that the return arguments is correct.

    """
    result = Fortimail.update_group_member_args(command_args)
    assert result == expected_result


@pytest.mark.parametrize(
    "command_name, expected_result",
    [
        ("fortimail-ip-policy-create", ("Ip Policy created successfully", "IPPolicy")),
        ("fortimail-ip-policy-list", ("Ip Policy", "IPPolicy")),
    ],
)
def test_get_command_entity(command_name: str, expected_result):
    """
    Scenario:
    - Test retrieving command entity data.

    Given:
    - Command name.

    Then:
    - Ensure that the return command request, title, and outputs prefix is correct.

    """
    result = Fortimail.get_command_entity(command_name)
    assert result == expected_result


def test_map_api_response_values_to_readable_string():
    """
    Scenario:
    - Test updating response integer values to readable strings.

    Given:
    - API response.

    Then:
    - Ensure that the updated response is correct.

    """
    response = {
        "objectID": "MailSetAccessRule",
        "reqAction": "some_action",
        "nodePermission": "some_permission",
        "collection": [
            {
                "sender_pattern_type": 1,
                "recipient_pattern_type": 2,
                "sender_ip_type": 3,
                "authenticated": 0,
                "action": 5,
                "status": True,
            }
        ],
    }
    result = Fortimail.map_api_response_values_to_readable_string(response)
    expected_result = [
        {
            "sender_pattern_type": "Regular Expression",
            "recipient_pattern_type": "Email Group",
            "sender_ip_type": "ISDB",
            "authenticated": "Any",
            "action": "Safe",
            "status": "enable",
        }
    ]
    assert result == expected_result


def test_reverse_dict():
    """
    Scenario:
    - Test reversing keys and values of a dictionary.

    Given:
    - Original dictionary.

    Then:
    - Ensure that the reversed dictionary is correct.

    """
    original_dict = {"key1": "value1", "key2": "value2", "key3": "value3"}
    result = Fortimail.reverse_dict(original_dict)
    expected_result = {"value1": "key1", "value2": "key2", "value3": "key3"}
    assert result == expected_result


@pytest.mark.parametrize(
    "input_cidr, expected_result",
    [
        ("192.168.1.1-192.168.1.10", "192.168.1.1-192.168.1.10"),
        ("192.168.1.1", "192.168.1.1-192.168.1.1"),
        ("192.168.1.1/24", "192.168.1.1-192.168.1.1"),
    ],
)
def test_convert_cidr_to_ip_range(input_cidr: str, expected_result: str):
    """
    Scenario:
    - Test converting CIDR to IP range.

    Given:
    - CIDR input.

    Then:
    - Ensure that the converted IP range is correct.

    """
    result = Fortimail.convert_cidr_to_ip_range(input_cidr)
    assert result == expected_result


@pytest.mark.parametrize(
    "input_email, expected_exception",
    [
        ("valid@email.com", None),
        ("invalid_email", DemistoException),
        ("another_invalid_email@", DemistoException),
        (["valid@email.com", "another_valid@email.com"], None),
        (["valid@email.com", "invalid_email"], DemistoException),
        (["invalid_email", "another_invalid_email@"], DemistoException),
    ],
)
def test_is_valid_email(input_email, expected_exception):
    """
    Scenario:
    - Test validating email addresses.

    Given:
    - Email address input.

    Then:
    - Ensure that the function raises the expected exception for invalid emails.

    """
    if expected_exception:
        with pytest.raises(expected_exception):
            Fortimail.is_valid_email(input_email)
    else:
        Fortimail.is_valid_email(input_email)
