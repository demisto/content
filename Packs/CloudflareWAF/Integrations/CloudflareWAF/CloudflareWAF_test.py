import json
import os

import pytest
from CloudflareWAF import Client


"""MOCK PARAMETERS """
CREDENTIALS = '{"Authorization": "Bearer YOUR_TOKEN"}'
ACCOUNT_ID = "account_id"
ZONE_ID = "zone_id"

"""CONSTANTS"""
BASE_URL = "https://api.cloudflare.com/client/v4/"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """

    with open(os.path.join("test_data", file_name), encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client():
    return Client(account_id=ACCOUNT_ID, zone_id=ZONE_ID, credentials=CREDENTIALS, base_url=BASE_URL, proxy=False, insecure=True)


def test_cloudflare_waf_firewall_rule_create_command(requests_mock, mock_client):
    """
    Scenario: Create firewall rule.
    Given:
     - User has provided valid credentials.
     - Firewall rule action and expression.
    When:
     - cloudflare-waf-firewall-rule-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_create_command

    mock_response = load_mock_response("create_firewall_rule.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/firewall/rules"
    requests_mock.post(url=url, json=mock_response)

    action = "allow"
    filter_expression = "filter_expression"

    result = cloudflare_waf_firewall_rule_create_command(mock_client, {"action": action, "filter_expression": filter_expression})

    assert result.outputs_prefix == "CloudflareWAF.FirewallRule"
    assert len(result.outputs[0]) == 8
    assert result.outputs[0]["id"] == "firewall_rule_id"


def test_cloudflare_waf_firewall_rule_update_command(requests_mock, mock_client):
    """
    Scenario: Update firewall rule.
    Given:
     - User has provided valid credentials.
     - Firewall rule ID, action and filter ID.
    When:
     - cloudflare-waf-firewall-rule-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_update_command

    mock_response = load_mock_response("create_firewall_rule.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/firewall/rules"
    requests_mock.put(url=url, json=mock_response)

    result = cloudflare_waf_firewall_rule_update_command(
        mock_client, {"id": "rule_id", "action": "action", "filter_id": "filter_id"}
    )

    assert result.outputs_prefix == "CloudflareWAF.FirewallRule"
    assert len(result.outputs[0]) == 8
    assert result.outputs[0]["id"] == "firewall_rule_id"


def test_cloudflare_waf_firewall_rule_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete firewall rule.
    Given:
     - User has provided valid credentials.
     - Firewall rule ID.
    When:
     - cloudflare-waf-firewall-rule-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure raw response is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_delete_command

    mock_response = load_mock_response("delete_firewall_rule.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/firewall/rules"
    requests_mock.delete(url=url, json=mock_response)

    rule_id = "rule_id"

    result = cloudflare_waf_firewall_rule_delete_command(mock_client, {"id": rule_id})

    assert len(result.raw_response) == 4
    assert result.raw_response["success"] is True
    assert result.raw_response["result"][0]["id"] == "firewall_rule_id"


def test_cloudflare_waf_firewall_rule_list_command(requests_mock, mock_client):
    """
    Scenario: List firewall rule.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-firewall-rule-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_list_command

    mock_response = load_mock_response("list_firewall_rule.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/firewall/rules"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_firewall_rule_list_command(mock_client, {"page": 1, "page_size": 5})

    assert result.outputs_prefix == "CloudflareWAF.FirewallRule"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "firewall_rule_id_1"


def test_cloudflare_waf_zone_list_command(requests_mock, mock_client):
    """
    Scenario: List zones.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-zone-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_zone_list_command

    mock_response = load_mock_response("list_zone.json")
    url = f"{BASE_URL}zones"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_zone_list_command(mock_client, {"page": 1, "page_size": 5})

    assert result.outputs_prefix == "CloudflareWAF.Zone"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "zone_id_1"


def test_cloudflare_waf_filter_create_command(requests_mock, mock_client):
    """
    Scenario: Create filter.
    Given:
     - User has provided valid credentials.
     - Filter expression.
    When:
     - cloudflare-waf-filter-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_create_command

    mock_response = load_mock_response("create_filter.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/filters"
    requests_mock.post(url=url, json=mock_response)

    filter_expression = "filter_expression"

    result = cloudflare_waf_filter_create_command(mock_client, {"expression": filter_expression})

    assert result.outputs_prefix == "CloudflareWAF.Filter"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "filter_id"


def test_cloudflare_waf_filter_update_command(requests_mock, mock_client):
    """
    Scenario: Update filter.
    Given:
     - User has provided valid credentials.
     - Filter expression.
    When:
     - cloudflare-waf-filter-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_update_command

    mock_response = load_mock_response("create_filter.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/filters"
    requests_mock.put(url=url, json=mock_response)

    filter_expression = "filter_expression"
    filter_id = "filter_id"

    result = cloudflare_waf_filter_update_command(mock_client, {"id": filter_id, "expression": filter_expression})

    assert result.outputs_prefix == "CloudflareWAF.Filter"
    assert len(result.outputs) == 1
    assert result.outputs[0]["id"] == "filter_id"


def test_cloudflare_waf_filter_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete filter.
    Given:
     - User has provided valid credentials.
     - Filter expression.
    When:
     - cloudflare-waf-filter-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_delete_command

    mock_response = load_mock_response("create_filter.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/filters"
    requests_mock.delete(url=url, json=mock_response)

    filter_id = "filter_id"

    result = cloudflare_waf_filter_delete_command(mock_client, {"filter_id": filter_id})

    assert len(result.raw_response) == 4
    assert result.raw_response["result"][0]["id"] == "filter_id"


def test_cloudflare_waf_filter_list_command(requests_mock, mock_client):
    """
    Scenario: List filters.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-filter-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_list_command

    mock_response = load_mock_response("list_filter.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/filters"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_filter_list_command(mock_client, {"limit": 5})

    assert result.outputs_prefix == "CloudflareWAF.Filter"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "filter_id_1"


def test_cloudflare_waf_ip_list_create_command(requests_mock, mock_client):
    """
    Scenario: Create ip list.
    Given:
     - User has provided valid credentials.
     - IP list name.
    When:
     - cloudflare-waf-ip-list-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_create_command

    mock_response = load_mock_response("create_ip_list.json")

    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists"
    requests_mock.post(url=url, json=mock_response)

    name = "list_name"

    result = cloudflare_waf_ip_list_create_command(mock_client, {"name": name})

    assert result.outputs_prefix == "CloudflareWAF.IpList"
    assert len(result.outputs) == 7
    assert result.outputs["id"] == "list_id"
    assert result.outputs["name"] == "list_name"


def test_cloudflare_waf_ip_list_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete ip list.
    Given:
     - User has provided valid credentials.
     - IP list name.
    When:
     - cloudflare-waf-ip-list-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_delete_command

    mock_response = load_mock_response("delete_ip_list.json")

    list_id = "list_id"

    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}"
    requests_mock.delete(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_delete_command(mock_client, {"id": list_id})

    assert len(result.raw_response) == 4
    assert result.raw_response["result"]["id"] == "list_id"


def test_cloudflare_waf_ip_lists_list_command(requests_mock, mock_client):
    """
    Scenario: List filters.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-filter-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_lists_list_command

    mock_response = load_mock_response("lists_ip_list.json")
    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_ip_lists_list_command(mock_client, {"page": 1, "page_size": 5})

    assert result.outputs_prefix == "CloudflareWAF.IpList"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "list_id_1"


def test_cloudflare_waf_ip_list_item_list_command(requests_mock, mock_client):
    """
    Scenario: List filters.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-filter-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_list_command

    mock_response = load_mock_response("ip_list_item_list.json")
    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/123/items"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_list_command(
        mock_client, {"page": 1, "page_size": 5, "list_id": "123", "item_ip": "ip1"}
    )

    assert result.outputs_prefix == "CloudflareWAF.IpListItem"
    assert result.outputs["list_id"] == "123"


def test_cloudflare_waf_ip_list_item_create_command(requests_mock, mock_client):
    """
    Scenario: Create ip list items.
    Given:
     - User has provided valid credentials.
     - IP list ID.
     - Items.
    When:
     - cloudflare-waf-ip-list-item-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_create_command

    mock_response = load_mock_response("ip_list_item.json")

    list_id = "list_id"
    items = "120.2.2.8"

    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}/items"

    requests_mock.post(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_create_command(mock_client, {"list_id": list_id, "items": items})

    assert result.raw_response["operation_id"] == "operation_id"


def test_cloudflare_waf_ip_list_item_update_command(requests_mock, mock_client):
    """
    Scenario: Replace ip list items.
    Given:
     - User has provided valid credentials.
     - IP list ID.
     - Items.
    When:
     - cloudflare-waf-ip-list-item-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_update_command

    mock_response = load_mock_response("ip_list_item.json")

    list_id = "list_id"
    items = "120.2.2.8"

    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}/items"

    requests_mock.put(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_update_command(mock_client, {"list_id": list_id, "items": items})

    assert result.raw_response["operation_id"] == "operation_id"


def test_cloudflare_waf_ip_list_item_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete items from ip list.
    Given:
     - User has provided valid credentials.
     - IP list ID.
     - Items ID.
    When:
     - cloudflare-waf-ip-list-item-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_delete_command

    mock_response = load_mock_response("ip_list_item.json")

    list_id = "list_id"
    items = "item_id"

    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}/items"

    requests_mock.delete(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_delete_command(mock_client, {"list_id": list_id, "items": items})

    assert result.raw_response["operation_id"] == "operation_id"


def test_get_headers_with_api_token():
    """
    Scenario: Use API Token authentication.
    Given:
     - User has provided an API token using the credentials parameter.
    When:
     - get_headers is called.
    Then:
     - Ensure the 'Authorization' header is correctly set with the bearer token.
     - Ensure the 'Content-Type' header is set to 'application/json'.
    """
    from CloudflareWAF import get_headers

    params = {"credentials": {"password": "test_token"}}
    expected = {"Authorization": "Bearer test_token", "Content-Type": "application/json"}
    result = get_headers(params)
    assert json.loads(result) == expected


def test_get_headers_with_global_api_key():
    """
    Scenario: Use Global API Key and Email for authentication.
    Given:
     - User has provided a global API key and email.
    When:
     - get_headers is called.
    Then:
     - Ensure the 'X-Auth-Email' and 'X-Auth-Key' headers are correctly set.
     - Ensure the 'Content-Type' header is set to 'application/json'.
    """
    from CloudflareWAF import get_headers

    params = {"global_api_key": {"password": "test_key"}, "email": "user@example.com"}
    expected = {"X-Auth-Email": "user@example.com", "X-Auth-Key": "test_key", "Content-Type": "application/json"}
    result = get_headers(params)
    assert json.loads(result) == expected


def test_get_headers_missing_authentication():
    """
    Scenario: Missing all authentication methods.
    Given:
     - No API token.
     - No global API key and email.
    When:
     - get_headers is called.
    Then:
     - Raise ValueError indicating that authentication parameters are missing.
    """
    from CloudflareWAF import get_headers

    params = {}
    with pytest.raises(ValueError, match="Missing authentication parameters"):
        get_headers(params)


def test_cloudflare_waf_ruleset_list_command(requests_mock, mock_client):
    """
    Scenario: List rulesets.
    Given:
     - User has provided valid credentials.
     - Default zone_id is configured on the client.
    When:
     - cloudflare-waf-ruleset-list called without explicit zone_id.
    Then:
     - Ensure the zone-level endpoint is used (falls back to client zone_id).
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ruleset_list_command

    mock_response = load_mock_response("list_ruleset.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/rulesets"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_ruleset_list_command(mock_client, {})

    assert result.outputs_prefix == "CloudflareWAF.Ruleset"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "ruleset_id_1"
    assert result.outputs[1]["id"] == "ruleset_id_2"


def test_cloudflare_waf_ruleset_list_command_account_level(requests_mock):
    """
    Scenario: List rulesets at account level.
    Given:
     - User has provided valid credentials.
     - No zone_id is configured on the client or passed as argument.
    When:
     - cloudflare-waf-ruleset-list called.
    Then:
     - Ensure the account-level endpoint is used.
     - Ensure outputs prefix is correct.
    """

    from CloudflareWAF import cloudflare_waf_ruleset_list_command

    client_no_zone = Client(
        account_id=ACCOUNT_ID, zone_id=None, credentials=CREDENTIALS, base_url=BASE_URL, proxy=False, insecure=True
    )

    mock_response = load_mock_response("list_ruleset.json")
    url = f"{BASE_URL}accounts/{ACCOUNT_ID}/rulesets"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_ruleset_list_command(client_no_zone, {})

    assert result.outputs_prefix == "CloudflareWAF.Ruleset"
    assert len(result.outputs) == 2


def test_cloudflare_waf_ruleset_get_command(requests_mock, mock_client):
    """
    Scenario: Get a specific ruleset.
    Given:
     - User has provided valid credentials.
     - Ruleset ID.
    When:
     - cloudflare-waf-ruleset-get called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
     - Ensure rules are included in the output.
    """

    from CloudflareWAF import cloudflare_waf_ruleset_get_command

    mock_response = load_mock_response("get_ruleset.json")
    ruleset_id = "ruleset_id_1"
    url = f"{BASE_URL}zones/{ZONE_ID}/rulesets/{ruleset_id}"
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_ruleset_get_command(mock_client, {"ruleset_id": ruleset_id})

    assert result.outputs_prefix == "CloudflareWAF.Ruleset"
    assert result.outputs["id"] == "ruleset_id_1"
    assert result.outputs["name"] == "Cloudflare Managed Ruleset"
    assert len(result.outputs["rules"]) == 2
    assert result.outputs["rules"][0]["id"] == "rule_id_1"


def test_cloudflare_waf_ruleset_create_command(requests_mock, mock_client):
    """
    Scenario: Create a new ruleset.
    Given:
     - User has provided valid credentials.
     - Ruleset name, kind, and phase.
    When:
     - cloudflare-waf-ruleset-create called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ruleset_create_command

    mock_response = load_mock_response("create_ruleset.json")
    url = f"{BASE_URL}zones/{ZONE_ID}/rulesets"
    requests_mock.post(url=url, json=mock_response)

    result = cloudflare_waf_ruleset_create_command(
        mock_client,
        {
            "name": "New Custom Ruleset",
            "kind": "custom",
            "phase": "http_request_firewall_custom",
            "description": "A new custom ruleset",
            "rules": '[{"action": "block", "expression": "(ip.src eq 10.0.0.1)", "description": "Block internal IP"}]',
        },
    )

    assert result.outputs_prefix == "CloudflareWAF.Ruleset"
    assert result.outputs["id"] == "ruleset_id_new"
    assert result.outputs["name"] == "New Custom Ruleset"


def test_cloudflare_waf_ruleset_update_command(requests_mock, mock_client):
    """
    Scenario: Update an existing ruleset.
    Given:
     - User has provided valid credentials.
     - Ruleset ID and updated fields.
    When:
     - cloudflare-waf-ruleset-update called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ruleset_update_command

    mock_response = load_mock_response("update_ruleset.json")
    ruleset_id = "ruleset_id_1"
    url = f"{BASE_URL}zones/{ZONE_ID}/rulesets/{ruleset_id}"
    requests_mock.put(url=url, json=mock_response)

    result = cloudflare_waf_ruleset_update_command(
        mock_client,
        {
            "ruleset_id": ruleset_id,
            "name": "Updated Ruleset Name",
            "description": "Updated description",
        },
    )

    assert result.outputs_prefix == "CloudflareWAF.Ruleset"
    assert result.outputs["id"] == "ruleset_id_1"
    assert result.outputs["name"] == "Updated Ruleset Name"


def test_cloudflare_waf_ruleset_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete a ruleset.
    Given:
     - User has provided valid credentials.
     - Ruleset ID.
    When:
     - cloudflare-waf-ruleset-delete called.
    Then:
     - Ensure the readable output confirms deletion.
    """

    from CloudflareWAF import cloudflare_waf_ruleset_delete_command

    ruleset_id = "ruleset_id_1"
    url = f"{BASE_URL}zones/{ZONE_ID}/rulesets/{ruleset_id}"
    requests_mock.delete(url=url, status_code=204)

    result = cloudflare_waf_ruleset_delete_command(mock_client, {"ruleset_id": ruleset_id})

    assert result.readable_output == f"Ruleset {ruleset_id} was successfully deleted."
