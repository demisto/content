"""Expanse V2 Integration for Cortex XSOAR - Unit Tests file

"""

import json
import io
import copy


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_authentication(mocker):
    pass


def test_pagination(mocker):
    pass


def test_fetch_incidents(mocker):
    pass


def test_get_remote_data_command(mocker):
    pass


def test_update_remote_system_command(mocker):
    pass


def test_expanse_get_issues(mocker):
    pass


def test_expanse_get_issue(mocker):
    pass


def test_expanse_get_issue_comments_command(requests_mock):
    from ExpanseV2 import Client, get_issue_comments_command

    MOCK_ISSUE_ID = "a827f1a5-f223-4bf6-80e0-e8481bce8e2c"
    MOCK_LIMIT = "2"
    mock_comments = util_load_json("test_data/expanse_get_issue_updates.json")
    mock_comments["data"] = [d for d in mock_comments["data"] if d["updateType"] == "Comment"]

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v1/issues/issues/{MOCK_ISSUE_ID}/updates?limit={MOCK_LIMIT}", json=mock_comments)
    result = get_issue_comments_command(client, {"issue_id": MOCK_ISSUE_ID, "limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.IssueComment"
    assert result.outputs_key_field == "id"
    assert result.outputs == [
        {**d, "issueId": MOCK_ISSUE_ID, "user": d["user"]["username"]} for d in mock_comments["data"][: int(MOCK_LIMIT)]
    ]


def test_expanse_get_issue_updates_command(requests_mock):
    from ExpanseV2 import Client, get_issue_updates_command

    MOCK_ISSUE_ID = "a827f1a5-f223-4bf6-80e0-e8481bce8e2c"
    MOCK_LIMIT = "3"
    mock_updates = util_load_json("test_data/expanse_get_issue_updates.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v1/issues/issues/{MOCK_ISSUE_ID}/updates?limit={MOCK_LIMIT}", json=mock_updates)
    result = get_issue_updates_command(client, {"issue_id": MOCK_ISSUE_ID, "limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.IssueUpdate"
    assert result.outputs_key_field == "id"
    assert result.outputs == [{**d, "issueId": MOCK_ISSUE_ID} for d in mock_updates["data"][: int(MOCK_LIMIT)]]


def test_expanse_list_businessunits_command(requests_mock):
    from ExpanseV2 import Client, list_businessunits_command

    MOCK_LIMIT = "2"
    mock_businessunits = util_load_json("test_data/expanse_list_businessunits.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v1/issues/businessunits?limit={MOCK_LIMIT}", json=mock_businessunits)
    result = list_businessunits_command(client, {"limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.BusinessUnit"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_businessunits["data"][: int(MOCK_LIMIT)]


def test_expanse_list_providers(requests_mock):
    from ExpanseV2 import Client, list_providers_command

    MOCK_LIMIT = "8"
    mock_providers = util_load_json("test_data/expanse_list_providers.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v1/issues/providers?limit={MOCK_LIMIT}", json=mock_providers)
    result = list_providers_command(client, {"limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.Provider"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_providers["data"][: int(MOCK_LIMIT)]


def test_expanse_list_tags(requests_mock):
    from ExpanseV2 import Client, list_tags_command

    MOCK_LIMIT = "2"
    mock_tags = util_load_json("test_data/expanse_list_tags.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_LIMIT}", json=mock_tags)
    result = list_tags_command(client, {"limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.Tag"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_tags["data"][: int(MOCK_LIMIT)]


def test_expanse_get_iprange(requests_mock):
    from ExpanseV2 import Client, get_iprange_command

    MOCK_BU = "BU 1 Dev,BU 2 Prod"
    MOCK_LIMIT = "2"
    mock_ipranges = util_load_json("test_data/expanse_get_ip_range.json")
    # input has startAddress and endAddress, doesn't have CIDR
    mock_ipranges_input = copy.deepcopy(mock_ipranges)
    for d in mock_ipranges_input["data"]:
        del d["cidr"]

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/ip-range?include=&limit={MOCK_LIMIT}&business-unit-names={MOCK_BU}",
        json=mock_ipranges_input
    )

    result = get_iprange_command(client, {"businessunitnames": MOCK_BU, "limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.IPRange"
    assert result.outputs_key_field == "id"
    # output has CIDR, doesn't have startAddress and endAddress
    mock_ipranges_output = copy.deepcopy(mock_ipranges)
    for d in mock_ipranges_output["data"]:
        del d["startAddress"]
        del d["endAddress"]
    assert result.outputs == mock_ipranges_output["data"][: int(MOCK_LIMIT)]


def test_expanse_create_tag(mocker):
    pass


def test_expanse_assign_single_tag_to_iprange(mocker):
    pass


def test_expanse_unassign_single_tag_from_iprange(mocker):
    pass


def test_expanse_assign_multiple_tags_to_iprange(mocker):
    pass


def test_expanse_unassign_multiple_tags_from_iprange(mocker):
    pass


def test_expanse_assign_single_tag_to_domain(mocker):
    pass


def test_expanse_unassign_single_tag_from_domain(mocker):
    pass


def test_expanse_assign_multiple_tags_to_domain(mocker):
    pass


def test_expanse_unassign_multiple_tags_from_domain(mocker):
    pass


def test_expanse_assign_single_tag_to_certificate(mocker):
    pass


def test_expanse_unassign_single_tag_from_certificate(mocker):
    pass


def test_expanse_assign_multiple_tags_to_certificate(mocker):
    pass


def test_expanse_unassign_multiple_tags_from_certificate(mocker):
    pass


def test_expanse_get_domain(mocker):
    pass


def test_expanse_get_certificate(mocker):
    pass


def test_certificate(mocker):
    pass


def test_domain(mocker):
    pass


def test_ip(mocker):
    pass


def test_cidr(requests_mock):
    from ExpanseV2 import Client, cidr_command
    from CommonServerPython import Common

    MOCK_INET = "203.0.112.0/22"
    MOCK_INCLUDE = "severityCounts,annotations,attributionReasons,relatedRegistrationInformation,locationInformation"
    mock_cidr = util_load_json("test_data/cidr.json")
    # input has startAddress and endAddress, doesn't have CIDR
    mock_cidr_input = copy.deepcopy(mock_cidr)
    for d in mock_cidr_input["data"]:
        del d["cidr"]

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/ip-range?include={MOCK_INCLUDE}&limit=1&inet={MOCK_INET}",
        json=mock_cidr_input
    )

    result = cidr_command(client, {"cidr": MOCK_INET, "include": MOCK_INCLUDE})

    assert result.outputs_prefix == "Expanse.IPRange"
    assert result.outputs_key_field == "IP"
    # output has CIDR, doesn't have startAddress and endAddress
    mock_cidr_output = copy.deepcopy(mock_cidr)
    for d in mock_cidr_output["data"]:
        del d["startAddress"]
        del d["endAddress"]
    assert result.outputs == mock_cidr_output["data"]
    assert isinstance(result.indicators[0], Common.Indicator)
    assert result.indicators[0].indicator == MOCK_INET


def test_expanse_get_risky_flows(mocker):
    pass


def test_expanse_list_risk_rules(mocker):
    pass
