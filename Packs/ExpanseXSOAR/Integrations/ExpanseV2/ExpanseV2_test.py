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
    assert result.outputs == mock_ipranges_output["data"][:int(MOCK_LIMIT)]


def test_expanse_create_tag(requests_mock):
    from ExpanseV2 import Client, create_tag_command

    MOCK_TAGNAME = "xsoar-test-tag1"
    MOCK_TAGDESC = "Test tag"
    mock_tag = util_load_json("test_data/expanse_create_tag.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.post(
        "https://example.com/api/v3/annotations/tags",
        json=mock_tag
    )

    result = create_tag_command(client, {"name": MOCK_TAGNAME, "description": MOCK_TAGDESC})

    assert result.outputs_prefix == "Expanse.Tag"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_tag


def test_expanse_assign_single_tag_to_iprange(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "IpRange"
    TAGS_BY_NAME = "xsoar-false-positive"
    TAGIDS = ["e9308766-be41-46bc-ab36-1ae417ba341e"]
    ASSET_TYPE_URL = "ip-range"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_unassign_single_tag_from_iprange(requests_mock, mocker):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "IpRange"
    TAGS_BY_NAME = "xsoar-false-positive"
    TAGIDS = ["e9308766-be41-46bc-ab36-1ae417ba341e"]
    ASSET_TYPE_URL = "ip-range"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_assign_multiple_tags_to_iprange(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "IpRange"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(',') + [
        "e9308766-be41-46bc-ab36-1ae417ba341e",
        "b3308766-be41-46bc-ab36-1ae417ba3aaa"
    ]
    ASSET_TYPE_URL = "ip-range"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_unassign_multiple_tags_from_iprange(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "IpRange"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(',') + [
        "e9308766-be41-46bc-ab36-1ae417ba341e",
        "b3308766-be41-46bc-ab36-1ae417ba3aaa"
    ]
    ASSET_TYPE_URL = "ip-range"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_assign_single_tag_to_domain(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "Domain"
    TAGS_BY_NAME = "xsoar-false-positive"
    TAGIDS = ["e9308766-be41-46bc-ab36-1ae417ba341e"]
    ASSET_TYPE_URL = "domains"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_unassign_single_tag_from_domain(requests_mock, mocker):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "Domain"
    TAGS_BY_NAME = "xsoar-false-positive"
    TAGIDS = ["e9308766-be41-46bc-ab36-1ae417ba341e"]
    ASSET_TYPE_URL = "domains"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_assign_multiple_tags_to_domain(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "Domain"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(',') + [
        "e9308766-be41-46bc-ab36-1ae417ba341e",
        "b3308766-be41-46bc-ab36-1ae417ba3aaa"
    ]
    ASSET_TYPE_URL = "domains"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_unassign_multiple_tags_from_domain(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "Domain"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(',') + [
        "e9308766-be41-46bc-ab36-1ae417ba341e",
        "b3308766-be41-46bc-ab36-1ae417ba3aaa"
    ]
    ASSET_TYPE_URL = "domains"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_assign_single_tag_to_certificate(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "Certificate"
    TAGS_BY_NAME = "xsoar-false-positive"
    TAGIDS = ["e9308766-be41-46bc-ab36-1ae417ba341e"]
    ASSET_TYPE_URL = "certificates"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_unassign_single_tag_from_certificate(requests_mock, mocker):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "Certificate"
    TAGS_BY_NAME = "xsoar-false-positive"
    TAGIDS = ["e9308766-be41-46bc-ab36-1ae417ba341e"]
    ASSET_TYPE_URL = "certificates"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_assign_multiple_tags_to_certificate(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "Certificate"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(',') + [
        "e9308766-be41-46bc-ab36-1ae417ba341e",
        "b3308766-be41-46bc-ab36-1ae417ba3aaa"
    ]
    ASSET_TYPE_URL = "certificates"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_unassign_multiple_tags_from_certificate(mocker, requests_mock):
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "Certificate"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(',') + [
        "e9308766-be41-46bc-ab36-1ae417ba341e",
        "b3308766-be41-46bc-ab36-1ae417ba3aaa"
    ]
    ASSET_TYPE_URL = "certificates"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(
        f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk",
        json={}
    )

    mock_func = mocker.patch.object(client, 'manage_asset_tags')

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID
        }
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == 'Operation complete'


def test_expanse_get_certificate_by_id(requests_mock):
    from ExpanseV2 import Client, get_certificate_command
    MOCK_MD5HASH = "zjgruhp5zhqLTvOsvgZGYw=="
    mock_cert = util_load_json("test_data/expanse_certificate.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/assets/certificates/{MOCK_MD5HASH}",
        json=mock_cert
    )

    result = get_certificate_command(client, {"pem_md5_hash": MOCK_MD5HASH})
    assert result.outputs_prefix == "Expanse.Certificate"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_cert


def test_expanse_get_certificate_by_query(requests_mock):
    from ExpanseV2 import Client, get_certificate_command
    MOCK_BU = "Test Company Dev,Test Company Prod"
    MOCK_LIMIT = "2"
    mock_certs = util_load_json("test_data/expanse_get_certificate.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/assets/certificates?limit={MOCK_LIMIT}&businessUnitName={MOCK_BU}",
        json=mock_certs
    )

    result = get_certificate_command(client, {"businessunitnames": MOCK_BU, "limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.Certificate"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_certs["data"][:int(MOCK_LIMIT)]


def test_expanse_certificate(requests_mock):
    pass


def test_expanse_get_domain(requests_mock):
    from ExpanseV2 import Client, get_domain_command
    from CommonServerPython import Common, DBotScoreType
    MOCK_BU = "Test Company Dev,Test Company Prod"
    MOCK_LIMIT = "2"
    mock_domain_data = util_load_json("test_data/expanse_get_domain.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/assets/domains?limit={MOCK_LIMIT}&businessUnitName={MOCK_BU}",
        json=mock_domain_data
    )

    result = get_domain_command(client, {"businessunitnames": MOCK_BU, "limit": MOCK_LIMIT})
    assert result.outputs_prefix == "Expanse.Domain"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_domain_data["data"][:int(MOCK_LIMIT)]
    assert isinstance(result.indicators[0], Common.Domain)
    assert result.indicators[0].domain == mock_domain_data["data"][0]["domain"]
    assert isinstance(result.indicators[0].dbot_score, Common.DBotScore)
    assert result.indicators[0].dbot_score.indicator == mock_domain_data["data"][0]["domain"]
    assert result.indicators[0].dbot_score.integration_name == "ExpanseV2"
    assert result.indicators[0].dbot_score.score == Common.DBotScore.NONE
    assert result.indicators[0].dbot_score.indicator_type == DBotScoreType.DOMAIN
    assert result.indicators[0].registrant_country == mock_domain_data["data"][0]['whois'][0]['registrant']['country']
    assert result.indicators[1].domain == mock_domain_data["data"][1]['domain']


def test_domain(requests_mock):
    from ExpanseV2 import Client, domain_command
    from CommonServerPython import Common, DBotScoreType
    MOCK_DOMAIN = "tableau.example.com"
    mock_domain_data = util_load_json("test_data/domain.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/assets/domains/{MOCK_DOMAIN}",
        json=mock_domain_data
    )

    result = domain_command(client, {"domain": MOCK_DOMAIN})
    assert result.outputs_prefix == "Expanse.Domain"
    assert result.outputs_key_field == "domain"
    assert result.outputs[0] == mock_domain_data
    assert isinstance(result.indicators[0], Common.Domain)
    assert result.indicators[0].domain == MOCK_DOMAIN
    assert isinstance(result.indicators[0].dbot_score, Common.DBotScore)
    assert result.indicators[0].dbot_score.indicator == MOCK_DOMAIN
    assert result.indicators[0].dbot_score.integration_name == "ExpanseV2"
    assert result.indicators[0].dbot_score.score == Common.DBotScore.NONE
    assert result.indicators[0].dbot_score.indicator_type == DBotScoreType.DOMAIN
    assert result.indicators[0].registrant_country == mock_domain_data['whois'][0]['registrant']['country']


def test_ip(requests_mock):
    from ExpanseV2 import Client, ip_command
    from CommonServerPython import Common, DBotScoreType
    MOCK_IP = "1.1.1.1"
    mock_ip_data = util_load_json("test_data/ip.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        "https://example.com/api/v2/assets/ips",
        json=mock_ip_data
    )

    result = ip_command(client, {"ip": MOCK_IP})
    assert result.outputs_prefix == "Expanse.IP"
    assert result.outputs_key_field == "IP"
    assert result.outputs == mock_ip_data["data"]
    assert isinstance(result.indicators[0], Common.IP)
    assert result.indicators[0].ip == MOCK_IP
    assert isinstance(result.indicators[0].dbot_score, Common.DBotScore)
    assert result.indicators[0].dbot_score.indicator == MOCK_IP
    assert result.indicators[0].dbot_score.integration_name == "ExpanseV2"
    assert result.indicators[0].dbot_score.score == Common.DBotScore.NONE
    assert result.indicators[0].dbot_score.indicator_type == DBotScoreType.IP


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
