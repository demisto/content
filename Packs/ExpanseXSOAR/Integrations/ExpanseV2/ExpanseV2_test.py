"""Expanse V2 Integration for Cortex XSOAR - Unit Tests file

"""

import json
import io
import copy


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_authentication_notcached(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - a valid API Key
    When
        - No token is stored in the integration context
    Then
        - the authentication is performed
        - the token and expiration is stored in the cache
    """
    from ExpanseV2 import Client
    import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
    from datetime import datetime

    MOCK_JWT = "JWT"
    MOCK_AUTH = {"token": MOCK_JWT}
    MOCK_NOW = "2020-11-25T0:10:10.000000Z"
    TOKEN_DURATION = 7200

    MOCK_NOW_DT = datetime.strptime(MOCK_NOW, "%Y-%m-%dT%H:%M:%S.%fZ")
    MOCK_EXP_TS = MOCK_NOW_DT.timestamp() + TOKEN_DURATION

    mock_get_ic = mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mock_set_ic = mocker.patch.object(demisto, "setIntegrationContext")

    requests_mock.get("https://example.com/api/v1/IdToken", json=MOCK_AUTH)

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    mocker.patch.object(client, "_get_utcnow", return_value=MOCK_NOW_DT)

    client.authenticate()

    assert mock_get_ic.call_count == 1
    assert mock_set_ic.call_count == 1
    assert mock_set_ic.call_args_list[0][0][0]["token"] == MOCK_JWT
    assert mock_set_ic.call_args_list[0][0][0]["expires"] == MOCK_EXP_TS
    assert client._headers["Authorization"] == f"JWT {MOCK_JWT}"


def test_authentication_invalid_token(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - an invalid API Key
    When
        - No token is stored in the integration context
    Then
        - the authentication is performed and fails
        - an error is returned
    """
    from ExpanseV2 import Client
    import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import

    requests_mock.get("https://example.com/api/v1/IdToken", json={})

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    try:
        client.authenticate()
    except ValueError as e:
        assert str(e) == "Authorization failed"


def test_authentication_cached_valid(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - a valid API Key
    When
        - A valid, not expired, token is stored in the integration context
    Then
        - the authentication is not performed
        - the cached token is used
    """
    from ExpanseV2 import Client
    import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
    from datetime import datetime

    MOCK_JWT = "JWT"
    MOCK_AUTH = {"token": MOCK_JWT}
    MOCK_NOW = "2020-11-25T0:10:10.000000Z"
    TOKEN_EXPIRES = 600  # stored token expires in 600s

    MOCK_NOW_DT = datetime.strptime(MOCK_NOW, "%Y-%m-%dT%H:%M:%S.%fZ")
    MOCK_STORED_EXP_TS = MOCK_NOW_DT.timestamp() + TOKEN_EXPIRES  # expiration of the stored token

    MOCK_CACHED_TOKEN = {"token": MOCK_JWT, "expires": MOCK_STORED_EXP_TS}

    mock_get_ic = mocker.patch.object(demisto, "getIntegrationContext", return_value=MOCK_CACHED_TOKEN)
    mock_set_ic = mocker.patch.object(demisto, "setIntegrationContext")

    requests_mock.get("https://example.com/api/v1/IdToken", json=MOCK_AUTH)

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    mocker.patch.object(client, "_get_utcnow", return_value=MOCK_NOW_DT)

    client.authenticate()

    assert mock_get_ic.call_count == 1
    assert mock_set_ic.call_count == 0
    assert client._headers["Authorization"] == f"JWT {MOCK_JWT}"


def test_authentication_cached_expired(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - a valid API Key
    When
        - An expired token is stored in the integration context
    Then
        - the authentication is performed
        - the new token is stored
    """
    from ExpanseV2 import Client
    import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
    from datetime import datetime

    MOCK_JWT = "JWT"
    MOCK_AUTH = {"token": MOCK_JWT}
    MOCK_NOW = "2020-11-25T0:10:10.000000Z"
    TOKEN_EXPIRES = -600  # stored token expired 600s ago
    TOKEN_DURATION = 7200  # expiration of the new token

    MOCK_NOW_DT = datetime.strptime(MOCK_NOW, "%Y-%m-%dT%H:%M:%S.%fZ")
    MOCK_EXP_TS = MOCK_NOW_DT.timestamp() + TOKEN_DURATION  # expiration of the new token
    MOCK_STORED_EXP_TS = MOCK_NOW_DT.timestamp() + TOKEN_EXPIRES  # expiration of the stored token

    MOCK_CACHED_TOKEN = {"token": MOCK_JWT, "expires": MOCK_STORED_EXP_TS}

    mock_get_ic = mocker.patch.object(demisto, "getIntegrationContext", return_value=MOCK_CACHED_TOKEN)
    mock_set_ic = mocker.patch.object(demisto, "setIntegrationContext")

    requests_mock.get("https://example.com/api/v1/IdToken", json=MOCK_AUTH)

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    mocker.patch.object(client, "_get_utcnow", return_value=MOCK_NOW_DT)

    client.authenticate()

    assert mock_get_ic.call_count == 1
    assert mock_set_ic.call_count == 1
    assert client._headers["Authorization"] == f"JWT {MOCK_JWT}"
    assert mock_set_ic.call_args_list[0][0][0]["token"] == MOCK_JWT
    assert mock_set_ic.call_args_list[0][0][0]["expires"] == MOCK_EXP_TS


def test_fetch_incidents(requests_mock, mocker):
    """
    Given:
        - an Expanse client
        - a stored first fetch time
        - a stored last incident id
        - max_fetch set to 2
        - filter based on business units
    When
        - Fetching incidents
    Then
        - first page of expanse issues is is read (max_fetch+1, which means positions 1 to 3 from the file)
        - incidents are skipped until the stored last incident id is found
        - the next good incident is returned (position 3 is saved)
        - another page is required and read (positions 4 to 6 from the file)
        - the first incident is also returned (position 4)
        - other incidents are not returned as we have reached the requested max_fetch (2)
    """
    from ExpanseV2 import Client, fetch_incidents, datestring_to_timestamp_us

    MOCK_LAST_FETCH_TIME = "2020-09-28T17:55:57.610230Z"
    MOCK_LAST_FETCH_ID = "6295b21f-f2e5-3189-9d6d-338cb129014c"

    MOCK_NEXT_FETCH_TIME = "2020-09-28T17:55:58.077836Z"
    MOCK_NEXT_FETCH_ID = "a4091781-373c-36c4-b928-c57e55f514f0"
    MOCK_BU = "testcorp123 Dev,BU2 Prod"
    MOCK_LIMIT = "2"
    MOCK_NEXT_PAGE_TOKEN = "token1"

    MOCK_URL = f'https://example.com/api/v1/issues/issues?limit={int(MOCK_LIMIT)+1}&businessUnitName={MOCK_BU}&sort=created'
    mock_issues = util_load_json("test_data/expanse_get_issues.json")
    mock_issues_page1 = {
        "data": mock_issues["data"][:int(MOCK_LIMIT) + 1],
        "pagination": {
            "next": f"{MOCK_URL}&pageToken={MOCK_NEXT_PAGE_TOKEN}",
            "prev": None
        },
        "meta": {
            "nextPageToken": MOCK_NEXT_PAGE_TOKEN,
            "prevPageToken": None,
            "totalCount": 5
        }
    }
    mock_issues_page2 = {
        "data": mock_issues["data"][int(MOCK_LIMIT) + 1:],
        "pagination": {
            "next": None,
            "prev": None
        },
        "meta": {
            "nextPageToken": None,
            "prevPageToken": None,
            "totalCount": 5
        }
    }

    mock_incidents = util_load_json("test_data/fetch_incidents_output.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"{MOCK_URL}", json=mock_issues_page1)
    requests_mock.get(f"{MOCK_URL}&pageToken={MOCK_NEXT_PAGE_TOKEN}", json=mock_issues_page2)
    last_run = {
        'last_fetch': datestring_to_timestamp_us(MOCK_LAST_FETCH_TIME),
        'last_issue_id': MOCK_LAST_FETCH_ID
    }

    next_run, result = fetch_incidents(client, max_incidents=int(MOCK_LIMIT), last_run=last_run, business_units=MOCK_BU,
                                       first_fetch=None, priority=None, activity_status=None, progress_status=None,
                                       issue_types=None, tags=None, mirror_direction=None, sync_tags=False,
                                       fetch_details=None, fetch_behavior=None)

    assert next_run == {
        'last_fetch': datestring_to_timestamp_us(MOCK_NEXT_FETCH_TIME),
        'last_issue_id': MOCK_NEXT_FETCH_ID
    }
    assert len(result) == int(MOCK_LIMIT)
    assert result == mock_incidents


def test_get_remote_data_command_should_update(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (id and lastUpdate time set to a lower than incident modification time)
        - a raw update (get-issue-updates results)
    When
        - running get_remote_data_command with changes to make
    Then
        - the mirrored_object in the GetRemoteDataResponse contains the modified incident fields
        - the entries in the GetRemoteDataResponse contain expected entries
    """
    from ExpanseV2 import Client, get_remote_data_command

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    MOCK_ISSUE_ID = "a827f1a5-f223-4bf6-80e0-e8481bce8e2c"
    MOCK_LIMIT = "5"

    args = {"id": MOCK_ISSUE_ID, "lastUpdate": 0}

    MOCK_UPDATES = {
        'progressStatus': 'Investigating',
        'priority': 'Critical',
        'xsoar_severity': 4,
        'id': 'a827f1a5-f223-4bf6-80e0-e8481bce8e2c'
    }

    MOCK_ENTRIES = util_load_json("test_data/get_remote_data_updated_entries.json")

    mock_updates = util_load_json("test_data/expanse_get_issue_updates.json")
    mock_updates["data"] = mock_updates["data"][: int(MOCK_LIMIT)]
    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v1/issues/issues/{MOCK_ISSUE_ID}/updates?limit=100", json=mock_updates)

    result = get_remote_data_command(client, args)

    assert result.mirrored_object == MOCK_UPDATES
    assert result.entries == MOCK_ENTRIES


def test_get_remote_data_command_no_update(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (id and lastUpdate time set to a lower than incident modification time)
        - no updates (get-issue-updates empty results)
    When
        - running get_remote_data_command with no changes to make
    Then
        - the mirrored_object in the GetRemoteDataResponse contains the modified incident fields
        - the entries in the GetRemoteDataResponse contain expected entries
    """
    from ExpanseV2 import Client, get_remote_data_command

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    MOCK_ISSUE_ID = "a827f1a5-f223-4bf6-80e0-e8481bce8e2c"

    args = {"id": MOCK_ISSUE_ID, "lastUpdate": 0}

    MOCK_UPDATES = {}
    MOCK_ENTRIES = []

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v1/issues/issues/{MOCK_ISSUE_ID}/updates?limit=100", json={})

    result = get_remote_data_command(client, args)

    assert result.mirrored_object == MOCK_UPDATES
    assert result.entries == MOCK_ENTRIES


def test_update_issue_command(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (issue_id, type of update, update value)
    When
        - running !expanse-update-issue
    Then
        - the issue is updated with the corresponding update type and value
        - the Expanse.IssueUpdate context is returned
    """
    from ExpanseV2 import Client, update_issue_command
    import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    MOCK_ISSUE_ID = "a827f1a5-f223-4bf6-80e0-e8481bce8e2c"
    MOCK_UPDATE_TYPE = "ProgressStatus"
    MOCK_UPDATE_VALUE = "InProgress"

    MOCK_ISSUE_UPDATE = {
        "created": "2020-11-26T15:13:01.147734Z",
        "id": "aaa9d812-0a4a-4741-ab63-8863e63d66a8",
        "issueId": MOCK_ISSUE_ID,
        "previousValue": "Investigating",
        "updateType": MOCK_UPDATE_TYPE,
        "user": {
            "username": "devUser"
        },
        "value": MOCK_UPDATE_VALUE
    }

    args = {
        "issue_id": MOCK_ISSUE_ID,
        "update_type": MOCK_UPDATE_TYPE,
        "value": MOCK_UPDATE_VALUE
    }

    requests_mock.post(f"https://example.com/api/v1/issues/issues/{MOCK_ISSUE_ID}/updates", json=MOCK_ISSUE_UPDATE)

    result = update_issue_command(client, args)

    assert result.outputs_prefix == "Expanse.IssueUpdate"
    assert result.outputs_key_field == "id"
    assert result.outputs == MOCK_ISSUE_UPDATE


def test_update_remote_system_command(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - incident changes (a comment and 3 field changes)
    When
        - outgoing mirroring triggered by a change in the incident
    Then
        - a comment is created in the Expanse issue
        - the Expanse issue is updated with the corresponding updates type and values
        - the returned result corresponds to the Expanse issue id
    """
    from ExpanseV2 import Client, update_remote_system_command
    import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    MOCK_ISSUE_ID = "a827f1a5-f223-4bf6-80e0-e8481bce8e2c"
    MOCK_EMAIL = "some@test.email"
    MOCK_COMMENT_ENTRIES = [{
        "type": 1,
        "contents": "Investigation being performed",
        "contentsformat": "text",
        "note": True,
        "tags": [],
        'category': 'chat'
    }]

    MOCK_DELTA = {
        "owner": "testuser",
        "severity": 4,
        "expanseprogressstatus": "InProgress"
    }

    args = {
        "entries": MOCK_COMMENT_ENTRIES,
        "delta": MOCK_DELTA,
        "remoteId": MOCK_ISSUE_ID,
        "incidentChanged": True,
        "inc_status": 1
    }

    mocker.patch.object(demisto, 'findUser', return_value={"email": MOCK_EMAIL})
    mock_upd = mocker.patch.object(client, 'update_issue')

    requests_mock.post(f"/v1/issues/issues/{MOCK_ISSUE_ID}/updates", json={})

    result = update_remote_system_command(client, args)

    assert result == MOCK_ISSUE_ID
    assert mock_upd.call_count == 4
    assert mock_upd.call_args_list[0][1]["issue_id"] == MOCK_ISSUE_ID
    assert mock_upd.call_args_list[0][1]["update_type"] == 'Comment'
    assert mock_upd.call_args_list[0][1]["value"] == 'Investigation being performed'
    assert mock_upd.call_args_list[1][1]["issue_id"] == MOCK_ISSUE_ID
    assert mock_upd.call_args_list[1][1]["update_type"] == 'Assignee'
    assert mock_upd.call_args_list[1][1]["value"] == MOCK_EMAIL
    assert mock_upd.call_args_list[2][1]["issue_id"] == MOCK_ISSUE_ID
    assert mock_upd.call_args_list[2][1]["update_type"] == 'Priority'
    assert mock_upd.call_args_list[2][1]["value"] == 'Critical'
    assert mock_upd.call_args_list[3][1]["issue_id"] == MOCK_ISSUE_ID
    assert mock_upd.call_args_list[3][1]["update_type"] == 'ProgressStatus'
    assert mock_upd.call_args_list[3][1]["value"] == 'InProgress'


def test_expanse_get_issue(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (issue_id)
    When
        - running !expanse-get-issue
    Then
        - the issue is retrieved and returned in the Context
    """
    from ExpanseV2 import Client, get_issue_command

    MOCK_ISSUE_ID = "62089967-7b41-3d49-a21d-d12753d8fd91"
    mock_issues = util_load_json("test_data/expanse_get_issues.json")
    mock_issue = [i for i in mock_issues["data"] if i["id"] == MOCK_ISSUE_ID][0]
    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v1/issues/issues/{MOCK_ISSUE_ID}", json=mock_issue)

    result = get_issue_command(client, {"issue_id": MOCK_ISSUE_ID})
    assert result.outputs_prefix == "Expanse.Issue"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_issue


def test_expanse_get_issues(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (businessunit, limit, sort)
    When
        - running !expanse-get-issues
    Then
        - the issues are retrieved and returned to the context
    """
    from ExpanseV2 import Client, get_issues_command

    MOCK_BU = "testcorp123 Dev,BU2 Prod"
    MOCK_LIMIT = "2"
    MOCK_SORT = "created"
    mock_issues = util_load_json("test_data/expanse_get_issues.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v1/issues/issues?limit={MOCK_LIMIT}&businessUnitName={MOCK_BU}&sort={MOCK_SORT}",
        json=mock_issues,
    )

    result = get_issues_command(client, {"business_unit": MOCK_BU, "limit": MOCK_LIMIT, "sort": MOCK_SORT})
    assert result.outputs_prefix == "Expanse.Issue"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_issues["data"][: int(MOCK_LIMIT)]


def test_expanse_get_issue_comments_command(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (issue_id, limit)
    When
        - running !expanse-get-issue-comments
    Then
        - the issue comments are retrieved and returned to the context
    """
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
    """
    Given:
        - an Expanse client
        - arguments (issue_id, limit)
    When
        - running !expanse-get-issue-updates
    Then
        - the issue updates are retrieved and returned to the context
    """
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
    """
    Given:
        - an Expanse client
        - arguments (limit)
    When
        - running !expanse-list-businessunits
    Then
        - the business units are retrieved and returned to the context
    """
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
    """
    Given:
        - an Expanse client
        - arguments (limit)
    When
        - running !expanse-list-providers
    Then
        - the providers are retrieved and returned to the context
    """
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
    """
    Given:
        - an Expanse client
        - arguments (limit)
    When
        - running !expanse-list-tags
    Then
        - the tags are retrieved and returned to the context
    """
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
    """
    Given:
        - an Expanse client
        - arguments (businessunit names, limit)
    When
        - running !expanse-get-ip-range
    Then
        - the IP ranges are retrieved and returned to the context
        - startAddress/endAddress are overridden and the corresponding CIDR is returned instead
        - DBotScore is present
    """
    from ExpanseV2 import Client, get_iprange_command
    from CommonServerPython import Common

    MOCK_BU = "BU 1 Dev,BU 2 Prod"
    MOCK_LIMIT = "2"
    mock_ipranges = util_load_json("test_data/expanse_get_ip_range.json")
    # input has startAddress and endAddress, doesn't have CIDR
    mock_ipranges_input = copy.deepcopy(mock_ipranges)
    for d in mock_ipranges_input["data"]:
        del d["cidr"]

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/ip-range?include=&limit={MOCK_LIMIT}&business-unit-names={MOCK_BU}", json=mock_ipranges_input
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
    assert isinstance(result.indicators[0], Common.Indicator)
    assert result.indicators[0].indicator == mock_ipranges_output["data"][0]["cidr"]


def test_expanse_create_tag(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (tag name, tag description)
    When
        - running !expanse-create-tag
    Then
        - A new tag is created in Expanse
        - the tag information is returned to the Context as Expanse.Tag
    """
    from ExpanseV2 import Client, create_tag_command

    MOCK_TAGNAME = "xsoar-test-tag1"
    MOCK_TAGDESC = "Test tag"
    mock_tag = util_load_json("test_data/expanse_create_tag.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.post("https://example.com/api/v3/annotations/tags", json=mock_tag)

    result = create_tag_command(client, {"name": MOCK_TAGNAME, "description": MOCK_TAGDESC})

    assert result.outputs_prefix == "Expanse.Tag"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_tag


def test_expanse_assign_single_tag_to_iprange(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (single tag name, ip range asset ID)
    When
        - running !expanse-assign-tags-to-iprange
    Then
        - The corresponding tag ID from the tag is retrieved via API
        - The tag ID is assigned to the IP range
        - "Operation Complete" is returned as human readable output
    """
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

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client, {"operation_type": OP_TYPE, "asset_type": ASSET_TYPE, "asset_id": MOCK_ASSET_ID, "tagnames": TAGS_BY_NAME}
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_unassign_single_tag_from_iprange(requests_mock, mocker):
    """
    Given:
        - an Expanse client
        - arguments (single tag name, ip range asset ID)
    When
        - running !expanse-unassign-tags-from-iprange
    Then
        - The corresponding tag ID from the tag is retrieved via API
        - The tag ID is unassigned from the IP range
        - "Operation Complete" is returned as human readable output
    """
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

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client, {"operation_type": OP_TYPE, "asset_type": ASSET_TYPE, "asset_id": MOCK_ASSET_ID, "tagnames": TAGS_BY_NAME}
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_assign_multiple_tags_to_iprange(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (1 tag id, 2 tag names, ip range asset ID)
    When
        - running !expanse-assign-tags-to-iprange
    Then
        - The corresponding 2 tag IDs from 2 the tag names are retrieved via API
        - The found tag IDs are merged with the provided one (total 3)
        - The 3 tag IDs are assigned to the IP range
        - "Operation Complete" is returned as human readable output
    """
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "IpRange"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(",") + ["e9308766-be41-46bc-ab36-1ae417ba341e", "b3308766-be41-46bc-ab36-1ae417ba3aaa"]
    ASSET_TYPE_URL = "ip-range"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID,
        },
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_unassign_multiple_tags_from_iprange(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (1 tag id, 2 tag names, ip range asset ID)
    When
        - running !expanse-unassign-tags-from-iprange
    Then
        - The corresponding 2 tag IDs from 2 the tag names are retrieved via API
        - The found tag IDs are merged with the provided one (total 3)
        - The 3 tag IDs are unassigned from the IP range
        - "Operation Complete" is returned as human readable output
    """
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "IpRange"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(",") + ["e9308766-be41-46bc-ab36-1ae417ba341e", "b3308766-be41-46bc-ab36-1ae417ba3aaa"]
    ASSET_TYPE_URL = "ip-range"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID,
        },
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_assign_single_tag_to_domain(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (single tag name, domain asset ID)
    When
        - running !expanse-assign-tags-to-domain
    Then
        - The corresponding tag ID from the tag is retrieved via API
        - The tag ID is assigned to the domain
        - "Operation Complete" is returned as human readable output
    """
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

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client, {"operation_type": OP_TYPE, "asset_type": ASSET_TYPE, "asset_id": MOCK_ASSET_ID, "tagnames": TAGS_BY_NAME}
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_unassign_single_tag_from_domain(requests_mock, mocker):
    """
    Given:
        - an Expanse client
        - arguments (single tag name, domain asset ID)
    When
        - running !expanse-unassign-tags-from-domain
    Then
        - The corresponding tag ID from the tag is retrieved via API
        - The tag ID is unassigned from the domain
        - "Operation Complete" is returned as human readable output
    """
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

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client, {"operation_type": OP_TYPE, "asset_type": ASSET_TYPE, "asset_id": MOCK_ASSET_ID, "tagnames": TAGS_BY_NAME}
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_assign_multiple_tags_to_domain(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (1 tag id, 2 tag names, domain asset ID)
    When
        - running !expanse-assign-tags-to-domain
    Then
        - The corresponding 2 tag IDs from 2 the tag names are retrieved via API
        - The found tag IDs are merged with the provided one (total 3)
        - The 3 tag IDs are assigned to the domain
        - "Operation Complete" is returned as human readable output
    """
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "Domain"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(",") + ["e9308766-be41-46bc-ab36-1ae417ba341e", "b3308766-be41-46bc-ab36-1ae417ba3aaa"]
    ASSET_TYPE_URL = "domains"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID,
        },
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_unassign_multiple_tags_from_domain(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (1 tag id, 2 tag names, ip range asset ID)
    When
        - running !expanse-unassign-tags-from-domain
    Then
        - The corresponding 2 tag IDs from 2 the tag names are retrieved via API
        - The found tag IDs are merged with the provided one (total 3)
        - The 3 tag IDs are unassigned from the domain
        - "Operation Complete" is returned as human readable output
    """
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "Domain"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(",") + ["e9308766-be41-46bc-ab36-1ae417ba341e", "b3308766-be41-46bc-ab36-1ae417ba3aaa"]
    ASSET_TYPE_URL = "domains"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID,
        },
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_assign_single_tag_to_certificate(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (single tag name, certificate asset ID)
    When
        - running !expanse-assign-tags-to-certificate
    Then
        - The corresponding tag ID from the tag is retrieved via API
        - The tag ID is assigned to the certificate
        - "Operation Complete" is returned as human readable output
    """
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

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client, {"operation_type": OP_TYPE, "asset_type": ASSET_TYPE, "asset_id": MOCK_ASSET_ID, "tagnames": TAGS_BY_NAME}
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_unassign_single_tag_from_certificate(requests_mock, mocker):
    """
    Given:
        - an Expanse client
        - arguments (single tag name, certificate asset ID)
    When
        - running !expanse-unassign-tags-from-certificate
    Then
        - The corresponding tag ID from the tag is retrieved via API
        - The tag ID is unassigned from the certificate
        - "Operation Complete" is returned as human readable output
    """
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

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client, {"operation_type": OP_TYPE, "asset_type": ASSET_TYPE, "asset_id": MOCK_ASSET_ID, "tagnames": TAGS_BY_NAME}
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_assign_multiple_tags_to_certificate(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (1 tag id, 2 tag names, certificate asset ID)
    When
        - running !expanse-assign-tags-to-certificate
    Then
        - The corresponding 2 tag IDs from 2 the tag names are retrieved via API
        - The found tag IDs are merged with the provided one (total 3)
        - The 3 tag IDs are assigned to the certificate
        - "Operation Complete" is returned as human readable output
    """
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "ASSIGN"
    ASSET_TYPE = "Certificate"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(",") + ["e9308766-be41-46bc-ab36-1ae417ba341e", "b3308766-be41-46bc-ab36-1ae417ba3aaa"]
    ASSET_TYPE_URL = "certificates"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID,
        },
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_unassign_multiple_tags_from_certificate(mocker, requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (1 tag id, 2 tag names, certificate asset ID)
    When
        - running !expanse-unassign-tags-from-certificate
    Then
        - The corresponding 2 tag IDs from 2 the tag names are retrieved via API
        - The found tag IDs are merged with the provided one (total 3)
        - The 3 tag IDs are unassigned from the certificate
        - "Operation Complete" is returned as human readable output
    """
    from ExpanseV2 import Client, manage_asset_tags_command

    OP_TYPE = "UNASSIGN"
    ASSET_TYPE = "Certificate"
    TAGS_BY_NAME = "xsoar-test-123,xsoar-false-positive"  # tags passed by name
    TAGS_BY_ID = "ccc08766-be41-46bc-ab36-1ae417ba3ddd"  # tag passed by id
    TAGIDS = TAGS_BY_ID.split(",") + ["e9308766-be41-46bc-ab36-1ae417ba341e", "b3308766-be41-46bc-ab36-1ae417ba3aaa"]
    ASSET_TYPE_URL = "certificates"

    MOCK_ASSET_ID = "c871feab-7d38-4cc5-9d36-5dad76f6b389"
    MOCK_PAGE_LIMIT = "20"

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    # For list tags
    mock_tags = util_load_json("test_data/expanse_list_tags.json")
    requests_mock.get(f"https://example.com/api/v3/annotations/tags?limit={MOCK_PAGE_LIMIT}", json=mock_tags)

    requests_mock.post(f"https://example.com/api/v2/{ASSET_TYPE_URL}/tag-assignments/bulk", json={})

    mock_func = mocker.patch.object(client, "manage_asset_tags")

    result = manage_asset_tags_command(
        client,
        {
            "operation_type": OP_TYPE,
            "asset_type": ASSET_TYPE,
            "asset_id": MOCK_ASSET_ID,
            "tagnames": TAGS_BY_NAME,
            "tags": TAGS_BY_ID,
        },
    )

    assert len(mock_func.call_args_list) == 1
    assert mock_func.call_args_list[0][0][0] == ASSET_TYPE_URL
    assert mock_func.call_args_list[0][0][1] == OP_TYPE
    assert mock_func.call_args_list[0][0][2] == MOCK_ASSET_ID
    assert sorted(mock_func.call_args_list[0][0][3]) == sorted(TAGIDS)
    assert result.outputs_prefix is None
    assert result.outputs_key_field is None
    assert result.outputs is None
    assert result.readable_output == "Operation complete"


def test_expanse_get_certificate_by_id(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (md5 hash)
    When
        - running !expanse-get-certificate with a hash
    Then
        - the Certificate is retrieved and returned to the context as Expanse.Certificate
        - the Certificate standard context is present
        - DBotScore is present
    """
    from ExpanseV2 import Client, get_certificate_command

    MOCK_MD5HASH = "mock_md5_hash"
    mock_cert = util_load_json("test_data/expanse_certificate.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v2/assets/certificates/{MOCK_MD5HASH}", json=mock_cert)

    result = get_certificate_command(client, {"pem_md5_hash": MOCK_MD5HASH})
    assert result.outputs_prefix == "Expanse.Certificate"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_cert
    #  XXX TODO command is being refactored


def test_expanse_get_certificate_by_query(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (businessunits, limit)
    When
        - running !expanse-get-certificate with a query
    Then
        - the Certificates are retrieved and returned to the context as Expanse.Certificate
        - the Certificate standard context is present
        - DBotScore is present
    """
    from ExpanseV2 import Client, get_certificate_command

    MOCK_BU = "Test Company Dev,Test Company Prod"
    MOCK_LIMIT = "2"
    mock_certs = util_load_json("test_data/expanse_get_certificate.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/assets/certificates?limit={MOCK_LIMIT}&businessUnitName={MOCK_BU}", json=mock_certs
    )

    result = get_certificate_command(client, {"businessunitnames": MOCK_BU, "limit": MOCK_LIMIT})

    assert result.outputs_prefix == "Expanse.Certificate"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_certs["data"][: int(MOCK_LIMIT)]
    # XXX TODO command is being refactored


def test_expanse_certificate(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (certificate hash)
    When
        - running !certificate
    Then
        - the certificate is retrieved and returned to the context as Expanse.Certificate
        - the Certificate standard context is present
        - DBotScore is present
    """
    pass  # XXX TODO command is being refactored


def test_expanse_get_domain(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (businessunit names, limit)
    When
        - running !expanse-get-domain
    Then
        - the domains are retrieved and returned to the context as Expanse.Domain
        - Domain standard context is present
        - DBotScore is present
    """
    from ExpanseV2 import Client, get_domain_command
    from CommonServerPython import Common, DBotScoreType

    MOCK_BU = "Test Company Dev,Test Company Prod"
    MOCK_LIMIT = "2"
    mock_domain_data = util_load_json("test_data/expanse_get_domain.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(
        f"https://example.com/api/v2/assets/domains?limit={MOCK_LIMIT}&businessUnitName={MOCK_BU}", json=mock_domain_data
    )

    result = get_domain_command(client, {"businessunitnames": MOCK_BU, "limit": MOCK_LIMIT})
    assert result.outputs_prefix == "Expanse.Domain"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_domain_data["data"][: int(MOCK_LIMIT)]
    assert isinstance(result.indicators[0], Common.Domain)
    assert result.indicators[0].domain == mock_domain_data["data"][0]["domain"]
    assert isinstance(result.indicators[0].dbot_score, Common.DBotScore)
    assert result.indicators[0].dbot_score.indicator == mock_domain_data["data"][0]["domain"]
    assert result.indicators[0].dbot_score.integration_name == "ExpanseV2"
    assert result.indicators[0].dbot_score.score == Common.DBotScore.NONE
    assert result.indicators[0].dbot_score.indicator_type == DBotScoreType.DOMAIN
    assert result.indicators[0].registrant_country == mock_domain_data["data"][0]["whois"][0]["registrant"]["country"]
    assert result.indicators[1].domain == mock_domain_data["data"][1]["domain"]


def test_domain(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (single domain)
    When
        - running !domain
    Then
        - the domain is retrieved and returned to the context as Expanse.Domain
        - Domain standard context is present
        - DBotScore is present
    """
    from ExpanseV2 import Client, domain_command
    from CommonServerPython import Common, DBotScoreType

    MOCK_DOMAIN = "tableau.example.com"
    mock_domain_data = util_load_json("test_data/domain.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get(f"https://example.com/api/v2/assets/domains/{MOCK_DOMAIN}", json=mock_domain_data)

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
    assert result.indicators[0].registrant_country == mock_domain_data["whois"][0]["registrant"]["country"]


def test_ip(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (single ip address)
    When
        - running !ip
    Then
        - the IP is retrieved and returned to the context as Expanse.IP
        - IP standard context is present
        - DBotScore is present
    """
    from ExpanseV2 import Client, ip_command
    from CommonServerPython import Common, DBotScoreType

    MOCK_IP = "1.1.1.1"
    mock_ip_data = util_load_json("test_data/ip.json")

    client = Client(api_key="key", base_url="https://example.com/api/", verify=True, proxy=False)

    requests_mock.get("https://example.com/api/v2/assets/ips", json=mock_ip_data)

    result = ip_command(client, {"ip": MOCK_IP})
    assert result.outputs_prefix == "Expanse.IP"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_ip_data["data"]
    assert isinstance(result.indicators[0], Common.IP)
    assert result.indicators[0].ip == MOCK_IP
    assert isinstance(result.indicators[0].dbot_score, Common.DBotScore)
    assert result.indicators[0].dbot_score.indicator == MOCK_IP
    assert result.indicators[0].dbot_score.integration_name == "ExpanseV2"
    assert result.indicators[0].dbot_score.score == Common.DBotScore.NONE
    assert result.indicators[0].dbot_score.indicator_type == DBotScoreType.IP


def test_cidr(requests_mock):
    """
    Given:
        - an Expanse client
        - arguments (single CIDR)
    When
        - running !cidr
    Then
        - the CIDR (from Expanse IP ranges) is retrieved and returned to the context as Expanse.IPRange
        - startAddress/endAddress are overridden and the corresponding CIDR is returned instead
        - DBotScore is present
    """
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
        f"https://example.com/api/v2/ip-range?include={MOCK_INCLUDE}&limit=1&inet={MOCK_INET}", json=mock_cidr_input
    )

    result = cidr_command(client, {"cidr": MOCK_INET, "include": MOCK_INCLUDE})

    assert result.outputs_prefix == "Expanse.IPRange"
    assert result.outputs_key_field == "id"
    # output has CIDR, doesn't have startAddress and endAddress
    mock_cidr_output = copy.deepcopy(mock_cidr)
    for d in mock_cidr_output["data"]:
        del d["startAddress"]
        del d["endAddress"]
    assert result.outputs == mock_cidr_output["data"]
    assert isinstance(result.indicators[0], Common.Indicator)
    assert result.indicators[0].indicator == MOCK_INET


def test_expanse_get_risky_flows(mocker):
    """
    Given:
        - an Expanse client
        - arguments (ip, limit)
    When
        - running !expanse-get-risky-flows
    Then
        - the Risky Flows for the IP from Behavior are retrieved and returned to the context
    """
    pass  # XXX TODO need access APIs


def test_expanse_list_risk_rules(mocker):
    """
    Given:
        - an Expanse client
        - arguments (limit)
    When
        - running !expanse-list-risk-rules
    Then
        - the risk rules are retrieved and returned to the context
    """
    pass  # XXX TODO need access to APIs
