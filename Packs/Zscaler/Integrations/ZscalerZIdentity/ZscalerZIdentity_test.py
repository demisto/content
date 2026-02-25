import demistomock as demisto
import pytest
import json
import time

from ZscalerZIdentity import (
    Client,
    _filter_and_limit,
    _dbot_score_for_url,
    zia_denylist_list_command,
    zia_denylist_update_command,
    zia_allowlist_list_command,
    zia_allowlist_update_command,
    zia_category_list_command,
    zia_category_update_command,
    zia_url_quota_get_command,
    zia_ip_destination_group_list_command,
    zia_ip_destination_group_update_command,
    zia_ip_destination_group_add_command,
    zia_ip_destination_group_delete_command,
    zia_user_list_command,
    zia_user_update_command,
    zia_groups_list_command,
    zia_departments_list_command,
    zia_sandbox_report_get_command,
    zia_activate_changes_command,
    url_command,
    ip_command,
    domain_command,
    test_module_command,
    SUSPICIOUS_CATEGORIES,
)
from CommonServerPython import DemistoException, Common, CommandResults


# ---- Fixtures ----


def load_json(path: str):
    """Load a JSON file from disk and return its parsed content."""
    with open(path) as f:
        return json.load(f)


def get_outputs(result: CommandResults) -> dict:
    """Extract outputs dict from a CommandResults, asserting it is a dict."""
    ctx = result.to_context()
    # outputs are nested under EntryContext key
    entry_context = ctx.get("EntryContext", {})
    if not entry_context:
        return {}
    # Return the first value (the actual outputs)
    for val in entry_context.values():
        return val  # type: ignore[return-value]
    return {}


def get_outputs_list(result: CommandResults) -> list:
    """Extract outputs as a list from a CommandResults."""
    ctx = result.to_context()
    entry_context = ctx.get("EntryContext", {})
    if not entry_context:
        return []
    for val in entry_context.values():
        if isinstance(val, list):
            return val
        return [val]
    return []


@pytest.fixture
def mock_client() -> Client:
    """Return a Client instance with mocked token retrieval."""
    client = Client(
        domain="testdomain",
        client_id="test_client_id",
        client_secret="test_client_secret",
        verify=False,
        proxy=False,
        reliability="C - Fairly reliable",
        auto_activate=True,
        suspicious_categories=list(SUSPICIOUS_CATEGORIES),
    )
    return client


@pytest.fixture(autouse=True)
def mock_demisto_params(mocker):
    """Patch demisto.params() with test instance configuration."""
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "domain": "testdomain",
            "credentials": {"identifier": "test_client_id", "password": "test_client_secret"},
            "reliability": "C - Fairly reliable",
            "auto_activate": True,
            "suspicious_categories": "SUSPICIOUS_DESTINATION,SPYWARE_OR_ADWARE",
            "insecure": True,
            "proxy": False,
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")


@pytest.fixture(autouse=True)
def mock_integration_context(mocker):
    """Mock integration context to return a valid cached token."""
    mocker.patch(
        "ZscalerZIdentity.get_integration_context",
        return_value={
            "access_token": "mock_access_token",
            "token_expires_at": time.time() + 3600,
        },
    )
    mocker.patch("ZscalerZIdentity.set_integration_context")


# ---- Helper ----


def _patch_api(mocker, client: Client, return_value):
    """Patch client.api_request to return a fixed value."""
    return mocker.patch.object(client, "api_request", return_value=return_value)


# ---- Unit tests: helpers ----


class TestFilterAndLimit:
    def test_no_filter_no_query(self):
        """
        Given: A mixed list of URLs and IPs with no filter or query.
        When: _filter_and_limit is called with empty filter and query strings.
        Then: The original list is returned unchanged.
        """
        items = ["a.com", "1.2.3.4", "b.net"]
        result = _filter_and_limit(items, "", "", 50, False)
        assert result == items

    def test_filter_url(self):
        """
        Given: A mixed list of URLs and IPs.
        When: _filter_and_limit is called with filter='url'.
        Then: Only URL entries (non-IP) are returned; IP addresses are excluded.
        """
        items = ["a.com", "1.2.3.4", "b.net"]
        result = _filter_and_limit(items, "url", "", 50, False)
        assert "1.2.3.4" not in result
        assert "a.com" in result

    def test_filter_ip(self):
        """
        Given: A mixed list of URLs and IPs.
        When: _filter_and_limit is called with filter='ip'.
        Then: Only IPv4 address entries are returned.
        """
        items = ["a.com", "1.2.3.4", "b.net"]
        result = _filter_and_limit(items, "ip", "", 50, False)
        assert result == ["1.2.3.4"]

    def test_query_match(self):
        """
        Given: A list of domain strings.
        When: _filter_and_limit is called with a regex query matching only one entry.
        Then: Only the matching entry is returned.
        """
        items = ["malicious.com", "safe.net", "malware.org"]
        result = _filter_and_limit(items, "", "malicious", 50, False)
        assert result == ["malicious.com"]

    def test_limit(self):
        """
        Given: A list of four items and a limit of 2.
        When: _filter_and_limit is called with all_results=False.
        Then: Only the first two items are returned.
        """
        items = ["a.com", "b.com", "c.com", "d.com"]
        result = _filter_and_limit(items, "", "", 2, False)
        assert result == ["a.com", "b.com"]

    def test_all_results_overrides_limit(self):
        """
        Given: A list of four items and a limit of 2.
        When: _filter_and_limit is called with all_results=True.
        Then: All four items are returned, ignoring the limit.
        """
        items = ["a.com", "b.com", "c.com", "d.com"]
        result = _filter_and_limit(items, "", "", 2, True)
        assert result == items


class TestDBotScoreCalculation:
    def test_miscellaneous_returns_none(self):
        """
        Given: A URL classified as MISCELLANEOUS_OR_UNKNOWN with no security alert.
        When: _dbot_score_for_url is called.
        Then: DBotScore.NONE is returned.
        """
        score = _dbot_score_for_url("MISCELLANEOUS_OR_UNKNOWN", "", list(SUSPICIOUS_CATEGORIES))
        assert score == Common.DBotScore.NONE

    def test_suspicious_category(self):
        """
        Given: A URL with a security alert category that is in the suspicious list.
        When: _dbot_score_for_url is called.
        Then: DBotScore.SUSPICIOUS is returned.
        """
        score = _dbot_score_for_url("MALWARE_SITE", "SUSPICIOUS_DESTINATION", list(SUSPICIOUS_CATEGORIES))
        assert score == Common.DBotScore.SUSPICIOUS

    def test_bad_category(self):
        """
        Given: A URL with a security alert category that is NOT in the suspicious list.
        When: _dbot_score_for_url is called.
        Then: DBotScore.BAD is returned.
        """
        score = _dbot_score_for_url("MALWARE_SITE", "MALWARE_SITE", list(SUSPICIOUS_CATEGORIES))
        assert score == Common.DBotScore.BAD

    def test_good_no_security_alert(self):
        """
        Given: A URL with a benign classification and no security alert.
        When: _dbot_score_for_url is called.
        Then: DBotScore.GOOD is returned.
        """
        score = _dbot_score_for_url("BUSINESS_AND_ECONOMY", "", list(SUSPICIOUS_CATEGORIES))
        assert score == Common.DBotScore.GOOD


# ---- Unit tests: OAuth token caching ----


class TestTokenCaching:
    def test_uses_cached_token(self, mock_client, mocker):
        """
        Given: A valid non-expired access token is cached in the integration context.
        When: _get_access_token is called.
        Then: The cached token is returned without making any HTTP request.
        """
        http_mock = mocker.patch.object(mock_client, "_http_request")
        token = mock_client._get_access_token()
        assert token == "mock_access_token"
        http_mock.assert_not_called()

    def test_fetches_new_token_when_expired(self, mock_client, mocker):
        """
        Given: An expired access token is in the integration context.
        When: _get_access_token is called.
        Then: A new token is fetched from ZIdentity and returned.
        """
        mocker.patch(
            "ZscalerZIdentity.get_integration_context",
            return_value={
                "access_token": "old_token",
                "token_expires_at": time.time() - 10,  # expired
            },
        )
        mocker.patch.object(
            mock_client,
            "_http_request",
            return_value={"access_token": "new_token", "expires_in": 3600},
        )
        token = mock_client._get_access_token()
        assert token == "new_token"

    def test_raises_on_missing_token(self, mock_client, mocker):
        """
        Given: The integration context has an expired token and ZIdentity returns no access_token.
        When: _get_access_token is called.
        Then: A DemistoException is raised with a message about failing to obtain the token.
        """
        mocker.patch(
            "ZscalerZIdentity.get_integration_context",
            return_value={"token_expires_at": time.time() - 10},
        )
        mocker.patch.object(mock_client, "_http_request", return_value={"error": "invalid_client"})
        with pytest.raises(DemistoException, match="Failed to obtain access token"):
            mock_client._get_access_token()


# ---- Unit tests: test_module ----


class TestTestModule:
    def test_ok(self, mock_client, mocker):
        """
        Given: The ZIA API is reachable and returns a valid status response.
        When: test_module_command is called.
        Then: The string "ok" is returned.
        """
        _patch_api(mocker, mock_client, {"status": "ACTIVE"})
        result = test_module_command(mock_client)
        assert result == "ok"


# ---- Unit tests: denylist ----


class TestDenylistCommands:
    def test_list_returns_items(self, mock_client, mocker):
        """
        Given: The ZIA API returns a denylist with multiple entries.
        When: zia_denylist_list_command is called with no filters.
        Then: The result has the correct outputs_prefix and all entries appear in the output.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/denylist.json")
        _patch_api(mocker, mock_client, data)
        result = zia_denylist_list_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.DenyList"
        assert "malicious.com" in result.readable_output

    def test_list_with_filter_ip(self, mock_client, mocker):
        """
        Given: The ZIA API returns a denylist containing both URLs and IPs.
        When: zia_denylist_list_command is called with filter='ip'.
        Then: Only IP addresses appear in the output; URL entries are excluded.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/denylist.json")
        _patch_api(mocker, mock_client, data)
        result = zia_denylist_list_command(mock_client, {"filter": "ip"})
        assert "1.2.3.4" in result.readable_output
        assert "malicious.com" not in result.readable_output

    def test_list_with_query(self, mock_client, mocker):
        """
        Given: The ZIA API returns a denylist with multiple entries.
        When: zia_denylist_list_command is called with a query matching only one entry.
        Then: Only the matching entry appears in the output.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/denylist.json")
        _patch_api(mocker, mock_client, data)
        result = zia_denylist_list_command(mock_client, {"query": "malicious"})
        assert "malicious.com" in result.readable_output
        assert "badsite.net" not in result.readable_output

    def test_update_add(self, mock_client, mocker):
        """
        Given: A URL and action=ADD_TO_LIST are provided.
        When: zia_denylist_update_command is called.
        Then: The denylist is updated and a success message is returned.
        """
        mocker.patch.object(mock_client, "get_denylist", return_value={"blacklistUrls": []})
        mocker.patch.object(mock_client, "api_request", return_value=None)
        result = zia_denylist_update_command(mock_client, {"url": "evil.com", "action": "ADD_TO_LIST"})
        assert "successfully updated" in result.readable_output

    def test_update_requires_url_or_ip(self, mock_client):
        """
        Given: Neither url nor ip argument is provided.
        When: zia_denylist_update_command is called.
        Then: A DemistoException is raised indicating at least one is required.
        """
        with pytest.raises(DemistoException, match="At least one"):
            zia_denylist_update_command(mock_client, {"action": "ADD_TO_LIST"})

    def test_update_requires_action(self, mock_client):
        """
        Given: A URL is provided but the action argument is missing.
        When: zia_denylist_update_command is called.
        Then: A DemistoException is raised indicating action is required.
        """
        with pytest.raises(DemistoException, match="'action' argument is required"):
            zia_denylist_update_command(mock_client, {"url": "evil.com"})


# ---- Unit tests: allowlist ----


class TestAllowlistCommands:
    def test_list_returns_items(self, mock_client, mocker):
        """
        Given: The ZIA API returns an allowlist with multiple entries.
        When: zia_allowlist_list_command is called with no filters.
        Then: The result has the correct outputs_prefix and all entries appear in the output.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/allowlist.json")
        _patch_api(mocker, mock_client, data)
        result = zia_allowlist_list_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.AllowList"
        assert "trusted.com" in result.readable_output

    def test_update_add(self, mock_client, mocker):
        """
        Given: A new URL and action=ADD_TO_LIST are provided.
        When: zia_allowlist_update_command is called.
        Then: The allowlist is updated and a success message is returned.
        """
        mocker.patch.object(mock_client, "get_allowlist", return_value={"whitelistUrls": ["existing.com"]})
        mocker.patch.object(mock_client, "api_request", return_value=None)
        result = zia_allowlist_update_command(mock_client, {"url": "new.com", "action": "ADD_TO_LIST"})
        assert "successfully updated" in result.readable_output

    def test_update_requires_url(self, mock_client):
        """
        Given: The url argument is missing.
        When: zia_allowlist_update_command is called.
        Then: A DemistoException is raised indicating url is required.
        """
        with pytest.raises(DemistoException, match="'url' argument is required"):
            zia_allowlist_update_command(mock_client, {"action": "ADD_TO_LIST"})

    def test_update_add_deduplicates(self, mock_client, mocker):
        """
        Given: The allowlist already contains a URL that is being added again.
        When: zia_allowlist_update_command is called with action=ADD_TO_LIST.
        Then: The URL appears only once in the PUT payload sent to the API.
        """
        existing = {"whitelistUrls": ["existing.com"]}
        mocker.patch.object(mock_client, "get_allowlist", return_value=existing)
        api_mock = mocker.patch.object(mock_client, "api_request", return_value=None)
        zia_allowlist_update_command(mock_client, {"url": "existing.com", "action": "ADD_TO_LIST"})
        call_kwargs = api_mock.call_args
        sent_data = call_kwargs[1].get("data") or call_kwargs[0][2]
        assert sent_data["whitelistUrls"].count("existing.com") == 1


# ---- Unit tests: URL categories ----


class TestCategoryCommands:
    def test_list_all(self, mock_client, mocker):
        """
        Given: The ZIA API returns a list of two URL categories.
        When: zia_category_list_command is called with no arguments.
        Then: The result has the correct outputs_prefix and two categories in the raw response.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/url_categories.json")
        _patch_api(mocker, mock_client, data)
        result = zia_category_list_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.Category"
        assert isinstance(result.raw_response, list)
        assert len(result.raw_response) == 2  # type: ignore[arg-type]

    def test_list_lite_with_other_params_raises(self, mock_client):
        """
        Given: Both lite=true and custom_only=true are provided.
        When: zia_category_list_command is called.
        Then: A DemistoException is raised because lite cannot be combined with other parameters.
        """
        with pytest.raises(DemistoException, match="cannot be used in combination"):
            zia_category_list_command(mock_client, {"lite": "true", "custom_only": "true"})

    def test_update_requires_category_id(self, mock_client):
        """
        Given: The category_id argument is missing.
        When: zia_category_update_command is called.
        Then: A DemistoException is raised indicating category_id is required.
        """
        with pytest.raises(DemistoException, match="'category_id' argument is required"):
            zia_category_update_command(mock_client, {"url": "test.com", "action": "ADD_TO_LIST"})

    def test_update_requires_url_or_ip(self, mock_client):
        """
        Given: A category_id and action are provided but neither url nor ip is given.
        When: zia_category_update_command is called.
        Then: A DemistoException is raised indicating at least one of url or ip is required.
        """
        with pytest.raises(DemistoException, match="At least one"):
            zia_category_update_command(mock_client, {"category_id": "MUSIC", "action": "ADD_TO_LIST"})

    def test_update_success(self, mock_client, mocker):
        """
        Given: A valid category_id, url, and action=ADD_TO_LIST are provided.
        When: zia_category_update_command is called.
        Then: The category is updated and a success message is returned.
        """
        current_cat = {
            "id": "MUSIC",
            "configuredName": "Music",
            "superCategory": "ENTERTAINMENT",
            "customCategory": False,
            "urls": ["pandora.com"],
            "ipRanges": [],
        }
        mocker.patch.object(mock_client, "api_request", side_effect=[current_cat, None])
        result = zia_category_update_command(mock_client, {"category_id": "MUSIC", "url": "spotify.com", "action": "ADD_TO_LIST"})
        assert "successfully updated" in result.readable_output


# ---- Unit tests: URL quota ----


class TestUrlQuotaCommand:
    def test_returns_quota(self, mock_client, mocker):
        """
        Given: The ZIA API returns URL quota information.
        When: zia_url_quota_get_command is called.
        Then: The result has the correct outputs_prefix, raw_response matches the API data,
            and the human-readable output contains the provisioned URL count.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/url_quota.json")
        _patch_api(mocker, mock_client, data)
        result = zia_url_quota_get_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.UrlQuota"
        assert result.raw_response == data  # type: ignore[comparison-overlap]
        assert "Unique Urls Provisioned" in result.readable_output
        assert "25000" in result.readable_output


# ---- Unit tests: IP destination groups ----


class TestIPDestinationGroupCommands:
    def test_list_all(self, mock_client, mocker):
        """
        Given: The ZIA API returns a list of two IP destination groups.
        When: zia_ip_destination_group_list_command is called with no arguments.
        Then: The result has the correct outputs_prefix and two groups in the raw response.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/ip_destination_groups.json")
        _patch_api(mocker, mock_client, data)
        result = zia_ip_destination_group_list_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.IPDestinationGroup"
        assert isinstance(result.raw_response, list)
        assert len(result.raw_response) == 2  # type: ignore[arg-type]

    def test_list_category_type_without_lite_raises(self, mock_client):
        """
        Given: category_type is provided but lite is not set to True.
        When: zia_ip_destination_group_list_command is called.
        Then: A DemistoException is raised indicating category_type requires lite=True.
        """
        with pytest.raises(DemistoException, match="only works with the 'lite' argument"):
            zia_ip_destination_group_list_command(mock_client, {"category_type": "DSTN_IP"})

    def test_update_requires_group_id(self, mock_client):
        """
        Given: The group_id argument is missing.
        When: zia_ip_destination_group_update_command is called.
        Then: A DemistoException is raised indicating group_id is required.
        """
        with pytest.raises(DemistoException, match="'group_id' argument is required"):
            zia_ip_destination_group_update_command(mock_client, {})

    def test_update_success(self, mock_client, mocker):
        """
        Given: A valid group_id and a new group_name are provided.
        When: zia_ip_destination_group_update_command is called.
        Then: The group is updated, the success message appears in the output,
            and the raw_response matches the updated group data.
        """
        existing = {
            "id": 1001,
            "name": "Test Group",
            "type": "DSTN_IP",
            "addresses": ["10.0.0.1"],
            "description": "desc",
            "ipCategories": [],
            "countries": [],
        }
        updated = {**existing, "name": "Updated Group"}
        mocker.patch.object(mock_client, "list_ip_destination_groups", return_value=existing)
        mocker.patch.object(mock_client, "update_ip_destination_group", return_value=updated)
        result = zia_ip_destination_group_update_command(mock_client, {"group_id": "1001", "group_name": "Updated Group"})
        assert "successfully edited" in result.readable_output
        assert result.raw_response == updated  # type: ignore[comparison-overlap]

    def test_add_success(self, mock_client, mocker):
        """
        Given: Valid group_name, group_type, and address arguments are provided.
        When: zia_ip_destination_group_add_command is called.
        Then: A new group is created, the success message appears in the output,
            and the raw_response matches the created group data.
        """
        new_group = {
            "id": 1003,
            "name": "New Group",
            "type": "DSTN_IP",
            "addresses": ["192.168.0.1"],
            "description": "",
            "ipCategories": [],
            "countries": [],
        }
        mocker.patch.object(mock_client, "add_ip_destination_group", return_value=new_group)
        result = zia_ip_destination_group_add_command(
            mock_client, {"group_name": "New Group", "group_type": "DSTN_IP", "address": "192.168.0.1"}
        )
        assert "successfully added" in result.readable_output
        assert result.raw_response == new_group  # type: ignore[comparison-overlap]

    def test_delete_requires_group_id(self, mock_client):
        """
        Given: The group_id argument is missing.
        When: zia_ip_destination_group_delete_command is called.
        Then: A DemistoException is raised indicating group_id is required.
        """
        with pytest.raises(DemistoException, match="'group_id' argument is required"):
            zia_ip_destination_group_delete_command(mock_client, {})

    def test_delete_success(self, mock_client, mocker):
        """
        Given: A valid group_id is provided.
        When: zia_ip_destination_group_delete_command is called.
        Then: The group is deleted and a success message is returned.
        """
        mocker.patch.object(mock_client, "delete_ip_destination_group", return_value=None)
        result = zia_ip_destination_group_delete_command(mock_client, {"group_id": "1001"})
        assert "successfully deleted" in result.readable_output


# ---- Unit tests: users ----


class TestUserCommands:
    def test_list_all(self, mock_client, mocker):
        """
        Given: The ZIA API returns a list of two users.
        When: zia_user_list_command is called with no arguments.
        Then: The result has the correct outputs_prefix, two users in the raw response,
            and the first user's name appears in the human-readable output.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/users.json")
        _patch_api(mocker, mock_client, data)
        result = zia_user_list_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.User"
        assert isinstance(result.raw_response, list)
        assert len(result.raw_response) == 2  # type: ignore[arg-type]
        assert "John Doe" in result.readable_output

    def test_update_requires_user_id(self, mock_client):
        """
        Given: The user_id argument is missing.
        When: zia_user_update_command is called.
        Then: A DemistoException is raised indicating user_id is required.
        """
        with pytest.raises(DemistoException, match="'user_id' argument is required"):
            zia_user_update_command(mock_client, {})

    def test_update_success(self, mock_client, mocker):
        """
        Given: A valid user_id and a new comments value are provided.
        When: zia_user_update_command is called.
        Then: The user is updated, the success heading appears in the output,
            and the raw_response matches the updated user data.
        """
        existing = {"id": 1, "name": "John Doe", "email": "john@example.com", "comments": ""}
        updated = {**existing, "comments": "Updated comment"}
        mocker.patch.object(mock_client, "get_users", return_value=existing)
        mocker.patch.object(mock_client, "update_user", return_value=updated)
        result = zia_user_update_command(mock_client, {"user_id": "1", "comments": "Updated comment"})
        assert "ZIA User Updated" in result.readable_output
        assert result.raw_response == updated  # type: ignore[comparison-overlap]

    def test_update_with_json_user(self, mock_client, mocker):
        """
        Given: A valid user_id and a full JSON user object are provided.
        When: zia_user_update_command is called.
        Then: The JSON object is used as the base payload and the user is updated accordingly.
        """
        existing = {"id": 1, "name": "John Doe", "email": "john@example.com"}
        updated = {"id": 1, "name": "New Name", "email": "john@example.com"}
        mocker.patch.object(mock_client, "get_users", return_value=existing)
        mocker.patch.object(mock_client, "update_user", return_value=updated)
        result = zia_user_update_command(
            mock_client, {"user_id": "1", "user": '{"id": 1, "name": "New Name", "email": "john@example.com"}'}
        )
        assert result.raw_response == updated  # type: ignore[comparison-overlap]

    def test_update_invalid_json_raises(self, mock_client, mocker):
        """
        Given: A user_id is provided and the 'user' argument contains invalid JSON.
        When: zia_user_update_command is called.
        Then: A DemistoException is raised indicating the JSON is invalid.
        """
        mocker.patch.object(mock_client, "get_users", return_value={"id": 1})
        with pytest.raises(DemistoException, match="Invalid JSON"):
            zia_user_update_command(mock_client, {"user_id": "1", "user": "not-json"})


# ---- Unit tests: groups ----


class TestGroupsCommand:
    def test_list_groups(self, mock_client, mocker):
        """
        Given: The ZIA API returns a list of two user groups.
        When: zia_groups_list_command is called with no arguments.
        Then: The result has the correct outputs_prefix, two groups in the raw response,
            and the first group's name appears in the human-readable output.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/groups.json")
        _patch_api(mocker, mock_client, data)
        result = zia_groups_list_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.Groups"
        assert isinstance(result.raw_response, list)
        assert len(result.raw_response) == 2  # type: ignore[arg-type]
        assert "Engineering" in result.readable_output


# ---- Unit tests: departments ----


class TestDepartmentsCommand:
    def test_list_departments(self, mock_client, mocker):
        """
        Given: The ZIA API returns a list of two departments.
        When: zia_departments_list_command is called with no arguments.
        Then: The result has the correct outputs_prefix, two departments in the raw response,
            and the first department's name appears in the human-readable output.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/departments.json")
        _patch_api(mocker, mock_client, data)
        result = zia_departments_list_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.Department"
        assert isinstance(result.raw_response, list)
        assert len(result.raw_response) == 2  # type: ignore[arg-type]
        assert "IT" in result.readable_output


# ---- Unit tests: sandbox report ----


class TestSandboxReportCommand:
    def test_malicious_report(self, mock_client, mocker):
        """
        Given: The ZIA Sandbox API returns a report classifying the file as MALICIOUS.
        When: zia_sandbox_report_get_command is called with a valid MD5 hash.
        Then: The result has the correct outputs_prefix, a non-None indicator,
            a BAD DBotScore, and "Malicious" appears in the human-readable output.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/sandbox_report.json")
        _patch_api(mocker, mock_client, data)
        result = zia_sandbox_report_get_command(
            mock_client, {"md5": "abc123def456abc123def456abc123de", "report_type": "summary"}
        )
        assert result.outputs_prefix == "ZIA.SandboxReport"
        assert result.indicator is not None
        # Access dbot_score via to_context() to avoid Pylance issues with base Indicator type
        ctx = result.to_context()
        dbot_entries = ctx.get("EntryContext", {}).get("DBotScore(val.Indicator && val.Indicator == obj.Indicator)", [])
        if isinstance(dbot_entries, list) and dbot_entries:
            assert dbot_entries[0].get("Score") == Common.DBotScore.BAD
        assert "Malicious" in result.readable_output

    def test_requires_md5(self, mock_client):
        """
        Given: The md5 argument is missing.
        When: zia_sandbox_report_get_command is called.
        Then: A DemistoException is raised indicating md5 is required.
        """
        with pytest.raises(DemistoException, match="'md5' argument is required"):
            zia_sandbox_report_get_command(mock_client, {})


# ---- Unit tests: activate changes ----


class TestActivateChangesCommand:
    def test_activate(self, mock_client, mocker):
        """
        Given: The ZIA API returns an activation status of ACTIVE.
        When: zia_activate_changes_command is called.
        Then: The result has the correct outputs_prefix, the raw_response matches the API data,
            and "ACTIVE" appears in the human-readable output.
        """
        _patch_api(mocker, mock_client, {"status": "ACTIVE"})
        result = zia_activate_changes_command(mock_client, {})
        assert result.outputs_prefix == "ZIA.ActivationStatus"
        assert result.raw_response == {"status": "ACTIVE"}  # type: ignore[comparison-overlap]
        assert "ACTIVE" in result.readable_output


# ---- Unit tests: URL/IP/Domain lookup commands ----


class TestLookupCommands:
    def test_url_command_bad(self, mock_client, mocker):
        """
        Given: The ZIA API returns a classification with a non-suspicious security alert for a URL.
        When: url_command is called with two URLs.
        Then: Two results are returned and the malicious URL has a BAD DBotScore.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/url_lookup.json")
        mocker.patch.object(mock_client, "url_lookup", return_value=data)
        results = url_command(mock_client, {"url": "malicious-site.com,safe-site.com"})
        assert len(results) == 2
        bad_result = next(r for r in results if "malicious-site.com" in r.readable_output)
        # Verify via to_context that DBotScore is BAD
        ctx = bad_result.to_context()
        dbot_key = next((k for k in ctx.get("EntryContext", {}) if "DBotScore" in k), None)
        assert dbot_key is not None
        dbot_val = ctx["EntryContext"][dbot_key]
        score = dbot_val.get("Score") if isinstance(dbot_val, dict) else dbot_val[0].get("Score")
        assert score == Common.DBotScore.BAD

    def test_url_command_good(self, mock_client, mocker):
        """
        Given: The ZIA API returns a benign classification with no security alert for a URL.
        When: url_command is called with two URLs.
        Then: The benign URL has a GOOD DBotScore.
        """
        data = load_json("Packs/Zscaler/Integrations/ZscalerZIdentity/test_data/responses/url_lookup.json")
        mocker.patch.object(mock_client, "url_lookup", return_value=data)
        results = url_command(mock_client, {"url": "malicious-site.com,safe-site.com"})
        good_result = next(r for r in results if "safe-site.com" in r.readable_output)
        ctx = good_result.to_context()
        dbot_key = next((k for k in ctx.get("EntryContext", {}) if "DBotScore" in k), None)
        assert dbot_key is not None
        dbot_val = ctx["EntryContext"][dbot_key]
        score = dbot_val.get("Score") if isinstance(dbot_val, dict) else dbot_val[0].get("Score")
        assert score == Common.DBotScore.GOOD

    def test_ip_command(self, mock_client, mocker):
        """
        Given: The ZIA API returns a benign classification for an IP address.
        When: ip_command is called with a single IP.
        Then: One result is returned and the IP address appears in the human-readable output.
        """
        data = [{"url": "8.8.8.8", "urlClassifications": ["DNS"], "urlClassificationsWithSecurityAlert": []}]
        mocker.patch.object(mock_client, "url_lookup", return_value=data)
        results = ip_command(mock_client, {"ip": "8.8.8.8"})
        assert len(results) == 1
        assert "8.8.8.8" in results[0].readable_output

    def test_domain_command(self, mock_client, mocker):
        """
        Given: The ZIA API returns a benign classification for a domain.
        When: domain_command is called with a single domain.
        Then: One result is returned and the domain appears in the human-readable output.
        """
        data = [{"url": "example.com", "urlClassifications": ["BUSINESS_AND_ECONOMY"], "urlClassificationsWithSecurityAlert": []}]
        mocker.patch.object(mock_client, "url_lookup", return_value=data)
        results = domain_command(mock_client, {"domain": "example.com"})
        assert len(results) == 1
        assert "example.com" in results[0].readable_output

    def test_url_command_suspicious(self, mock_client, mocker):
        """
        Given: The ZIA API returns a security alert category that is in the suspicious list.
        When: url_command is called with the URL.
        Then: The result has a SUSPICIOUS DBotScore.
        """
        data = [
            {
                "url": "spyware-site.com",
                "urlClassifications": ["SPYWARE_OR_ADWARE"],
                "urlClassificationsWithSecurityAlert": ["SPYWARE_OR_ADWARE"],
            }
        ]
        mocker.patch.object(mock_client, "url_lookup", return_value=data)
        results = url_command(mock_client, {"url": "spyware-site.com"})
        ctx = results[0].to_context()
        dbot_key = next((k for k in ctx.get("EntryContext", {}) if "DBotScore" in k), None)
        assert dbot_key is not None
        dbot_val = ctx["EntryContext"][dbot_key]
        score = dbot_val.get("Score") if isinstance(dbot_val, dict) else dbot_val[0].get("Score")
        assert score == Common.DBotScore.SUSPICIOUS

    def test_url_command_empty_response(self, mock_client, mocker):
        """
        Given: The ZIA API returns an empty list for the URL lookup.
        When: url_command is called.
        Then: A single result with "No results found" in the readable output is returned.
        """
        mocker.patch.object(mock_client, "url_lookup", return_value=[])
        results = url_command(mock_client, {"url": "test.com"})
        assert len(results) == 1
        assert "No results found" in results[0].readable_output


# ---- Unit tests: client allowlist update logic ----


class TestClientAllowlistUpdate:
    def test_add_to_list(self, mock_client, mocker):
        """
        Given: The current allowlist contains "a.com" and "b.com" is being added.
        When: update_allowlist is called with action=ADD_TO_LIST.
        Then: Both "a.com" and "b.com" are present in the PUT payload sent to the API.
        """
        mocker.patch.object(mock_client, "get_allowlist", return_value={"whitelistUrls": ["a.com"]})
        api_mock = mocker.patch.object(mock_client, "api_request", return_value=None)
        mock_client.update_allowlist(["b.com"], "ADD_TO_LIST")
        sent = api_mock.call_args[1]["data"]
        assert "a.com" in sent["whitelistUrls"]
        assert "b.com" in sent["whitelistUrls"]

    def test_remove_from_list(self, mock_client, mocker):
        """
        Given: The current allowlist contains "a.com" and "b.com", and "a.com" is being removed.
        When: update_allowlist is called with action=REMOVE_FROM_LIST.
        Then: "a.com" is absent and "b.com" is present in the PUT payload sent to the API.
        """
        mocker.patch.object(mock_client, "get_allowlist", return_value={"whitelistUrls": ["a.com", "b.com"]})
        api_mock = mocker.patch.object(mock_client, "api_request", return_value=None)
        mock_client.update_allowlist(["a.com"], "REMOVE_FROM_LIST")
        sent = api_mock.call_args[1]["data"]
        assert "a.com" not in sent["whitelistUrls"]
        assert "b.com" in sent["whitelistUrls"]

    def test_overwrite(self, mock_client, mocker):
        """
        Given: The current allowlist contains "a.com" and "b.com", and OVERWRITE with "c.com" is requested.
        When: update_allowlist is called with action=OVERWRITE.
        Then: Only "c.com" is present in the PUT payload sent to the API.
        """
        mocker.patch.object(mock_client, "get_allowlist", return_value={"whitelistUrls": ["a.com", "b.com"]})
        api_mock = mocker.patch.object(mock_client, "api_request", return_value=None)
        mock_client.update_allowlist(["c.com"], "OVERWRITE")
        sent = api_mock.call_args[1]["data"]
        assert sent["whitelistUrls"] == ["c.com"]
