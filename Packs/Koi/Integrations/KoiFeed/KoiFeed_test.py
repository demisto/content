import demistomock as demisto
from CommonServerPython import *  # noqa
from KoiFeed import (
    Client,
    koi_risk_to_dbot_score,
    _build_indicator_from_item,
    _build_cve_indicators_from_item,
    _build_relationships,
    get_indicators_command,
    fetch_indicators_command,
    INDICATOR_TYPE,
    INTEGRATION_NAME,
)


MOCK_ITEM_BASIC = {
    "item_id": "test-extension-id",
    "marketplace": "chrome_web_store",
    "version": "2.1.0",
    "item_display_name": "Test Extension",
    "risk": 5.0,
    "risk_level": "medium",
    "publisher_name": "Test Publisher",
    "endpoint_count": 10,
    "findings": [],
    "platforms": ["chrome"],
    "status": "active",
    "installs_count": 1000,
    "first_seen": "2026-01-01T00:00:00Z",
    "last_seen": "2026-09-01T00:00:00Z",
    "short_description": "A test extension.",
}

MOCK_ITEM_SHA1 = {
    "item_id": "048728125C9B67AEBAF9C9A5C48A7B74CA229A0E",
    "marketplace": "windows",
    "version": "1.0.0",
    "item_display_name": "Windows Driver Package",
    "risk": None,
    "risk_level": "pending",
    "publisher_name": "Microsoft",
    "endpoint_count": 1,
    "findings": [],
    "platforms": ["windows"],
    "status": None,
    "installs_count": None,
    "first_seen": "2026-01-01T00:00:00Z",
    "last_seen": "2026-01-02T00:00:00Z",
    "short_description": "A driver package.",
}

MOCK_ITEM_WITH_CVES = {
    "item_id": "vulnerable-pkg",
    "marketplace": "npm",
    "version": "1.0.0",
    "item_display_name": "Vulnerable Package",
    "risk": 8.5,
    "risk_level": "high",
    "publisher_name": "Unknown",
    "endpoint_count": 5,
    "findings": ["CVE-2024-1234", "CVE-2024-5678", "some-other-finding"],
    "platforms": ["linux"],
    "status": "active",
    "installs_count": 500,
    "first_seen": "2026-01-01T00:00:00Z",
    "last_seen": "2026-09-01T00:00:00Z",
    "short_description": "A vulnerable package.",
}

MOCK_ITEM_VERSION_IN_NAME = {
    "item_id": "{GUID-1234}",
    "marketplace": "windows",
    "version": "04/03/2026 1.1.1.1",
    "item_display_name": "Windows Driver (04/03/2026 1.1.1.1)",
    "risk": None,
    "risk_level": "pending",
    "publisher_name": "Vendor",
    "endpoint_count": 1,
    "findings": [],
    "platforms": ["windows"],
    "status": None,
    "installs_count": None,
    "first_seen": "2026-01-01T00:00:00Z",
    "last_seen": "2026-01-02T00:00:00Z",
    "short_description": None,
}

MOCK_INVENTORY_RESPONSE = {
    "items": [MOCK_ITEM_BASIC, MOCK_ITEM_SHA1, MOCK_ITEM_WITH_CVES],
    "total_count": 3,
}


class TestKoiRiskToDbotScore:
    def test_none_inputs(self):
        assert koi_risk_to_dbot_score(None, None) == Common.DBotScore.NONE

    def test_pending_level(self):
        assert koi_risk_to_dbot_score(None, "pending") == Common.DBotScore.NONE

    def test_pending_level_case_insensitive(self):
        assert koi_risk_to_dbot_score(None, "Pending") == Common.DBotScore.NONE

    def test_low_score(self):
        assert koi_risk_to_dbot_score(2.0, None) == Common.DBotScore.GOOD

    def test_boundary_good(self):
        assert koi_risk_to_dbot_score(3.0, None) == Common.DBotScore.GOOD

    def test_medium_score(self):
        assert koi_risk_to_dbot_score(5.0, None) == Common.DBotScore.SUSPICIOUS

    def test_boundary_suspicious(self):
        assert koi_risk_to_dbot_score(6.0, None) == Common.DBotScore.SUSPICIOUS

    def test_high_score(self):
        assert koi_risk_to_dbot_score(8.0, None) == Common.DBotScore.BAD

    def test_level_low(self):
        assert koi_risk_to_dbot_score(None, "low") == Common.DBotScore.GOOD

    def test_level_medium(self):
        assert koi_risk_to_dbot_score(None, "medium") == Common.DBotScore.SUSPICIOUS

    def test_level_high(self):
        assert koi_risk_to_dbot_score(None, "high") == Common.DBotScore.BAD

    def test_level_critical(self):
        assert koi_risk_to_dbot_score(None, "critical") == Common.DBotScore.BAD

    def test_score_takes_precedence_over_level(self):
        assert koi_risk_to_dbot_score(2.0, "critical") == Common.DBotScore.GOOD

    def test_zero_score(self):
        assert koi_risk_to_dbot_score(0.0, None) == Common.DBotScore.GOOD


class TestBuildIndicatorFromItem:
    def test_basic_indicator(self):
        ind = _build_indicator_from_item(MOCK_ITEM_BASIC, [], None)
        assert ind["value"] == "Test Extension (2.1.0)"
        assert ind["type"] == INDICATOR_TYPE
        assert ind["service"] == INTEGRATION_NAME
        assert ind["score"] == Common.DBotScore.SUSPICIOUS
        assert ind["fields"]["koiitemid"] == "test-extension-id"
        assert ind["fields"]["koimarketplace"] == "chrome_web_store"
        assert ind["fields"]["koiversion"] == "2.1.0"
        assert ind["fields"]["koipublisher"] == "Test Publisher"
        assert "relationships" not in ind

    def test_version_not_duplicated(self):
        ind = _build_indicator_from_item(MOCK_ITEM_VERSION_IN_NAME, [], None)
        assert ind["value"] == "Windows Driver (04/03/2026 1.1.1.1)"
        assert "(04/03/2026 1.1.1.1) (04/03/2026 1.1.1.1)" not in ind["value"]

    def test_tags_applied(self):
        ind = _build_indicator_from_item(MOCK_ITEM_BASIC, ["Koi", "Test"], None)
        assert ind["fields"]["tags"] == ["Koi", "Test"]

    def test_tlp_color_applied(self):
        ind = _build_indicator_from_item(MOCK_ITEM_BASIC, [], "GREEN")
        assert ind["fields"]["trafficlightprotocol"] == "GREEN"

    def test_no_tags_or_tlp(self):
        ind = _build_indicator_from_item(MOCK_ITEM_BASIC, [], None)
        assert "tags" not in ind["fields"]
        assert "trafficlightprotocol" not in ind["fields"]

    def test_relationships_created(self):
        ind = _build_indicator_from_item(MOCK_ITEM_SHA1, [], None, create_relationships=True, reliability="B - Usually reliable")
        assert "relationships" in ind
        assert len(ind["relationships"]) == 1
        rel = ind["relationships"][0]
        assert rel["entityB"] == "048728125C9B67AEBAF9C9A5C48A7B74CA229A0E"
        assert rel["entityBType"] == "File"

    def test_relationships_not_created_when_disabled(self):
        ind = _build_indicator_from_item(MOCK_ITEM_SHA1, [], None, create_relationships=False)
        assert "relationships" not in ind

    def test_pending_risk_gives_none_score(self):
        ind = _build_indicator_from_item(MOCK_ITEM_SHA1, [], None)
        assert ind["score"] == Common.DBotScore.NONE
        assert ind["fields"]["dbotreputation"] == "None"

    def test_display_name_falls_back_to_item_id(self):
        item = {**MOCK_ITEM_BASIC, "item_display_name": None}
        del item["item_display_name"]
        ind = _build_indicator_from_item(item, [], None)
        assert ind["value"].startswith("test-extension-id")


class TestBuildRelationships:
    def test_sha1_item_id(self):
        rels = _build_relationships(MOCK_ITEM_SHA1, "Windows Driver Package (1.0.0)", "B - Usually reliable")
        assert len(rels) == 1
        assert rels[0]["entityBType"] == "File"
        assert rels[0]["entityB"] == "048728125C9B67AEBAF9C9A5C48A7B74CA229A0E"

    def test_sha256_item_id(self):
        sha256_item = {
            **MOCK_ITEM_BASIC,
            "item_id": "a" * 64,
        }
        rels = _build_relationships(sha256_item, "Test", "B - Usually reliable")
        assert len(rels) == 1
        assert rels[0]["entityBType"] == "File"

    def test_non_hash_item_id(self):
        rels = _build_relationships(MOCK_ITEM_BASIC, "Test", "B - Usually reliable")
        assert len(rels) == 0

    def test_cve_findings(self):
        rels = _build_relationships(MOCK_ITEM_WITH_CVES, "Vulnerable Package (1.0.0)", "B - Usually reliable")
        assert len(rels) == 2
        cve_values = [r["entityB"] for r in rels]
        assert "CVE-2024-1234" in cve_values
        assert "CVE-2024-5678" in cve_values

    def test_mixed_hash_and_cves(self):
        item = {**MOCK_ITEM_SHA1, "findings": ["CVE-2024-9999"]}
        rels = _build_relationships(item, "Driver (1.0.0)", "B - Usually reliable")
        assert len(rels) == 2
        types = {r["entityBType"] for r in rels}
        assert "File" in types
        assert "CVE" in types


class TestBuildCveIndicators:
    def test_cve_extraction(self):
        cves = _build_cve_indicators_from_item(MOCK_ITEM_WITH_CVES, ["Koi"], "WHITE")
        assert len(cves) == 2
        assert cves[0]["value"] == "CVE-2024-1234"
        assert cves[0]["type"] == FeedIndicatorType.CVE
        assert cves[0]["service"] == INTEGRATION_NAME
        assert cves[0]["fields"]["tags"] == ["Koi"]
        assert cves[0]["fields"]["trafficlightprotocol"] == "WHITE"
        assert cves[1]["value"] == "CVE-2024-5678"

    def test_no_cves(self):
        cves = _build_cve_indicators_from_item(MOCK_ITEM_BASIC, [], None)
        assert cves == []

    def test_non_list_findings(self):
        item = {**MOCK_ITEM_BASIC, "findings": "not-a-list"}
        cves = _build_cve_indicators_from_item(item, [], None)
        assert cves == []

    def test_case_insensitive_cve_detection(self):
        item = {**MOCK_ITEM_BASIC, "findings": ["cve-2024-0001"]}
        cves = _build_cve_indicators_from_item(item, [], None)
        assert len(cves) == 1
        assert cves[0]["value"] == "CVE-2024-0001"


class TestGetIndicatorsCommand:
    def test_basic_get(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = MOCK_INVENTORY_RESPONSE

        result = get_indicators_command(
            mock_client,
            {"limit": "10"},
            {"feedReliability": "B - Usually reliable", "createRelationships": "true"},
        )
        assert result.outputs is not None
        assert len(result.outputs) == 3
        assert "KOI Feed Indicators" in result.readable_output

    def test_limit_clamping(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = {"items": [MOCK_ITEM_BASIC] * 2}

        result = get_indicators_command(
            mock_client,
            {"limit": "1"},
            {"createRelationships": "false"},
        )
        assert len(result.outputs) == 1

    def test_empty_results(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = {"items": []}

        result = get_indicators_command(
            mock_client,
            {"limit": "10"},
            {"createRelationships": "false"},
        )
        assert "No indicators found" in result.readable_output
        assert result.outputs == []

    def test_min_risk_score_filter(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = MOCK_INVENTORY_RESPONSE

        result = get_indicators_command(
            mock_client,
            {"limit": "50", "min_risk_score": "7"},
            {"createRelationships": "false"},
        )
        # Items with risk=None pass through (unscored), risk=5.0 filtered out, risk=8.5 passes
        assert len(result.outputs) == 2
        risk_values = [r["fields"]["koirisk"] for r in result.outputs]
        assert 5.0 not in risk_values
        assert 8.5 in risk_values

    def test_pagination_args(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = {"items": [MOCK_ITEM_BASIC]}

        get_indicators_command(
            mock_client,
            {"limit": "10", "page": "2", "page_size": "5"},
            {"createRelationships": "false"},
        )
        mock_client.get_inventory.assert_called_with(page=2, page_size=5, marketplace=None)


class TestFetchIndicatorsCommand:
    def test_basic_fetch(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_create = mocker.patch.object(demisto, "createIndicators")
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = MOCK_INVENTORY_RESPONSE

        fetch_indicators_command(
            mock_client,
            {
                "feedReliability": "B - Usually reliable",
                "createRelationships": "true",
            },
        )
        mock_create.assert_called_once()
        indicators = mock_create.call_args[0][0]
        koi_items = [i for i in indicators if i["type"] == INDICATOR_TYPE]
        cve_items = [i for i in indicators if i["type"] == FeedIndicatorType.CVE]
        assert len(koi_items) == 3
        assert len(cve_items) == 2

    def test_marketplace_filter(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mocker.patch.object(demisto, "createIndicators")
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = {"items": [MOCK_ITEM_BASIC]}

        fetch_indicators_command(
            mock_client,
            {
                "feedMarketplaces": "npm,pypi",
                "feedReliability": "B - Usually reliable",
                "createRelationships": "false",
            },
        )
        calls = mock_client.get_inventory.call_args_list
        marketplaces_called = [c.kwargs.get("marketplace") or c[1].get("marketplace") for c in calls]
        assert "npm" in marketplaces_called
        assert "pypi" in marketplaces_called

    def test_min_risk_score_filter(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_create = mocker.patch.object(demisto, "createIndicators")
        mock_client = mocker.MagicMock()
        mock_client.get_inventory.return_value = MOCK_INVENTORY_RESPONSE

        fetch_indicators_command(
            mock_client,
            {
                "feedMinRiskScore": "6",
                "feedReliability": "B - Usually reliable",
                "createRelationships": "false",
            },
        )
        mock_create.assert_called_once()
        indicators = mock_create.call_args[0][0]
        koi_items = [i for i in indicators if i["type"] == INDICATOR_TYPE]
        # Items with risk=None pass through (unscored), risk=5.0 filtered out, risk=8.5 passes
        assert len(koi_items) == 2
        risk_values = [i["fields"]["koirisk"] for i in koi_items]
        assert 5.0 not in risk_values
        assert 8.5 in risk_values


class TestClientTestConnection:
    def test_test_connection(self, mocker):
        mocker.patch.object(demisto, "params", return_value={})
        mock_client = mocker.MagicMock(spec=Client)
        mock_client.test_connection = Client.test_connection.__get__(mock_client)
        mock_client.get_inventory.return_value = {"items": []}

        result = mock_client.test_connection()
        assert result == "ok"
        mock_client.get_inventory.assert_called_once_with(page=1, page_size=1)
