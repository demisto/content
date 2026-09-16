"""Tests for the Darkmon Feed integration (feed half of the Darkmon pack)."""

import importlib
import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

src = importlib.import_module("DarkmonFeed")


def _client() -> "src.Client":
    return src.Client(
        base_url="https://example.test/tip/x",
        headers={"X-API-KEY": "k"},
        verify=False,
        proxy=False,
    )


# ---- Client construction ----


def test_client_constructs():
    c = _client()
    assert c is not None


# ---- Indicator field mapping ----


def test_apply_indicator_fields_full():
    obj = {"fields": {}}
    item = {
        "classification": "malware",
        "compromise_sources": ["redline", "lumma"],
        "first_compromise": "2026-01-01T00:00:00Z",
        "last_compromise": "2026-06-01T00:00:00Z",
        "stealers": ["redline"],
    }
    src._apply_indicator_fields(item, "Email", obj)
    f = obj["fields"]
    assert f["darkmonclassification"] == "malware"
    assert f["darkmoncompromisesources"] == ["redline", "lumma"]
    assert f["darkmonfirstcompromise"] == "2026-01-01T00:00:00Z"
    assert f["darkmonlastcompromise"] == "2026-06-01T00:00:00Z"
    assert f["darkmonstealers"] == ["redline"]


def test_apply_indicator_fields_partial():
    obj = {"fields": {}}
    src._apply_indicator_fields({"classification": "phishing"}, "URL", obj)
    assert obj["fields"] == {"darkmonclassification": "phishing"}


# ---- fetch_indicators_command ----


def test_fetch_indicators_command_maps_types(monkeypatch):
    c = _client()
    monkeypatch.setattr(
        c,
        "get_indicators",
        lambda size=20: {
            "iocObjects": [
                {"type": "IP", "value": "8.8.8.8", "classification": "scanner"},
                {"type": "Domain", "value": "evil.test", "classification": "phishing"},
                {
                    "type": "URL",
                    "value": "https://evil.test",
                    "classification": "phishing",
                },
            ]
        },
    )
    indicators = src.fetch_indicators_command(c, {"limit": 3, "feedTags": "darkmon"})
    assert len(indicators) == 3
    assert {i["type"] for i in indicators} == {
        src.FeedIndicatorType.IP,
        src.FeedIndicatorType.Domain,
        src.FeedIndicatorType.URL,
    }
    assert all(i["service"] == "Darkmon" for i in indicators)
    assert all("darkmon" in i["fields"].get("tags", []) for i in indicators)


def test_fetch_indicators_command_skips_empty(monkeypatch):
    c = _client()
    monkeypatch.setattr(
        c,
        "get_indicators",
        lambda size=20: {
            "iocObjects": [
                {"type": "IP", "value": ""},  # skipped
                {"type": "IP", "value": "1.1.1.1"},
            ]
        },
    )
    indicators = src.fetch_indicators_command(c, {"limit": 2})
    assert len(indicators) == 1
    assert indicators[0]["value"] == "1.1.1.1"


def test_fetch_indicators_command_tlp(monkeypatch):
    c = _client()
    monkeypatch.setattr(
        c,
        "get_indicators",
        lambda size=20: {"iocObjects": [{"type": "IP", "value": "1.1.1.1"}]},
    )
    indicators = src.fetch_indicators_command(c, {"limit": 1, "tlp_color": "AMBER"})
    assert indicators[0]["fields"]["trafficlightprotocol"] == "AMBER"


# ---- darkmon-get-indicators ----


def test_darkmon_get_indicators_command(monkeypatch):
    c = _client()
    monkeypatch.setattr(
        c,
        "get_indicators",
        lambda size=20: {"iocObjects": [{"type": "IP", "value": "1.1.1.1", "classification": "scanner"}]},
    )
    result = src.darkmon_get_indicators_command(c, {"limit": "1"})
    assert result.outputs_prefix == "Darkmon.Indicator"
    assert result.outputs_key_field == "value"
    assert result.outputs[0]["value"] == "1.1.1.1"
