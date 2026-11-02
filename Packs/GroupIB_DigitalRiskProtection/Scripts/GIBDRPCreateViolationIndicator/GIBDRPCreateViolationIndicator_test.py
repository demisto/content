import pytest

import GIBDRPCreateViolationIndicator as script


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("https://bad.example/login", ("URL", "https://bad.example/login")),
        ("http://bad.example/login?x=1", ("URL", "http://bad.example/login?x=1")),
        # DRP writes most URIs without a scheme; the fetch strips the leading `//` but not always.
        ("//bad.example/login", ("URL", "https://bad.example/login")),
        ("bad.example/login", ("URL", "https://bad.example/login")),
        ("bad.example", ("Domain", "bad.example")),
        ("Sub.Bad.Example.", ("Domain", "sub.bad.example")),
        ("203.0.113.7", ("IP", "203.0.113.7")),
    ],
)
def test_http_urls_domains_and_ipv4_addresses_become_indicators(uri, expected):
    assert script.classify(uri) == expected


@pytest.mark.parametrize(
    "uri",
    [
        "mail://spam@example.com",
        "tg://resolve?domain=acme_support",
        "android-app://com.acme.fake",
        "ftp://files.example/x",
        "seller-42",
        "@acme_support",
        "999.1.1.1",
        "",
        "   ",
    ],
)
def test_anything_else_is_not_an_indicator(uri):
    """The fetch used to publish these as URL indicators (`mail://...`), which is junk in the threat intel."""
    assert script.classify(uri) is None


@pytest.mark.parametrize(
    "violation_type,reputation",
    [
        ("Phishing", "Bad"),
        ("scam", "Bad"),
        ("Trademark", "Suspicious"),
        ("No violation", "Good"),
        ("Something new", "Suspicious"),
        (None, "Suspicious"),
    ],
)
def test_reputation_follows_the_violation_type(violation_type, reputation):
    assert script.reputation_for(violation_type) == reputation


INCIDENT = {
    "id": "302",
    "CustomFields": {
        "gibdrpid": "v-1",
        "gibdrpviolationuri": "//acme-login.example/verify",
        "gibdrptype": "Phishing",
        "gibdrpbrand": "Acme",
        "gibdrptitle": "Phishing page impersonating Acme",
        "gibdrpfirstdetected": "2026-09-10T10:00:00+00:00",
        "gibdrpcurrentstatusdate": "2026-09-15T10:00:00+00:00",
    },
}


def test_the_indicator_is_linked_to_the_incident_and_carries_its_source_and_dates():
    arguments = script.indicator_arguments(INCIDENT, "https://acme-login.example/verify", "URL")
    assert arguments == {
        "value": "https://acme-login.example/verify",
        "type": "URL",
        "source": "Group-IB Digital Risk Protection",
        "reputation": "Bad",
        "relatedIncidents": "302",
        "tags": "Group-IB DRP,Phishing,Acme",
        "description": "Phishing page impersonating Acme",
        "firstseenbysource": "2026-09-10T10:00:00+00:00",
        "lastseenbysource": "2026-09-15T10:00:00+00:00",
    }


def _run(mocker, incident, args=None):
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    mocker.patch.object(script.demisto, "args", return_value=args or {})
    mocker.patch.object(script, "is_error", return_value=False)
    executed = mocker.patch.object(script.demisto, "executeCommand", return_value=[{"Type": 1, "Contents": "ok"}])
    results = mocker.patch.object(script, "return_results")
    script.main()
    return executed, results.call_args.args[0]


def test_main_creates_the_indicator_from_the_incident(mocker):
    executed, result = _run(mocker, INCIDENT)

    assert executed.call_args.args[0] == "createNewIndicator"
    assert executed.call_args.args[1]["value"] == "https://acme-login.example/verify"
    assert executed.call_args.args[1]["relatedIncidents"] == "302"
    assert result.outputs == {
        "uri": "//acme-login.example/verify",
        "created": True,
        "value": "https://acme-login.example/verify",
        "type": "URL",
        "verdict": "Malicious",
    }
    assert result.ignore_auto_extract is True


def test_main_skips_a_uri_that_is_not_an_indicator_without_failing(mocker):
    incident = {"id": "303", "CustomFields": {"gibdrpviolationuri": "mail://spam@example.com", "gibdrptype": "Scam"}}
    executed, result = _run(mocker, incident)

    executed.assert_not_called()
    assert result.outputs == {"uri": "mail://spam@example.com", "created": False}
    assert "No indicator was created" in result.readable_output


def test_an_explicit_value_wins_over_the_incident(mocker):
    executed, result = _run(mocker, INCIDENT, {"value": "bad.example"})
    assert executed.call_args.args[1]["type"] == "Domain"
    assert result.outputs["value"] == "bad.example"


def test_a_failed_creation_is_an_error(mocker):
    mocker.patch.object(script.demisto, "incident", return_value=INCIDENT)
    mocker.patch.object(script.demisto, "args", return_value={})
    mocker.patch.object(script.demisto, "executeCommand", return_value=[{"Type": 4, "Contents": "boom"}])
    mocker.patch.object(script, "is_error", return_value=True)
    mocker.patch.object(script, "get_error", return_value="boom")
    error = mocker.patch.object(script, "return_error")

    script.main()

    assert "boom" in error.call_args.args[0]


def test_no_uri_anywhere_is_an_error(mocker):
    mocker.patch.object(script.demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(script.demisto, "args", return_value={})
    error = mocker.patch.object(script, "return_error")

    script.main()

    assert "No violation URI" in error.call_args.args[0]
