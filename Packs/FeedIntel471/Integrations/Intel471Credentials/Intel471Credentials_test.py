import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def _sample_credential() -> dict:
    return {
        "id": "cred--00000000-0000-0000-0000-000000000001",
        "last_updated_ts": "2026-06-20T10:00:00Z",
        "activity": {
            "first_seen_ts": "2026-06-01T00:00:00Z",
            "last_seen_ts": "2026-06-20T00:00:00Z",
        },
        "data": {
            "credential_login": "victim@example.com",
            "credential_domain": "example.com",
            "detection_domain": "example.com",
            "affiliations": ["my_employees"],
            "info_stealer": {
                "antivirus_software": ["Defender"],
                "computer_username": ["jdoe"],
                "infection_ts": ["2026-06-19T12:00:00Z"],
                "ip": ["1.2.3.4", "5.6.7.8"],
                "isp": ["ExampleISP"],
                "machine_id": ["m-1"],
                "malware_family": ["lumma"],
                "malware_install_path": ["C:/Users/jdoe/AppData/Roaming"],
                "os": ["Windows 11"],
                "pc_name": ["DESKTOP-XYZ"],
                "screenshot_path": ["screens/abc.png"],
                "version": ["1.2.3"],
            },
            "password": {"strength": "weak"},
        },
    }


def test_build_indicator_email():
    from Intel471Credentials import build_indicator

    indicator = build_indicator(_sample_credential())

    assert indicator["value"] == "victim@example.com"
    assert indicator["type"] == "Email"
    assert "lumma" in indicator["fields"]["tags"]
    assert "my_employees" in indicator["fields"]["tags"]


def test_build_indicator_account_when_no_at_sign():
    from Intel471Credentials import build_indicator

    cred = _sample_credential()
    cred["data"]["credential_login"] = "johndoe"
    indicator = build_indicator(cred)

    assert indicator["type"] == "Account"


def test_build_indicator_returns_empty_when_no_login():
    from Intel471Credentials import build_indicator

    cred = _sample_credential()
    cred["data"]["credential_login"] = ""

    assert build_indicator(cred) == {}


def test_build_incident_name_includes_login_and_domain():
    from Intel471Credentials import build_incident

    incident = build_incident(_sample_credential())

    assert "victim@example.com" in incident["name"]
    assert "example.com" in incident["name"]
    assert incident["occurred"] == "2026-06-20T10:00:00Z"
    payload = json.loads(incident["rawJSON"])
    assert payload["id"] == "cred--00000000-0000-0000-0000-000000000001"


def test_build_incident_includes_info_stealer_labels():
    from Intel471Credentials import build_incident

    incident = build_incident(_sample_credential())
    labels = {label["type"]: label["value"] for label in incident.get("labels", [])}

    assert labels["info_stealer.malware_family"] == "lumma"
    assert labels["info_stealer.ip"] == "1.2.3.4, 5.6.7.8"
    assert labels["info_stealer.os"] == "Windows 11"
    assert labels["info_stealer.pc_name"] == "DESKTOP-XYZ"
    assert labels["info_stealer.version"] == "1.2.3"


def test_build_incident_omits_info_stealer_when_empty():
    from Intel471Credentials import build_incident

    cred = _sample_credential()
    cred["data"]["info_stealer"] = {}
    incident = build_incident(cred)

    assert "labels" not in incident


def test_fetch_credentials_paginates_until_cursor_exhausted(mocker, requests_mock):
    from Intel471Credentials import Client, FEED_URL_CREDENTIALS

    requests_mock.get(
        FEED_URL_CREDENTIALS,
        [
            {"json": {"credentials": [_sample_credential()], "cursor_next": "abc"}},
            {"json": {"credentials": [_sample_credential()], "cursor_next": ""}},
        ],
    )

    mocker.patch("Intel471Credentials.handle_proxy", return_value={})
    client = Client(auth=("u", "p"), fetch_time="1 day")
    creds, next_cursor = client.fetch_credentials("0", "", limit=10)

    assert len(creds) == 2
    assert next_cursor == "abc"


def test_fetch_indicators_command_links_indicator_to_incident(monkeypatch):
    import demistomock as demisto

    import Intel471Credentials

    monkeypatch.setattr(Intel471Credentials, "handle_proxy", lambda **_: {})
    monkeypatch.setattr(demisto, "getLastRun", dict)

    client = Intel471Credentials.Client(auth=("u", "p"), fetch_time="1 day")
    monkeypatch.setattr(client, "fetch_credentials", lambda *a, **kw: ([_sample_credential()], "next-cursor"))

    indicators, incidents, next_run = Intel471Credentials.fetch_indicators_command(client, max_items=10)

    assert len(indicators) == 1
    assert len(incidents) == 1
    # Indicator-to-incident association is set up inside the loop.
    assert indicators[0]["relatedIncidents"] == [incidents[0]["name"]]
    assert next_run["cursor"] == "next-cursor"
