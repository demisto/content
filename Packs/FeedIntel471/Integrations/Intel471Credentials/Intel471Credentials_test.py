import json


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


""" INCIDENT BUILDING """


def test_build_incident_name_includes_login_and_domain():
    from Intel471Credentials import build_incident

    incident = build_incident(_sample_credential())

    assert "victim@example.com" in incident["name"]
    assert incident["type"] == "Intel471 Leaked Credential"
    assert incident["occurred"] == "2026-06-20T10:00:00Z"
    payload = json.loads(incident["rawJSON"])
    assert payload["id"] == "cred--00000000-0000-0000-0000-000000000001"


def test_build_incident_honors_configured_incident_type():
    from Intel471Credentials import build_incident

    assert build_incident(_sample_credential(), "Custom Type")["type"] == "Custom Type"


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

    assert "labels" not in build_incident(cred)


""" INDICATOR EXTRACTION """


def test_extract_indicators_covers_every_observable():
    from Intel471Credentials import extract_indicators

    indicators = extract_indicators(_sample_credential())
    by_value = {i["value"]: i["type"] for i in indicators}

    assert by_value == {
        "victim@example.com": "Email",
        # detection_domain and credential_domain are identical here, so the domain is extracted once.
        "example.com": "Domain",
        "1.2.3.4": "IP",
        "5.6.7.8": "IP",
        "DESKTOP-XYZ": "Host",
    }


def test_extract_indicators_login_is_first_and_carries_info_stealer_fields():
    from Intel471Credentials import extract_indicators

    indicators = extract_indicators(_sample_credential())
    login, rest = indicators[0], indicators[1:]

    assert login["value"] == "victim@example.com"
    # infection_ts uses the CLI_NAME_OVERRIDES mapping and is kept as a single ISO string.
    assert login["fields"]["intel471infostealerinfectiontimestamp"] == "2026-06-19T12:00:00Z"
    # Multi-value fields are comma-joined.
    assert login["fields"]["intel471infostealerip"] == "1.2.3.4, 5.6.7.8"
    # Single-value fields come through unchanged.
    assert login["fields"]["intel471infostealerantivirussoftware"] == "Defender"
    assert login["fields"]["intel471infostealercomputerusername"] == "jdoe"
    assert login["fields"]["intel471infostealerisp"] == "ExampleISP"
    assert login["fields"]["intel471infostealermachineid"] == "m-1"
    assert login["fields"]["intel471infostealermalwarefamily"] == "lumma"
    assert login["fields"]["intel471infostealermalwareinstallpath"] == "C:/Users/jdoe/AppData/Roaming"
    assert login["fields"]["intel471infostealeros"] == "Windows 11"
    assert login["fields"]["intel471infostealerpcname"] == "DESKTOP-XYZ"
    assert login["fields"]["intel471infostealerscreenshotpath"] == "screens/abc.png"
    assert login["fields"]["intel471infostealerversion"] == "1.2.3"
    # The host's own observables don't repeat the info stealer detail.
    for indicator in rest:
        assert not any(key.startswith("intel471infostealer") for key in indicator["fields"])


def test_extract_indicators_account_when_no_at_sign():
    from Intel471Credentials import extract_indicators

    cred = _sample_credential()
    cred["data"]["credential_login"] = "johndoe"

    assert extract_indicators(cred)[0]["type"] == "Account"


def test_extract_indicators_still_extracts_host_data_without_a_login():
    from Intel471Credentials import extract_indicators

    cred = _sample_credential()
    cred["data"]["credential_login"] = ""
    values = {i["value"] for i in extract_indicators(cred)}

    assert values == {"example.com", "1.2.3.4", "5.6.7.8", "DESKTOP-XYZ"}


def test_extract_indicators_returns_empty_without_any_observable():
    from Intel471Credentials import extract_indicators

    cred = {"data": {}, "activity": {}}

    assert extract_indicators(cred) == []


def test_extract_indicators_distinguishes_detection_and_credential_domains():
    from Intel471Credentials import extract_indicators

    cred = _sample_credential()
    cred["data"]["credential_domain"] = "other.example.org"
    domains = [i["value"] for i in extract_indicators(cred) if i["type"] == "Domain"]

    assert domains == ["example.com", "other.example.org"]


def test_extract_indicators_skips_malformed_observables():
    from Intel471Credentials import extract_indicators

    cred = _sample_credential()
    cred["data"]["detection_domain"] = "not a domain"
    cred["data"]["credential_domain"] = ""
    cred["data"]["info_stealer"]["ip"] = ["1.2.3.4", "999.999.999.999", ""]
    values = {i["value"] for i in extract_indicators(cred)}

    assert values == {"victim@example.com", "1.2.3.4", "DESKTOP-XYZ"}


def test_extract_indicators_types_ipv6():
    from Intel471Credentials import extract_indicators

    cred = _sample_credential()
    cred["data"]["info_stealer"]["ip"] = ["2001:db8::1"]
    by_value = {i["value"]: i["type"] for i in extract_indicators(cred)}

    assert by_value["2001:db8::1"] == "IPv6"


def test_extract_indicators_applies_tags_tlp_and_reputation():
    from Intel471Credentials import extract_indicators

    indicators = extract_indicators(_sample_credential(), ["intel471"], "RED", "Bad")

    for indicator in indicators:
        assert indicator["fields"]["tags"] == ["lumma", "my_employees", "intel471"]
        assert indicator["fields"]["trafficlightprotocol"] == "RED"
        assert indicator["score"] == 3


def test_extract_indicators_tags_are_not_shared_between_indicators():
    from Intel471Credentials import extract_indicators

    indicators = extract_indicators(_sample_credential())
    indicators[0]["fields"]["tags"].append("mutated")

    assert "mutated" not in indicators[1]["fields"]["tags"]


""" ASSOCIATION """


def test_associate_indicators_to_incident_prefers_the_incident_id():
    from Intel471Credentials import associate_indicators_to_incident, extract_indicators

    indicators = extract_indicators(_sample_credential())
    associate_indicators_to_incident(indicators, "42", "Intel471 Leaked Credential: victim@example.com")

    assert all(i["relatedIncidents"] == ["42"] for i in indicators)


def test_associate_indicators_to_incident_falls_back_to_the_incident_name():
    from Intel471Credentials import associate_indicators_to_incident, extract_indicators

    indicators = extract_indicators(_sample_credential())
    associate_indicators_to_incident(indicators, "", "Intel471 Leaked Credential: victim@example.com")

    assert all(i["relatedIncidents"] == ["Intel471 Leaked Credential: victim@example.com"] for i in indicators)


def test_created_incident_ids_matches_by_name():
    from Intel471Credentials import created_incident_ids

    incidents = [{"name": "a"}, {"name": "b"}]
    created = [{"name": "b", "id": "20"}, {"name": "a", "id": "10"}]

    assert created_incident_ids(created, incidents) == ["10", "20"]


def test_created_incident_ids_falls_back_to_submission_order():
    from Intel471Credentials import created_incident_ids

    incidents = [{"name": "a"}, {"name": "b"}]
    created = [{"id": "10"}, {"id": "20"}]

    assert created_incident_ids(created, incidents) == ["10", "20"]


def test_created_incident_ids_handles_a_server_that_returns_nothing():
    from Intel471Credentials import created_incident_ids

    assert created_incident_ids(None, [{"name": "a"}, {"name": "b"}]) == ["", ""]


def test_created_incident_ids_handles_a_single_object():
    from Intel471Credentials import created_incident_ids

    assert created_incident_ids({"name": "a", "id": "10"}, [{"name": "a"}]) == ["10"]


""" COMMANDS """


def test_fetch_credentials_paginates_until_cursor_exhausted(mocker, requests_mock):
    from Intel471Credentials import FEED_URL_CREDENTIALS, Client

    requests_mock.get(
        FEED_URL_CREDENTIALS,
        [
            {"json": {"credentials": [_sample_credential()], "cursor_next": "abc"}},
            {"json": {"credentials": [_sample_credential()], "cursor_next": ""}},
        ],
    )

    mocker.patch("Intel471Credentials.handle_proxy", return_value={})
    client = Client(auth=("u", "p"), first_fetch="1 day")
    creds, next_cursor = client.fetch_credentials("0", "", limit=10)

    assert len(creds) == 2
    assert next_cursor == "abc"


def test_fetch_incidents_command_pairs_incidents_with_their_credentials(monkeypatch):
    import Intel471Credentials

    monkeypatch.setattr(Intel471Credentials, "handle_proxy", lambda **_: {})

    client = Intel471Credentials.Client(auth=("u", "p"), first_fetch="1 day")
    monkeypatch.setattr(client, "fetch_credentials", lambda *a, **kw: ([_sample_credential()], "next-cursor"))

    incidents, credentials, next_run = Intel471Credentials.fetch_incidents_command(client, 10, {})

    assert len(incidents) == 1
    assert credentials[0]["id"] == "cred--00000000-0000-0000-0000-000000000001"
    assert next_run["cursor"] == "next-cursor"
    assert next_run["from_ts"]


def test_fetch_incidents_command_keeps_the_existing_watermark(monkeypatch):
    import Intel471Credentials

    monkeypatch.setattr(Intel471Credentials, "handle_proxy", lambda **_: {})

    client = Intel471Credentials.Client(auth=("u", "p"), first_fetch="1 day")
    monkeypatch.setattr(client, "fetch_credentials", lambda *a, **kw: ([], ""))

    _incidents, _credentials, next_run = Intel471Credentials.fetch_incidents_command(
        client, 10, {"cursor": "saved-cursor", "from_ts": "1750000000000"}
    )

    assert next_run == {"cursor": "saved-cursor", "from_ts": "1750000000000"}


def test_create_incidents_with_indicators_associates_every_indicator(mocker):
    import demistomock as demisto

    from Intel471Credentials import build_incident, create_incidents_with_indicators

    credential = _sample_credential()
    incident = build_incident(credential)

    mocker.patch.object(demisto, "createIncidents", return_value=[{"name": incident["name"], "id": "77"}])
    create_indicators = mocker.patch.object(demisto, "createIndicators")

    incident_count, indicator_count = create_incidents_with_indicators([incident], [credential])

    assert (incident_count, indicator_count) == (1, 5)
    created = create_indicators.call_args[0][0]
    assert all(i["relatedIncidents"] == ["77"] for i in created)


def test_create_incidents_with_indicators_is_a_no_op_when_nothing_was_fetched(mocker):
    import demistomock as demisto

    from Intel471Credentials import create_incidents_with_indicators

    create_incidents = mocker.patch.object(demisto, "createIncidents")
    create_indicators = mocker.patch.object(demisto, "createIndicators")

    assert create_incidents_with_indicators([], []) == (0, 0)
    create_incidents.assert_not_called()
    create_indicators.assert_not_called()


def test_get_indicators_command_reports_the_incident_each_indicator_belongs_to(monkeypatch):
    import Intel471Credentials

    monkeypatch.setattr(Intel471Credentials, "handle_proxy", lambda **_: {})

    client = Intel471Credentials.Client(auth=("u", "p"), first_fetch="1 day")
    monkeypatch.setattr(client, "fetch_credentials", lambda *a, **kw: ([_sample_credential()], ""))

    results = Intel471Credentials.get_indicators_command(client, {"limit": "10"})

    assert len(results.outputs) == 5
    assert "Intel471 Leaked Credential: victim@example.com @ example.com" in results.readable_output


def test_test_module(monkeypatch):
    import Intel471Credentials

    monkeypatch.setattr(Intel471Credentials, "handle_proxy", lambda **_: {})

    client = Intel471Credentials.Client(auth=("u", "p"), first_fetch="1 day")
    monkeypatch.setattr(client, "fetch_credentials", lambda *a, **kw: ([], ""))

    assert Intel471Credentials.test_module(client) == "ok"
