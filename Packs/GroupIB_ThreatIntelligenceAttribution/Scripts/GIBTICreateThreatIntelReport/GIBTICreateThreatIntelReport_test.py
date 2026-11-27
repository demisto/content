import pytest

import GIBTICreateThreatIntelReport as script

THREAT = {
    "id": "abc123",
    "title": "ExampleGang hits banks",
    "reportNumber": "R-1",
    "description": "Long text",
    "threatActor": {"name": "ExampleGang", "country": "RU", "isAPT": False},
    "evaluation": {"severity": "red", "tlp": "amber", "admiraltyCode": "A1"},
    "regions": ["Europe"],
    "sectors": ["Finance"],
    "indicators": {"ipv4": ["203.0.113.7"], "domain": [], "hashes_md5": ["a" * 32]},
    "forumsAccounts": {"nickname": ["examplegang"], "url": ["https://forum.example.com/examplegang"]},
    "portalLink": "https://portal.example.com/threat/abc123",
}
ACTOR = {
    "id": "ta1",
    "name": "ExampleGang",
    "threat_actor_name": "ExampleGang",
    "aliases": ["ExampleGang Group"],
    "isAPT": False,
    "malware": ["LoaderOne"],
    "reports": {"id": ["r1", "r2"], "name": ["Report one", "Report two"]},
}
MALWARE = {
    "id": "m1",
    "name": "LoaderOne",
    "malware_name": "LoaderOne",
    "aliases": ["ExampleGang loader"],
    "platform": ["Windows"],
    "threatLevel": "high",
    "shortDescription": "loader",
}
VULN = {
    "id": "CVE-2099-0001",
    "title": "example backdoor",
    "cvss": {"score": 10.0, "vector": "AV:N"},
    "epssScore": 0.9,
    "hasExploit": True,
    "description": "supply chain",
    "evaluation": {"severity": "red"},
}


def _entries(record, key="GIBTI.GIBCybercriminalThreatReport(val.id == obj.id)"):
    return [{"Type": 1, "Contents": record, "EntryContext": {key: record}}]


@pytest.mark.parametrize(
    "args, incident, expected",
    [
        ({"collection": "malware/malware"}, {}, "malware/malware"),
        ({"is_apt": "true"}, {}, "apt/threat"),
        ({}, {"type": "GIB Nation-State Cybercriminals Threat Actor"}, "apt/threat_actor"),
        ({}, {"type": "GIB OSI Vulnerability"}, "osi/vulnerability"),
    ],
)
def test_the_collection_comes_from_the_arguments_or_the_incident_type(args, incident, expected):
    assert script.resolve_collection(args, incident) == expected


def test_an_unsupported_collection_or_incident_type_is_refused():
    with pytest.raises(script.DemistoException, match="Cannot derive the collection"):
        script.resolve_collection({}, {"type": "GIB Suspicious IP TOR Node"})
    with pytest.raises(script.DemistoException, match="Unsupported collection"):
        script.resolve_collection({"collection": "ioc/common"}, {})


def test_the_gib_id_comes_from_the_argument_else_the_incident_and_is_required():
    assert script.resolve_gib_id({}, {"CustomFields": {"gibid": "x1"}}) == "x1"
    assert script.resolve_gib_id({"gib_id": "arg"}, {"CustomFields": {"gibid": "x1"}}) == "arg"
    with pytest.raises(script.DemistoException, match="gib_id"):
        script.resolve_gib_id({}, {})


def test_the_record_is_read_with_the_collection_command(mocker):
    calls = []

    def fake(command, args, extract_contents=True):
        calls.append((command, args))
        return _entries(ACTOR, "GIBTI.Nation-StateCybercriminalsThreatActorProfile(val.id == obj.id)")

    mocker.patch.object(script, "execute_command", side_effect=fake)
    assert script.fetch_record("apt/threat_actor", "ta1")["id"] == "ta1"
    assert calls == [("gibti-get-threat-actor-info", {"id": "ta1", "isAPT": "true"})]


def test_a_lookup_without_a_record_is_an_error(mocker):
    mocker.patch.object(script, "execute_command", return_value=[{"Type": 4, "Contents": "", "EntryContext": {}}])
    with pytest.raises(script.DemistoException, match="returned no record"):
        script.fetch_record("hi/threat", "missing")


def test_a_threat_report_body_shows_its_actor_indicators_and_forum_accounts():
    body = script.build_body(THREAT, "hi/threat")
    assert "| Threat actor | ExampleGang |" in body
    assert "| IP | 203.0.113.7 |" in body
    assert "| MD5 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |" in body
    assert "- examplegang (https://forum.example.com/examplegang)" in body
    assert "**Regions:** Europe" in body


def test_actor_malware_and_vulnerability_bodies_carry_their_own_rows():
    actor = script.build_body(ACTOR, "hi/threat_actor")
    assert "| Aliases | ExampleGang Group |" in actor
    assert "- Report one (r1)" in actor
    assert "**Malware:** LoaderOne" in actor
    malware = script.build_body(MALWARE, "malware/malware")
    assert "| Platforms | Windows |" in malware
    assert "## Short description" in malware
    vuln = script.build_body(VULN, "osi/vulnerability")
    assert "| CVSS | 10.0 |" in vuln
    assert "| Exploit available | True |" in vuln


@pytest.mark.parametrize(
    "record, collection, report_type, body_field, has_actor",
    [
        (THREAT, "hi/threat", "Campaign", "bodycampaign", True),
        (ACTOR, "hi/threat_actor", "Threat Actor", "bodythreatactor", True),
        (MALWARE, "malware/malware", "Malware", "bodymalware", False),
        (VULN, "osi/vulnerability", "Vulnerability", "bodyvulnerability", False),
        (THREAT, "hi/threat", "Custom", None, False),
    ],
)
def test_fields_follow_the_report_type(record, collection, report_type, body_field, has_actor):
    fields = script.build_fields(record, collection, report_type)
    assert fields["source"] == script.SOURCE_NAME
    assert ("threatactor" in fields) is has_actor
    assert [key for key in fields if key.startswith("body")] == ([body_field] if body_field else [])


def test_a_report_is_named_after_the_record_with_the_group_ib_prefix():
    assert script.report_name(THREAT, "hi/threat") == "[Group-IB] ExampleGang hits banks (R-1)"
    assert script.report_name(ACTOR, "hi/threat_actor") == "[Group-IB] ExampleGang"
    assert script.report_name(VULN, "osi/vulnerability") == "[Group-IB] CVE-2099-0001: example backdoor"


def test_the_report_id_is_read_from_the_context_or_the_contents():
    assert script.extract_report_id([{"EntryContext": {"ThreatIntelReport.Object": {"id": "42"}}}]) == "42"
    assert script.extract_report_id([{"Contents": {"id": "7"}}]) == "7"
    assert script.extract_report_id([{"Contents": ""}]) is None


def test_a_dry_run_creates_nothing(mocker):
    calls = []
    mocker.patch.object(
        script,
        "execute_command",
        side_effect=lambda c, a, extract_contents=True: calls.append(c) or _entries(THREAT),
    )
    result = script.create_report("hi/threat", "abc123", None, dry_run=True)
    assert calls == ["gibti-get-threat-info"]
    assert result.outputs["created"] is False
    assert result.outputs["type"] == "Campaign"
    assert result.outputs["payload"]["name"] == "[Group-IB] ExampleGang hits banks (R-1)"


def test_a_report_is_created_then_filled_with_the_type_of_its_collection(mocker):
    calls = []

    def fake(command, args, extract_contents=True):
        calls.append((command, args))
        if command == "gibti-get-osi-vulnerability-info":
            return _entries(VULN, "GIBTI.OSIVulnerability(val.id == obj.id)")
        if command == script.CREATE_COMMAND:
            return [{"EntryContext": {"ThreatIntelReport.Object": {"id": "99"}}}]
        return [{"Contents": "ok"}]

    mocker.patch.object(script, "execute_command", side_effect=fake)
    result = script.create_report("osi/vulnerability", "CVE-2099-0001", None, dry_run=False)
    assert [c for c, _ in calls] == ["gibti-get-osi-vulnerability-info", script.CREATE_COMMAND, script.SET_COMMAND]
    assert calls[1][1] == {"name": "[Group-IB] CVE-2099-0001: example backdoor", "type": "Vulnerability"}
    assert calls[2][1]["id"] == "99"
    assert "bodyvulnerability" in calls[2][1]
    assert "threatactor" not in calls[2][1]
    assert result.outputs["id"] == "99"
    assert result.outputs["collection"] == "osi/vulnerability"


def test_main_runs_inside_an_incident_without_arguments(mocker):
    mocker.patch.object(script.demisto, "args", return_value={})
    mocker.patch.object(script.demisto, "incident", return_value={"type": "GIB Malware", "CustomFields": {"gibid": "m1"}})
    create = mocker.patch.object(script, "create_report", return_value="ok")
    mocker.patch.object(script, "return_results")
    script.main()
    assert create.call_args.args == ("malware/malware", "m1", None, False, None)


def test_the_record_is_read_on_the_fetching_instance_else_on_every_instance_when_several_are_active(mocker):
    modules = {
        "gib-a": {"brand": "Group-IB Threat Intelligence & Attribution", "state": "active"},
        "gib-b": {"brand": "Group-IB Threat Intelligence & Attribution", "state": "active"},
    }
    mocker.patch.object(script.demisto, "getModules", return_value=modules)
    assert script.resolve_instance({}, {"sourceInstance": "gib-b"}) == "gib-b"
    assert script.resolve_instance({}, {}) is None
    calls = []

    def fake(command, args, extract_contents=True):
        calls.append((command, args))
        return _entries(ACTOR, "GIBTI.Nation-StateCybercriminalsThreatActorProfile(val.id == obj.id)")

    mocker.patch.object(script, "execute_command", side_effect=fake)
    script.fetch_record("apt/threat_actor", "ta1", "gib-b")
    assert calls == [("gibti-get-threat-actor-info", {"id": "ta1", "isAPT": "true", "using": "gib-b"})]


@pytest.mark.parametrize("key", ["description", "shortDescription", "extDescription"])
def test_a_description_reaches_the_body_as_the_lookup_returns_it(key):
    """The lookup returns a narrative as text, its tags already removed and its entities decoded once; each of its
    lines is a paragraph of the Markdown body, which would join consecutive lines into one."""
    first = "Payload uses #include <stdio.h> and mails <ops@example.com>; R&D &lt;b&gt; note"
    body = script.build_body({**MALWARE, key: f"{first}\nSecond para\n\n  Third para "}, "malware/malware")
    assert f"\n\n{first}\n\nSecond para\n\nThird para\n" in f"{body}\n"


def test_the_indicators_table_restores_defanged_values_skips_placeholders_and_keeps_one_hash_per_file():
    """A report's indicators block holds one element per entry in each column: a list of IPs for a network entry,
    hashes and nothing else for a file entry."""
    record = {
        **THREAT,
        "indicators": {
            "ipv4": [["203.0.113.7", "203.0.113.8"], None, None, ["203.0.113.7"]],
            "domain": ["evil[.]example[.]com", None, None, None],
            "url": [["hxxps://evil[.]example[.]com/gate", "https://x.example.com/{machineId}/a"], None, None, None],
            "hashes_md5": [None, "a" * 32, "c" * 32, None],
            "hashes_sha1": [None, "b" * 40, "", None],
            "hashes_sha256": [None, "", "", None],
        },
    }
    body = script.build_body(record, "hi/threat")
    table = body.split("## Indicators", 1)[1].split("\n\n## ", 1)[0]
    assert [line for line in table.splitlines() if line.startswith("| ") and line.split()[1] not in ("Type", "---")] == [
        "| IP | 203.0.113.7 |",
        "| IP | 203.0.113.8 |",
        "| Domain | evil.example.com |",
        "| URL | https://evil.example.com/gate |",
        f"| SHA1 | {'b' * 40} |",
        f"| MD5 | {'c' * 32} |",
    ]
    assert "['" not in table
