import pytest
import demistomock as demisto
from CommonServerPython import CommandResults, Common, DBotScoreType, DemistoException, EntityRelationship
import GIBTIEnrichIncidentIndicators as script


def _dbot(value, type_, score=3):
    return {"Indicator": value, "Type": type_, "Vendor": "GroupIBTI", "Score": score}


def _indicator_entry(value, type_, relationships=None, contents="x"):
    entry = {
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": contents,
        "HumanReadable": f"### {type_} indicator\n| value |\n| {value} |",
        "EntryContext": {
            "DBotScore(val.Indicator && val.Indicator == obj.Indicator)": [_dbot(value, type_)],
            "IP(val.Address && val.Address == obj.Address)": {"Address": value},
        },
    }
    if relationships is not None:
        entry["Relationships"] = relationships
    return entry


RECORD_ENTRY = {
    "Type": 1,
    "ContentsFormat": "json",
    "Contents": {"id": "rec"},
    "HumanReadable": "### Feed",
    "EntryContext": {"GIBTI.MalwareCNC(val.id == obj.id)": {"id": "rec"}},
    "IgnoreAutoExtract": True,
}
INCIDENT = {
    "type": "GIB Malware CNC",
    "CustomFields": {
        "gibid": "rec",
        "gibmalwarename": "BotTwo, BankerFive",
        "gibthreatactorname": "ExampleCrew",
        "gibthreatactorid": "examplecrew-id",
        "gibthreatactorisapt": False,
    },
}


@pytest.fixture
def commands(mocker):
    calls = []

    def fake(command, args=None, extract_contents=True, fail_on_error=True):
        calls.append((command, args))
        if command == "createNewIndicator":
            if args["value"] == "Broken":
                raise DemistoException("no such type")
            return [{"Type": 1, "Contents": {"id": "obj"}}]
        rel = [
            {
                "name": "indicator-of",
                "entityA": "203.0.113.5",
                "entityAType": "IP",
                "entityB": "BotTwo",
                "entityBType": "Malware",
            },
            {
                "name": "related-to",
                "entityA": "203.0.113.5",
                "entityAType": "IP",
                "entityB": "ExampleCrew",
                "entityBType": "Threat Actor",
            },
        ]
        return [RECORD_ENTRY, _indicator_entry("203.0.113.5", "ip", rel), _indicator_entry("cnc.test", "domain", rel)]

    mocker.patch.object(script, "execute_command", side_effect=fake)
    return calls


def test_enrich_reissues_the_indicator_entries_and_creates_the_indicators_and_the_objects(commands):
    results = script.enrich("malware/cnc", "rec", True, INCIDENT)
    assert commands[0] == ("gibti-get-malware-cnc-info", {"id": "rec"})
    assert commands[1:3] == [
        (
            "createNewIndicator",
            {
                "value": "203.0.113.5",
                "type": "IP",
                "verdict": "Malicious",
                "source": "Group-IB Threat Intelligence & Attribution",
                "gibcollection": "malware/cnc",
            },
        ),
        (
            "createNewIndicator",
            {
                "value": "cnc.test",
                "type": "Domain",
                "verdict": "Malicious",
                "source": "Group-IB Threat Intelligence & Attribution",
                "gibcollection": "malware/cnc",
            },
        ),
    ]
    assert commands[3:] == [
        (
            "createNewIndicator",
            {"value": "BotTwo", "type": "Malware", "verdict": "Malicious", "tags": "malware/cnc", "gibcollection": "malware/cnc"},
        ),
        (
            "createNewIndicator",
            {
                "value": "ExampleCrew",
                "type": "Threat Actor",
                "verdict": "Malicious",
                "tags": "malware/cnc",
                "gibcollection": "malware/cnc",
                "gibthreatactorid": "examplecrew-id",
                "gibthreatactorisapt": "false",
            },
        ),
    ]
    reissued = [r for r in results if isinstance(r, dict)]
    assert [r["HumanReadable"].split("\n")[0] for r in reissued] == ["### ip indicator", "### domain indicator"]
    assert all("IgnoreAutoExtract" not in r and r["Relationships"] for r in reissued)
    summary = results[-1]
    assert isinstance(summary, CommandResults)
    assert summary.relationships is None  # the command's entries already carry them
    assert summary.outputs["indicators"] == [{"value": "203.0.113.5", "type": "IP"}, {"value": "cnc.test", "type": "Domain"}]
    assert summary.outputs["objectsCreated"] == [
        {"type": "Malware", "name": "BotTwo"},
        {"type": "Threat Actor", "name": "ExampleCrew"},
    ]
    assert "2 indicator(s) enriched, 2 Malware / Threat Actor object(s) created or updated" in summary.readable_output
    assert all(r["Contents"] == "x" and r["ContentsFormat"] == "json" for r in reissued)


def test_an_entry_without_contents_is_reissued_as_a_markdown_note():
    entry = _indicator_entry("203.0.113.5", "ip", contents=None)
    reissued = script.reissue(entry)
    assert reissued["Contents"] == reissued["HumanReadable"] == entry["HumanReadable"]
    assert reissued["ContentsFormat"] == "markdown"
    assert reissued["Type"] == 1
    assert "Relationships" not in reissued


def test_relationships_are_built_from_the_incident_when_the_entries_have_none(mocker):
    entries = [RECORD_ENTRY, _indicator_entry("203.0.113.5", "ip")]
    mocker.patch.object(script, "execute_command", return_value=entries)
    results = script.enrich("malware/cnc", "rec", False, INCIDENT)
    summary = results[-1]
    assert [(r._entity_a, r._name, r._entity_b, r._entity_b_type) for r in summary.relationships] == [
        ("203.0.113.5", "indicator-of", "BotTwo", "Malware"),
        ("203.0.113.5", "indicator-of", "BankerFive", "Malware"),
        ("203.0.113.5", "related-to", "ExampleCrew", "Threat Actor"),
    ]
    assert isinstance(summary.relationships[0], EntityRelationship)
    assert summary.outputs["objectsCreated"] == []
    assert summary.outputs["objects"] == [
        {"type": "Malware", "name": "BotTwo"},
        {"type": "Malware", "name": "BankerFive"},
        {"type": "Threat Actor", "name": "ExampleCrew"},
    ]


def test_a_failed_object_is_reported_not_raised(mocker):
    rel = [
        {"name": "indicator-of", "entityB": "Broken", "entityBType": "Malware"},
        {"name": "related-to", "entityB": "ExampleCrew", "entityBType": "Threat Actor"},
    ]
    entries = [_indicator_entry("203.0.113.5", "ip", rel)]

    def fake(command, args=None, extract_contents=True, fail_on_error=True):
        if command == "createNewIndicator" and args["value"] == "Broken":
            raise DemistoException("no such type")
        return entries if command != "createNewIndicator" else []

    mocker.patch.object(script, "execute_command", side_effect=fake)
    summary = script.enrich("malware/cnc", "rec", True, {})[-1]
    assert summary.outputs["objectsCreated"] == [{"type": "Threat Actor", "name": "ExampleCrew"}]
    assert summary.outputs["errors"] == ["Malware 'Broken': no such type"]
    assert "1 failed: Malware 'Broken': no such type" in summary.readable_output


def test_collection_and_id_come_from_the_incident_or_the_arguments():
    assert script.resolve_collection({}, INCIDENT) == "malware/cnc"
    assert script.resolve_collection({"collection": "hi/threat"}, INCIDENT) == "hi/threat"
    with pytest.raises(DemistoException, match="Unsupported collection"):
        script.resolve_collection({"collection": "nope"}, INCIDENT)
    with pytest.raises(DemistoException, match="Cannot derive the collection"):
        script.resolve_collection({}, {"type": "Unclassified"})
    assert script.resolve_gib_id({}, INCIDENT) == "rec"
    assert script.resolve_gib_id({"gib_id": " abc "}, {}) == "abc"
    with pytest.raises(DemistoException, match="gib_id"):
        script.resolve_gib_id({}, {})
    assert set(script.COLLECTION_BY_INCIDENT_TYPE.values()) <= set(script.COLLECTION_COMMANDS)


def test_a_breached_record_is_read_by_its_first_id():
    """A breached record's GIB ID joins its IDs with ", "; the lookup takes the first."""
    breach = {"CustomFields": {"gibid": "a1b2, c3d4"}}
    assert script.resolve_gib_id({}, breach) == "a1b2"
    assert script.resolve_gib_id({"gib_id": "a1b2, c3d4"}, {}) == "a1b2"


def test_an_incident_of_no_known_type_fails_saying_the_collection_cannot_be_derived(mocker):
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "incident", return_value={"type": "Unclassified"})
    error = mocker.patch.object(script, "return_error")
    script.main()
    assert "Cannot derive the collection" in error.call_args.args[0]


def test_an_incident_of_a_legacy_type_gets_a_note_not_an_error(mocker):
    """A legacy type names a collection the pack does not read; the postprocessing playbook's task completes with a note."""
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "incident", return_value={"type": "GIB Compromised Account", "CustomFields": {"gibid": "x"}})
    error = mocker.patch.object(script, "return_error")
    results = mocker.patch.object(script, "return_results")
    command = mocker.patch.object(script, "execute_command")
    script.main()
    error.assert_not_called()
    command.assert_not_called()
    assert "GIB Compromised Account" in results.call_args.args[0].readable_output


def test_object_arguments_carry_no_actor_id_for_an_object_the_incident_does_not_name():
    # objects carry the verdict Cortex XSOAR's own threat-intel feeds give them
    assert script.object_arguments("Threat Actor", "Other", "hi/threat", INCIDENT) == {
        "value": "Other",
        "type": "Threat Actor",
        "verdict": "Malicious",
        "tags": "hi/threat",
        "gibcollection": "hi/threat",
    }
    assert script.object_arguments("Malware", "BotTwo", "hi/threat", None) == {
        "value": "BotTwo",
        "type": "Malware",
        "verdict": "Malicious",
        "tags": "hi/threat",
        "gibcollection": "hi/threat",
    }


MODULES = {
    "gib-a": {"brand": "Group-IB Threat Intelligence & Attribution", "state": "active"},
    "gib-b": {"brand": "Group-IB Threat Intelligence & Attribution", "state": "active"},
    "gib-off": {"brand": "Group-IB Threat Intelligence & Attribution", "state": "disabled"},
    "other": {"brand": "Something Else", "state": "active"},
}


def test_the_lookup_runs_on_the_instance_argument_else_the_fetching_one_else_the_only_active_one_else_every_one(mocker):
    mocker.patch.object(demisto, "getModules", return_value=MODULES)
    assert script.resolve_instance({}, {"sourceInstance": "gib-b"}) == "gib-b"
    assert script.resolve_instance({"instance": " gib-a "}, {"sourceInstance": "gib-b"}) == "gib-a"
    # the fetching instance is gone or disabled and two others are active: every instance, as the platform does
    assert script.resolve_instance({}, {"sourceInstance": "gib-off"}) is None
    assert script.resolve_instance({}, {}) is None
    single = {name: module for name, module in MODULES.items() if name != "gib-b"}
    mocker.patch.object(demisto, "getModules", return_value=single)
    assert script.resolve_instance({}, {"sourceInstance": "renamed"}) == "gib-a"
    assert script.resolve_instance({}, None) == "gib-a"


def test_enrich_passes_the_instance_to_the_lookup_and_reports_it(commands):
    results = script.enrich("malware/cnc", "rec", False, INCIDENT, "gib-b")
    assert commands[0] == ("gibti-get-malware-cnc-info", {"id": "rec", "using": "gib-b"})
    assert results[-1].outputs["instance"] == "gib-b"
    commands.clear()
    script.enrich("hi/threat", "rec", False, INCIDENT, None)
    assert commands[0] == ("gibti-get-threat-info", {"id": "rec", "isAPT": "false"})


def _context_entry(context_key, context, dbot):
    return {
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": "x",
        "HumanReadable": "### indicators",
        "EntryContext": {"DBotScore(val.Indicator && val.Indicator == obj.Indicator)": dbot, context_key: context},
    }


def test_every_observable_is_created_with_its_verdict_and_the_attributes_of_its_context():
    """The script creates each observable itself, whatever the task's indicator extraction mode."""
    ip = _context_entry(
        "IP(val.Address && val.Address == obj.Address)",
        [
            {
                "Address": "203.0.113.9",
                "ASN": "AS64500",
                "Geo": {"Country": "Italy", "Description": "Europe"},
                "Tags": ["suspicious_ip/tor_node"],
                "TrafficLightProtocol": "GREEN",
            }
        ],
        [_dbot("203.0.113.9", "ip", score=2)],
    )
    cve = _context_entry(
        "CVE(val.ID && val.ID == obj.ID)",
        {
            "ID": "CVE-2099-0001",
            "CVSS": {"Score": 9.8, "Vector": "CVSS:3.1/AV:N"},
            "Published": "2026-10-01",
            "Modified": "2026-10-02",
            "Description": "A flaw.",
            "Tags": ["osi/vulnerability"],
        },
        _dbot("CVE-2099-0001", "cve"),
    )
    file_ = _context_entry(
        "File(val.MD5 && val.MD5 == obj.MD5)",
        [{"MD5": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Size": 10, "MalwareFamily": ["BotTwo", "BotTwo"]}],
        [_dbot("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "file", score=0)],
    )
    scored = script.scored_observables([ip, cve, file_])
    arguments = {
        key: script.observable_arguments(key[0], key[1], score, context, "c") for key, (score, context) in scored.items()
    }
    common = {"source": "Group-IB Threat Intelligence & Attribution", "gibcollection": "c"}
    assert arguments[("203.0.113.9", "IP")] == {
        "value": "203.0.113.9",
        "type": "IP",
        "verdict": "Suspicious",
        **common,
        "tags": "suspicious_ip/tor_node",
        "trafficlightprotocol": "GREEN",
        "asn": "AS64500",
        "geocountry": "Italy",
        "geolocation": "Europe",
    }
    assert arguments[("CVE-2099-0001", "CVE")] == {
        "value": "CVE-2099-0001",
        "type": "CVE",
        "verdict": "Malicious",
        **common,
        "tags": "osi/vulnerability",
        "cvss": 9.8,
        "cvssvector": "CVSS:3.1/AV:N",
        "published": "2026-10-01",
        "cvemodified": "2026-10-02",
        "cvedescription": "A flaw.",
    }
    assert arguments[("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "File")] == {
        "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "type": "File",
        "verdict": "Unknown",
        **common,
        "malwarefamily": "BotTwo",
        "md5": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "size": 10,
    }


def test_an_observable_the_lookup_returned_from_several_instances_is_created_once_with_its_highest_score():
    entries = [_indicator_entry("203.0.113.5", "ip"), _indicator_entry("203.0.113.5", "ip")]
    entries[0]["EntryContext"]["DBotScore(val.Indicator && val.Indicator == obj.Indicator)"] = [
        _dbot("203.0.113.5", "ip", score=1)
    ]
    scored = script.scored_observables(entries)
    assert list(scored) == [("203.0.113.5", "IP")]
    assert scored[("203.0.113.5", "IP")][0] == 3


def test_a_description_is_a_cve_description_only_on_a_cve_and_a_score_that_is_no_number_is_unknown():
    entry = _context_entry(
        "URL(val.Data && val.Data == obj.Data)",
        {"Data": "http://a.example.com/x", "Description": "not a CVE"},
        [{"Indicator": "http://a.example.com/x", "Type": "url", "Score": "high"}],
    )
    ((key, (score, context)),) = script.scored_observables([entry]).items()
    assert (key, score) == (("http://a.example.com/x", "URL"), 0)
    assert "cvedescription" not in script.observable_arguments(key[0], key[1], score, context, "c")


def test_a_record_context_is_not_read_as_an_indicator_context():
    assert (
        script.indicator_context(
            {"EntryContext": {"GIBTI.X(val.id)": {"Data": "http://a.example.com/x"}}}, "http://a.example.com/x"
        )
        == {}
    )


def test_a_failed_indicator_is_reported_and_the_others_are_still_created(mocker):
    entries = [_indicator_entry("203.0.113.5", "ip"), _indicator_entry("203.0.113.6", "ip")]

    def fake(command, args=None, extract_contents=True, fail_on_error=True):
        if command == "createNewIndicator" and args["value"] == "203.0.113.5":
            raise DemistoException("store is down")
        return entries if command != "createNewIndicator" else []

    mocker.patch.object(script, "execute_command", side_effect=fake)
    summary = script.enrich("suspicious_ip/tor_node", "rec", False, {})[-1]
    assert summary.outputs["indicators"] == [{"value": "203.0.113.6", "type": "IP"}]
    assert summary.outputs["errors"] == ["IP '203.0.113.5': store is down"]
    assert "1 indicator(s) enriched" in summary.readable_output


def _created(mocker, entries, collection, incident):
    calls = []

    def fake(command, args=None, extract_contents=True, fail_on_error=True):
        calls.append((command, args))
        return entries if command != "createNewIndicator" else []

    mocker.patch.object(script, "execute_command", side_effect=fake)
    results = script.enrich(collection, "rec", True, incident)
    return [args for command, args in calls if command == "createNewIndicator"], results


def test_the_publishers_of_a_breached_record_become_no_threat_actor(mocker):
    """The names on a breached record are the leak's publishers; they attribute nothing."""
    record = {**RECORD_ENTRY, "EntryContext": {"GIBTI.DataBreach(val.id == obj.id)": {"id": "rec"}}}
    incident = {"type": "GIB Data Breach", "CustomFields": {"gibid": "rec", "gibthreatactorname": "leak_publisher"}}
    created, results = _created(mocker, [record], "compromised/breacheddb", incident)
    assert created == []
    assert results[-1].outputs["objects"] == []


def test_a_flagged_phishing_group_creates_neither_indicators_nor_objects_and_an_unflagged_one_creates_its_actor(mocker):
    """A phishing group Group-IB flags falsePositive: its lookup builds no indicator, and the actor its
    incident names becomes no object."""
    record = {
        **RECORD_ENTRY,
        "EntryContext": {"GIBTI.PhishingGroup(val.id == obj.id)": {"id": "rec", "falsePositive": True, "whitelist": False}},
    }
    incident = {"type": "GIB Attacks Phishing Group", "CustomFields": {"gibid": "rec", "gibthreatactorname": "Phisher"}}
    created, results = _created(mocker, [record], "attacks/phishing_group", incident)
    assert created == []
    assert results[-1].outputs["objects"] == []
    record["EntryContext"]["GIBTI.PhishingGroup(val.id == obj.id)"]["falsePositive"] = False
    created, _ = _created(mocker, [record], "attacks/phishing_group", incident)
    assert [(args["type"], args["value"]) for args in created] == [("Threat Actor", "Phisher")]


def test_an_ipv6_address_is_created_as_an_ipv6_indicator(mocker):
    entry = _context_entry(
        "IPv6(val.Address && val.Address == obj.Address)",
        {"Address": "2001:db8::77", "ASN": "AS64500", "Geo": {"Country": "NL"}},
        [_dbot("2001:db8::77", "ip")],
    )
    assert script.observables_of(entry) == [("2001:db8::77", "IPv6")]
    created, _ = _created(mocker, [entry], "malware/cnc", {})
    [arguments] = created
    assert (arguments["value"], arguments["type"], arguments["asn"], arguments["geocountry"]) == (
        "2001:db8::77",
        "IPv6",
        "AS64500",
        "NL",
    )


def test_an_email_is_created_with_the_tags_and_tlp_of_its_account_context(mocker):
    """Common.EMAIL writes its context under Account, the address nested in Email.Address."""
    score = Common.DBotScore("drop@example.com", DBotScoreType.EMAIL, "GroupIBTI", 2)
    email = Common.EMAIL("drop@example.com", score, tags=["attacks/phishing_kit"], traffic_light_protocol="RED")
    entry = CommandResults(readable_output="### Email", indicator=email).to_context()
    created, _ = _created(mocker, [entry], "attacks/phishing_kit", {})
    [arguments] = created
    assert {key: arguments.get(key) for key in ("type", "value", "verdict", "tags", "trafficlightprotocol")} == {
        "type": "Email",
        "value": "drop@example.com",
        "verdict": "Suspicious",
        "tags": "attacks/phishing_kit",
        "trafficlightprotocol": "RED",
    }


def test_a_file_known_by_its_sha512_only_is_created_with_it(mocker):
    sha512 = "d" * 128
    entry = _context_entry(
        "File(val.SHA512 && val.SHA512 == obj.SHA512)", {"SHA512": sha512, "Name": "a.bin"}, [_dbot(sha512, "file")]
    )
    created, _ = _created(mocker, [entry], "hi/threat", {})
    [arguments] = created
    assert (arguments["value"], arguments["type"], arguments["sha512"]) == (sha512, "File", sha512)


def test_an_entry_the_command_keeps_out_of_extraction_stays_out_when_reissued():
    """A defacement's indicator entry is not extracted: the victim site's host would become a Domain."""
    entry = {**_indicator_entry("http://victim.example.com/index.html", "url"), "IgnoreAutoExtract": True}
    assert script.reissue(entry)["IgnoreAutoExtract"] is True
    assert "IgnoreAutoExtract" not in script.reissue(_indicator_entry("203.0.113.5", "ip"))


def test_the_defacer_of_a_defacement_becomes_no_threat_actor(mocker):
    """The handle on a defacement groups defacements; it attributes nothing."""
    record = {**RECORD_ENTRY, "EntryContext": {"GIBTI.AttacksDeface(val.id == obj.id)": {"id": "rec"}}}
    incident = {"type": "GIB Attacks Deface", "CustomFields": {"gibid": "rec", "gibthreatactorname": "defacer-one"}}
    created, results = _created(mocker, [record], "attacks/deface", incident)
    assert all(args.get("type") != "Threat Actor" for args in created)
    assert results[-1].outputs["objects"] == []


def _object_tlps(mocker, tlps, existing, incident=INCIDENT):
    """The TLP each Malware / Threat Actor object is created with, for a record whose indicators carry
    ``tlps`` and a findIndicators that answers ``existing`` (an exception to raise or a list)."""
    calls = []

    def entry(value, tlp):
        indicator = _indicator_entry(value, "ip")
        indicator["EntryContext"]["IP(val.Address && val.Address == obj.Address)"]["TrafficLightProtocol"] = tlp
        return indicator

    def fake(command, args=None, extract_contents=True, fail_on_error=True):
        calls.append((command, args))
        if command == "findIndicators":
            if isinstance(existing, Exception):
                raise existing
            return existing
        if command == "createNewIndicator":
            return [{"Type": 1, "Contents": {"id": "obj"}}]
        return [RECORD_ENTRY, *(entry(f"203.0.113.{n}", tlp) for n, tlp in enumerate(tlps, start=1))]

    mocker.patch.object(script, "execute_command", side_effect=fake)
    script.enrich("malware/cnc", "rec", True, incident)
    created = [args for command, args in calls if command == "createNewIndicator" and args["type"] in ("Malware", "Threat Actor")]
    assert {args["value"] for args in created} == {"BotTwo", "BankerFive", "ExampleCrew"}
    searches = [args for command, args in calls if command == "findIndicators"]
    return {args.get("trafficlightprotocol") for args in created}, searches


def test_a_new_object_takes_the_most_restrictive_tlp_of_its_record(mocker):
    tlps, searches = _object_tlps(mocker, ["AMBER", "RED"], [])
    assert tlps == {"RED"}
    assert searches[0] == {"query": 'value:"BotTwo" and type:"Malware"', "size": 1}


def test_an_existing_object_keeps_its_tlp(mocker):
    """createNewIndicator replaces the field, and an object is shared by every record and feed that names it."""
    for tlp in ("RED", "GREEN", None):
        existing = [{"value": "x", "CustomFields": {"trafficlightprotocol": tlp}}]
        assert _object_tlps(mocker, ["AMBER"], existing)[0] == {None}


def test_an_object_is_created_without_a_tlp_when_the_search_fails(mocker):
    assert _object_tlps(mocker, ["RED"], DemistoException("search refused"))[0] == {None}


def test_a_new_object_takes_the_incident_tlp_without_a_record_tlp_else_the_most_restrictive_of_both(mocker):
    incident = {**INCIDENT, "CustomFields": {**INCIDENT["CustomFields"], "gibtlp": "amber"}}
    assert _object_tlps(mocker, [None], [], incident)[0] == {"AMBER"}
    assert _object_tlps(mocker, ["RED"], [], incident)[0] == {"RED"}


def test_a_record_without_a_tlp_searches_nothing(mocker):
    tlps, searches = _object_tlps(mocker, [None], [])
    assert (tlps, searches) == ({None}, [])
