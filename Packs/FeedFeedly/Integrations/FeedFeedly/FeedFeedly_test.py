import json

from CommonServerPython import FeedIndicatorType
from FeedFeedly import Client, STIX2Parser

URL = (
    "https://api.feedly.com/v3/enterprise/ioc?"
    "streamId=tag%2FenterpriseName%2Fcategory%2Fuuid&count=20"
    "&newerThan=0"
    "&client=feedly.demisto.client"
)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_build_iterator(requests_mock):
    """

    Given:
        - Output of the feed API
    When:
        - When calling fetch_indicators or get_indicators
    Then:
        - Returns a list of the indicators parsed from the API's response

    """
    with open("test_data/api_call_mock.txt") as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_ips = {"31.31.194.65", "95.213.205.83", "77.223.124.212"}
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.fetch_indicators_from_stream("tag/enterpriseName/category/uuid", 0)
    ip_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "IP"}
    assert expected_ips == ip_indicators

    report = next(indicator for indicator in indicators if indicator["type"] == "Feedly Report")
    assert report["fields"]["description"].startswith("Recently, threat actors have")

    assert len(report["relationships"]) == 13

    feedly_tags = {"Domains", "Feedly AI", "IPs", "TTPs"}
    threat_tags = {"RMS", "TA505"}
    ttp_tags = {"T1112", "T1125", "T1132.001", "T1566", "T1566.001"}

    assert set(report["fields"]["tags"]) == feedly_tags | threat_tags | ttp_tags


def test_build_iterator_with_instance_tags(requests_mock):
    """
    Given:
        - An instance configured with feed_tags
    When:
        - Fetching indicators from the stream
    Then:
        - The instance-level tags are merged onto every fetched indicator
    """
    with open("test_data/api_call_mock.txt") as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
        feed_tags=["incoming_feed", "source_feedly"],
    )
    indicators = client.fetch_indicators_from_stream("tag/enterpriseName/category/uuid", 0)

    for indicator in indicators:
        tags = set(indicator["fields"].get("tags", []))
        assert {"incoming_feed", "source_feedly"} <= tags


def test_parse_vulnerability_maps_cvss_fields():
    """
    Given:
        - A vulnerability exported with Feedly's CVSS v3 custom properties
    When:
        - Parsing the STIX objects
    Then:
        - The CVE indicator gets its CVSS score, version, vector and table
    """
    [cve] = STIX2Parser().parse_stix2_objects([make_vulnerability()])

    fields = cve["customFields"]
    assert fields["cvssscore"] == 9.6
    assert fields["cvssversion"] == "3.1"
    assert fields["cvssvector"] == CVSS_VECTOR
    assert {"metrics": "AV", "value": "N"} in fields["cvsstable"]
    assert {"metrics": "C", "value": "H"} in fields["cvsstable"]


def test_parse_vulnerability_tags_its_cwes():
    """
    Given:
        - A vulnerability with a CWE external reference
    When:
        - Parsing the STIX objects
    Then:
        - The CWE id is added to the CVE indicator's tags
    """
    [cve] = STIX2Parser().parse_stix2_objects([make_vulnerability()])

    assert "CWE-89" in cve["customFields"]["tags"]


def test_parse_vulnerability_without_cvss_leaves_cvss_fields_unset():
    """
    Given:
        - A vulnerability exported without CVSS data
    When:
        - Parsing the STIX objects
    Then:
        - No CVSS field is set on the CVE indicator
    """
    vulnerability = make_vulnerability()
    del vulnerability["x_feedly_cvss_v3_base_score"]
    del vulnerability["x_feedly_cvss_v3_vector"]

    [cve] = STIX2Parser().parse_stix2_objects([vulnerability])

    assert not {"cvssscore", "cvssversion", "cvssvector", "cvsstable"} & cve["customFields"].keys()


def test_parse_vulnerability_lists_the_cpes_of_its_related_softwares():
    """
    Given:
        - A vulnerability with two related software objects, one without a CPE
    When:
        - Parsing the STIX objects
    Then:
        - The CVE indicator's vulnerable products list the CPE of the software that has one
    """
    objects = [
        make_vulnerability(),
        make_software("software--1", "cpe:2.3:a:adobe:campaign_classic:*:*:*:*:*:*:*:*"),
        make_software("software--2", None),
        make_related_to("software--1", VULNERABILITY_ID),
        make_related_to("software--2", VULNERABILITY_ID),
    ]

    indicators = STIX2Parser().parse_stix2_objects(objects)

    [cve] = [indicator for indicator in indicators if indicator["indicator_type"] == FeedIndicatorType.CVE]
    assert cve["customFields"]["vulnerableproducts"] == [{"CPE": "cpe:2.3:a:adobe:campaign_classic:*:*:*:*:*:*:*:*"}]


def test_parse_identity_keeps_its_sectors():
    """
    Given:
        - A targeted organization exported as an identity
    When:
        - Parsing the STIX objects
    Then:
        - An Identity indicator is created with its class and industry sectors
    """
    [identity] = STIX2Parser().parse_stix2_objects([make_identity()])

    assert identity["value"] == "Adobe"
    assert identity["indicator_type"] == FeedIndicatorType.Identity
    assert identity["customFields"]["identityclass"] == "organization"
    assert identity["customFields"]["industrysectors"] == ["technology"]


def test_parse_identity_skips_the_authors_of_the_objects():
    """
    Given:
        - The Feedly AI identity, referenced as the author of a report
    When:
        - Parsing the STIX objects
    Then:
        - No Identity indicator is created for the author
    """
    author = {"type": "identity", "id": "identity--feedly-ai", "name": "Feedly AI", "identity_class": "organization"}
    report = {"type": "report", "id": "report--1", "name": "A report", "created_by_ref": author["id"], "object_refs": []}

    indicators = STIX2Parser().parse_stix2_objects([author, report])

    assert "Feedly AI" not in {indicator["value"] for indicator in indicators}


def test_parse_location_falls_back_to_the_country_code():
    """
    Given:
        - A country exported as a location without a name
    When:
        - Parsing the STIX objects
    Then:
        - A Location indicator is created, named after its country code
    """
    [location] = STIX2Parser().parse_stix2_objects([{"type": "location", "id": "location--1", "country": "fr"}])

    assert location["value"] == "FR"
    assert location["indicator_type"] == FeedIndicatorType.Location
    assert location["customFields"]["countrycode"] == "FR"


def test_parse_software_creates_a_software_indicator_with_its_cpe():
    """
    Given:
        - An affected product exported as a software object
    When:
        - Parsing the STIX objects
    Then:
        - A Software indicator is created with its vendor and CPE
    """
    [software] = STIX2Parser().parse_stix2_objects([make_software("software--1", CPE)])

    assert software["value"] == "Adobe Campaign Classic"
    assert software["indicator_type"] == FeedIndicatorType.Software
    assert software["customFields"]["cpe"] == CPE
    assert software["customFields"]["vendor"] == "Adobe"


def test_parse_relationships_keeps_the_links_to_organizations_countries_and_softwares():
    """
    Given:
        - A threat actor targeting an organization located in a country, and a software related to a CVE
    When:
        - Parsing the STIX objects
    Then:
        - The relationships are kept, located-at as Cortex's related-to
    """
    objects = [
        make_threat_actor(),
        make_identity(),
        {"type": "location", "id": "location--1", "country": "US"},
        make_vulnerability(),
        make_software("software--1", CPE),
        make_relationship("targets", "threat-actor--1", "identity--1"),
        make_relationship("located-at", "identity--1", "location--1"),
        make_relationship("related-to", "software--1", VULNERABILITY_ID),
    ]

    indicators = STIX2Parser().parse_stix2_objects(objects)

    assert get_relationship_names(indicators) == {
        ("APT28", "targets", "Adobe"),
        ("Adobe", "related-to", "US"),
        ("Adobe Campaign Classic", "related-to", "CVE-2026-125717"),
    }


def test_parse_relationships_maps_originates_from_to_cortex_originated_from():
    """
    Given:
        - A threat actor originating from a country, with STIX's originates-from relationship
    When:
        - Parsing the STIX objects
    Then:
        - The relationship is kept under Cortex's originated-from name
    """
    objects = [
        make_threat_actor(),
        {"type": "location", "id": "location--1", "country": "RU"},
        make_relationship("originates-from", "threat-actor--1", "location--1"),
    ]

    indicators = STIX2Parser().parse_stix2_objects(objects)

    assert get_relationship_names(indicators) == {("APT28", "originated-from", "RU")}


def test_parse_relationships_tags_indicators_with_the_tools_they_indicate():
    """
    Given:
        - An IP indicator indicating a tool
    When:
        - Parsing the STIX objects
    Then:
        - The IP indicator is tagged with the tool's name, as for malwares and threat actors
    """
    objects = [
        {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
        },
        {"type": "tool", "id": "tool--1", "name": "Cobalt Strike"},
        make_relationship("indicates", "indicator--1", "tool--1"),
    ]

    indicators = STIX2Parser().parse_stix2_objects(objects)

    [ip] = [indicator for indicator in indicators if indicator["value"] == "1.2.3.4"]
    assert "Cobalt Strike" in ip["customFields"]["tags"]


CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
VULNERABILITY_ID = "vulnerability--1"
CPE = "cpe:2.3:a:adobe:campaign_classic:*:*:*:*:*:*:*:*"


def make_vulnerability() -> dict:
    return {
        "type": "vulnerability",
        "id": VULNERABILITY_ID,
        "name": "CVE-2026-125717",
        "description": "SQL injection in Adobe Campaign Classic.",
        "external_references": [
            {"source_name": "cve", "external_id": "CVE-2026-125717"},
            {
                "source_name": "cwe",
                "external_id": "CWE-89",
                "description": "SQL Injection",
                "url": "https://cwe.mitre.org/data/definitions/89.html",
            },
        ],
        "x_feedly_cvss_v3_base_score": 9.6,
        "x_feedly_cvss_v3_vector": CVSS_VECTOR,
    }


def make_software(software_id: str, cpe: str | None) -> dict:
    software = {"type": "software", "id": software_id, "name": "Adobe Campaign Classic", "vendor": "Adobe"}
    if cpe:
        software["cpe"] = cpe
    return software


def make_related_to(source_ref: str, target_ref: str) -> dict:
    return make_relationship("related-to", source_ref, target_ref)


def make_relationship(relationship_type: str, source_ref: str, target_ref: str) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{source_ref}-{target_ref}",
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }


def make_identity() -> dict:
    return {
        "type": "identity",
        "id": "identity--1",
        "name": "Adobe",
        "identity_class": "organization",
        "sectors": ["technology"],
    }


def make_threat_actor() -> dict:
    return {"type": "threat-actor", "id": "threat-actor--1", "name": "APT28"}


def get_relationship_names(indicators: list[dict]) -> set[tuple[str, str, str]]:
    return {
        (relationship["entityA"], relationship["name"], relationship["entityB"])
        for indicator in indicators
        for relationship in indicator.get("relationships", [])
    }
