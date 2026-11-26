import json

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

    [cve] = STIX2Parser().parse_stix2_objects(objects)

    assert cve["customFields"]["vulnerableproducts"] == [{"CPE": "cpe:2.3:a:adobe:campaign_classic:*:*:*:*:*:*:*:*"}]


CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
VULNERABILITY_ID = "vulnerability--1"


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
    return {
        "type": "relationship",
        "id": f"relationship--{source_ref}",
        "relationship_type": "related-to",
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
