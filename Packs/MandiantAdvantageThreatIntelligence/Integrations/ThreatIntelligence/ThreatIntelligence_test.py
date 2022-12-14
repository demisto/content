import json
import io
import freezegun
import pytest
from CommonServerPython import *
from ThreatIntelligence import MandiantClient


def test_retrieve_token(mocker):
    """
    Given -
       client
    When -
        generating a token
    Then -
        Validate the result is as expected
    """
    MandiantClient._http_request = lambda _, *args, **kwargs: {
        "access_token": "token",
        "expires_in": 1666749807,
    }
    client = MandiantClient(
        "url", "username", "password", False, False, 60, "90 days", 1, ["Malware"]
    )

    mocker.patch.object(
        client,
        "_http_request",
        return_value={"access_token": "token", "expires_in": 1666749807},
    )
    res = client._retrieve_token()
    assert res == "token"


def mock_client():
    MandiantClient._retrieve_token = lambda x: "token"
    client = MandiantClient(
        "url", "username", "password", False, False, 60, "90 days", 1, ["Malware"]
    )
    return client


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


@freezegun.freeze_time("2020-11-25T11:57:28Z")
def test_get_token():
    """
    Given -
       client
    When -
        getting a token
    Then -
        Validate the result is as expected
    """
    from ThreatIntelligence import MandiantClient

    MandiantClient._retrieve_token = lambda x: "token"
    client = MandiantClient(
        "url",
        "username",
        "password",
        False,
        False,
        60,
        "x_app_name",
        "first_fetch",
        1,
        [],
    )
    res = client._get_token()
    assert res == "token"


@pytest.mark.parametrize(
    "info_type, response, result",
    [
        ("info-type", {"info-type": "res"}, "res"),
        ("", {"info-type": "res"}, {"info-type": "res"}),
        ("attack-pattern", {}, []),
        ("attack-pattern", {"malware": [{"attack-patterns": {"res": {}}}]}, ["res"]),
    ],
)
def test_get_indicator_additional_info(mocker, info_type, response, result):
    client = mock_client()
    mocker.patch.object(client, "_http_request", return_value=response)
    res = client.get_indicator_info("identifier", "Malware", info_type)
    assert res == result


def test_get_indicators_valid(mocker):
    client = mock_client()
    mocker.patch.object(client, "_http_request", return_value={"malware": ["list"]})
    res = client.get_indicators("Malware")
    assert res == ["list"]


def test_get_indicators_invalid(mocker):
    from ThreatIntelligence import DemistoException

    client = mock_client()
    mocker.patch.object(
        client, "_http_request", side_effect=DemistoException("exception")
    )
    res = client.get_indicators("Malware")
    assert res == []


INDICATOR_LIST = [
    {"last_updated": "2020-11-23T11:57:28Z", "type": "md5"},
    {"last_updated": "2020-11-24T11:57:28Z", "type": "md5"},
]


@pytest.mark.parametrize(
    "indicator_type, result",
    [("Indicators", INDICATOR_LIST), ("Malware", INDICATOR_LIST[::-1])],
)
@freezegun.freeze_time("2020-11-25T11:57:28Z")
def test_get_new_indicators(mocker, indicator_type, result):
    from ThreatIntelligence import get_new_indicators

    client = mock_client()
    mocker.patch.object(client, "get_indicators", return_value=INDICATOR_LIST)
    res = get_new_indicators(client, "90 days ago", indicator_type, 10)
    assert res == result


@pytest.mark.parametrize(
    "mscore, res", [(None, 0), ("1", 1), ("22", 0), ("52", 2), ("82", 3), ("101", 0)]
)
def test_get_verdict(mscore, res):
    """
    Given -
       mscore
    When -
        get_verdict
    Then -
        receive valid verdict for each mscore
    """
    from ThreatIntelligence import get_verdict

    assert get_verdict(mscore) == res


def test_get_indicator_relationships():
    from ThreatIntelligence import get_indicator_relationships, EntityRelationship

    res = get_indicator_relationships(
        {
            "field_indicator": [{"entity_b_field": "value_b"}],
            "entity_a_field": "value_a",
        },
        "field_indicator",
        "entity_a_field",
        "entity_a_type",
        "entity_b_field",
        "entity_b_type",
        EntityRelationship.Relationships.RELATED_TO,
        EntityRelationship.Relationships.RELATED_TO,
    )
    assert len(res) == 1
    assert res[0]["entityA"] == "value_a"
    assert res[0]["entityAType"] == "entity_a_type"
    assert res[0]["entityB"] == "value_b"
    assert res[0]["entityBType"] == "entity_b_type"
    assert res[0]["name"] == "related-to"
    assert res[0]["reverseName"] == "related-to"


BASIC_INDICATOR = {
    "operating_systems": "operatingsystemrefs",
    "aliases": "redacted",
    "capabilities": "capabilities",
    "industries": [{"name": "tags"}],
    "detections": "mandiantdetections",
    "yara": [{"name": "name", "id": "id"}],
    "roles": "roles",
    "id": "stixid",
    "name": "name",
    "description": "description",
    "last_updated": "updateddate",
    "last_activity_time": "lastseenbysource",
    "actors": [],
    "cve": [],
    "mscore": 100,
    "motivations": [{"name": "primarymotivation"}],
    "locations": {"target": [{"name": "target"}]},
}


def test_create_malware_indicator():
    from ThreatIntelligence import create_malware_indicator

    client = mock_client()
    indicator_dict = BASIC_INDICATOR
    indicator_dict["type"] = "malware"
    res = create_malware_indicator(client, indicator_dict)
    assert res["value"] == "name"
    assert res["type"] == "Malware"
    assert len(res["fields"]) == 12


def test_create_actor_indicator():
    from ThreatIntelligence import create_actor_indicator

    client = mock_client()
    indicator_dict = BASIC_INDICATOR
    indicator_dict["type"] = "actor"
    res = create_actor_indicator(client, indicator_dict)
    assert res["value"] == "name"
    assert res["type"] == "Threat Actor"
    assert len(res["fields"]) == 8


@freezegun.freeze_time("2020-11-25T11:57:28Z")
def test_fetch_indicators(mocker):
    from ThreatIntelligence import fetch_indicators

    client = mock_client()
    mocker.patch.object(client, "get_indicators", return_value=INDICATOR_LIST)
    res = fetch_indicators(client, update_context=False)
    assert len(res) == 1


@pytest.mark.parametrize(
    "command", ["test-module", "threat-intelligence-get-indicators"]
)
def test_main(mocker, command):
    from ThreatIntelligence import main, MandiantClient
    import demistomock as demisto

    params = {
        "auth": {"identifier": "identifier", "password": "password"},
        "insecure": True,
        "url": "url",
        "first_fetch": "89 days ago",
        "indicatorMetadata": True,
        "limit": 10,
        "indicatorRelationships": True,
        "type": [],
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(MandiantClient, "_retrieve_token", return_value="token")
    mocker.patch.object(demisto, "command", return_value=command)
    main()


def test_get_indicators_by_value(mocker):
    """
    Given -
       client
    When -
        getting new indicators
    Then -
        receive list of indicators
    """
    client = mock_client()

    raw_indicator_post = {
        "indicators": [
            {
                "id": "fqdn--some-uuid-goes-here",
                "mscore": 50,
                "type": "fqdn",
                "value": "msdns.example.com",
                "is_exclusive": True,
                "is_publishable": True,
                "sources": [],
                "attributed_associations": [],
                "last_updated": "2022-08-16T04:52:49.046Z",
                "first_seen": "2011-09-12T12:23:13.000Z",
                "last_seen": "2022-07-18T23:15:03.000Z",
            }
        ]
    }

    mocker.patch.object(client, "_http_request", return_value=raw_indicator_post)
    res = client.get_indicators_by_value("msdns.example.com")

    assert res == [
        {
            "attributed_associations": [],
            "first_seen": "2011-09-12T12:23:13.000Z",
            "id": "fqdn--some-uuid-goes-here",
            "is_exclusive": True,
            "is_publishable": True,
            "last_seen": "2022-07-18T23:15:03.000Z",
            "last_updated": "2022-08-16T04:52:49.046Z",
            "mscore": 50,
            "sources": [],
            "type": "fqdn",
            "value": "msdns.example.com",
        }
    ]


def test_get_indicator_list():
    """
    Given -
       client
    When -
        getting new indicators
    Then -
        receive list of indicators
    """
    import ThreatIntelligence

    client = mock_client()
    res_indicators = util_load_json("./test_data/result_indicators.json")

    def get_new_indicators_mock(a, b, c, d):
        return res_indicators["new_indicators"]

    ThreatIntelligence.get_new_indicators = get_new_indicators_mock
    res = ThreatIntelligence.get_indicator_list(client, 2, "90 days ago", "Indicators")
    assert res == res_indicators["new_indicators"]


def test_get_cvss_v3_score():
    example_cve = {
        "common_vulnerability_scores": {
            "v3.1": {"base_score": "V3.1Score"},
            "v2.0": {"base_score": "V2Score"},
        }
    }

    import ThreatIntelligence

    assert ThreatIntelligence.get_cvss_score(example_cve) == "V3.1Score"


def test_get_cvss_v2_score():
    example_cve = {"common_vulnerability_scores": {"v2.0": {"base_score": "V2Score"}}}

    import ThreatIntelligence

    assert ThreatIntelligence.get_cvss_score(example_cve) == "V2Score"


@pytest.mark.parametrize(
    "value, type, response",
    [
        (
            "8.8.8.8",
            "IP",
            {
                "id": "ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9",
                "mscore": 0,
                "type": "ipv4",
                "value": "8.8.8.8",
                "is_publishable": True,
                "sources": [],
                "last_updated": "2022-10-25T15:01:24.711Z",
                "first_seen": "2014-09-01T21:39:51.000Z",
                "last_seen": "2022-10-25T15:01:21.000Z",
            },
        ),
        (
            "google.com",
            "Domain",
            {
                "id": "fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1",
                "mscore": 0,
                "type": "fqdn",
                "value": "google.com",
                "is_publishable": True,
                "sources": [],
                "last_updated": "2022-10-25T17:03:58.528Z",
                "first_seen": "2014-09-01T21:39:23.000Z",
                "last_seen": "2022-10-25T16:51:58.000Z",
            },
        ),
        (
            "fe09cf6d3a358305f8c2f687b6f6da02",
            "File",
            {
                "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
                "mscore": 100,
                "type": "md5",
                "value": "fe09cf6d3a358305f8c2f687b6f6da02",
                "is_exclusive": False,
                "is_publishable": True,
                "sources": [],
                "associated_hashes": [
                    {
                        "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
                        "type": "md5",
                        "value": "fe09cf6d3a358305f8c2f687b6f6da02",
                    },
                    {
                        "id": "sha1--ad083435-4612-5b45-811a-157a77f65bdf",
                        "type": "sha1",
                        "value": "30d64987a6903a9995ea74fe268689811b14b81b",
                    },
                    {
                        "id": "sha256--c17aca6a-7a35-5265-93f6-f6b5537cef7e",
                        "type": "sha256",
                        "value": "af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070",
                    },
                ],
                "attributed_associations": [],
                "last_updated": "2022-10-19T00:37:24.612Z",
                "first_seen": "2022-01-13T23:01:27.000Z",
                "last_seen": "2022-08-12T22:05:41.000Z",
            },
        ),
        (
            "https://google.com",
            "URL",
            {
                "id": "url--431bfcd3-a8a5-5103-9ad7-ac7f05891875",
                "mscore": 0,
                "type": "url",
                "value": "https://google.com",
                "is_publishable": True,
                "sources": [],
                "last_updated": "2022-10-19T22:16:54.141Z",
                "first_seen": "2021-06-19T09:13:28.000Z",
                "last_seen": "2022-10-19T22:16:52.000Z",
            },
        ),
    ],
)
def test_fetch_by_value(mocker, value, type, response):
    import ThreatIntelligence

    raw_response = {"indicators": [response]}

    client = mock_client()

    mocker.patch.object(client, "_http_request", return_value=raw_response)
    res = ThreatIntelligence.fetch_indicator_by_value(
        client, {"indicator_value": value}
    )

    assert res.indicators[0]["type"] == type


@pytest.mark.parametrize(
    "value, command, type, response",
    [
        (
            "8.8.8.8",
            "ip",
            "IP",
            {
                "id": "ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9",
                "mscore": 0,
                "type": "ipv4",
                "value": "8.8.8.8",
                "is_publishable": True,
                "sources": [],
                "last_updated": "2022-10-25T15:01:24.711Z",
                "first_seen": "2014-09-01T21:39:51.000Z",
                "last_seen": "2022-10-25T15:01:21.000Z",
            },
        ),
        (
            "google.com",
            "domain",
            "Domain",
            {
                "id": "fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1",
                "mscore": 0,
                "type": "fqdn",
                "value": "google.com",
                "is_publishable": True,
                "sources": [],
                "last_updated": "2022-10-25T17:03:58.528Z",
                "first_seen": "2014-09-01T21:39:23.000Z",
                "last_seen": "2022-10-25T16:51:58.000Z",
            },
        ),
        (
            "fe09cf6d3a358305f8c2f687b6f6da02",
            "file",
            "File",
            {
                "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
                "mscore": 100,
                "type": "md5",
                "value": "fe09cf6d3a358305f8c2f687b6f6da02",
                "is_exclusive": False,
                "is_publishable": True,
                "sources": [],
                "associated_hashes": [
                    {
                        "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
                        "type": "md5",
                        "value": "fe09cf6d3a358305f8c2f687b6f6da02",
                    },
                    {
                        "id": "sha1--ad083435-4612-5b45-811a-157a77f65bdf",
                        "type": "sha1",
                        "value": "30d64987a6903a9995ea74fe268689811b14b81b",
                    },
                    {
                        "id": "sha256--c17aca6a-7a35-5265-93f6-f6b5537cef7e",
                        "type": "sha256",
                        "value": "af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070",
                    },
                ],
                "attributed_associations": [],
                "last_updated": "2022-10-19T00:37:24.612Z",
                "first_seen": "2022-01-13T23:01:27.000Z",
                "last_seen": "2022-08-12T22:05:41.000Z",
            },
        ),
        (
            "https://google.com",
            "url",
            "URL",
            {
                "id": "url--431bfcd3-a8a5-5103-9ad7-ac7f05891875",
                "mscore": 0,
                "type": "url",
                "value": "https://google.com",
                "is_publishable": True,
                "sources": [],
                "last_updated": "2022-10-19T22:16:54.141Z",
                "first_seen": "2021-06-19T09:13:28.000Z",
                "last_seen": "2022-10-19T22:16:52.000Z",
            },
        ),
    ],
)
def test_fetch_reputation(mocker, value, command, type, response):
    import ThreatIntelligence

    raw_response = {"indicators": [response]}

    client = mock_client()

    mocker.patch.object(client, "_http_request", return_value=raw_response)
    mocker.patch("demistomock.command", return_value=command)

    res = ThreatIntelligence.fetch_reputation(client, {command: value})
    assert res.outputs[0]["type"] == type


def test_fetch_malware_family(mocker):
    import ThreatIntelligence

    raw_response = {
        "actors": [],
        "description": "A310Logger is an infostealer that steals bookmarks, website login credentials, cookies, credit card and autofill information from internet browsers. It also performs a system survey that collects basic system information. An external program or script is required to exfiltrate the stolen information.",
        "detections": [],
        "id": "malware--7fc0c282-a920-5394-b709-884fc4fda1fb",
        "industries": [],
        "inherently_malicious": 1,
        "last_activity_time": "2022-10-20T02:12:11.000Z",
        "last_updated": "2022-10-20T02:12:11.000Z",
        "malware": [],
        "name": "A310LOGGER",
        "operating_systems": ["Windows"],
        "type": "malware",
        "yara": [],
        "is_publishable": True,
        "intel_free": False,
        "aliases": [],
        "capabilities": [
            {
                "name": "Capture browser bookmarks",
                "description": "Capable of capturing or mining browser bookmarks. ",
            },
            {
                "name": "Capture cookies",
                "description": "Includes the capability to acquire cookies from a victim machine",
            },
            {
                "name": "Capture credentials stored by Chrome",
                "description": "Can capture or mine credentials stored, cached, or used by Chrome.",
            },
            {
                "name": "Capture credentials stored by Firefox",
                "description": "Can capture or mine credentials stored, cached, or used by Firefox.",
            },
            {
                "name": "Capture credentials stored by Microsoft Edge browser",
                "description": "Capable of capturing or mining credentials from Microsoft Edge browser.",
            },
            {
                "name": "Capture payment card data",
                "description": "Can search for and capture payment card data.",
            },
            {
                "name": "Capture system information",
                "description": "Can capture or extract various types of system information. Potentially includes a variety of data, including disk, network, or memory configuration; local user accounts; installed applications or patches; or the output of various system commands, such as 'sysinfo' or 'ipconfig' on Windows.",
            },
            {
                "name": "Communicates using HTTP",
                "description": "Can communicate using HTTP or an HTTP-like protocol.",
            },
            {
                "name": "File manipulation",
                "description": 'Capabilities associated with operations on files. "Parent" aspect used to contain specific sub-aspects.',
            },
        ],
        "cve": [],
        "roles": ["Data Miner"],
    }

    client = mock_client()

    mocker.patch.object(client, "_http_request", return_value=raw_response)

    res = ThreatIntelligence.fetch_malware_family(
        client, {"malware_name": "A310LOGGER"}
    )

    indicator = res.outputs[0]

    assert indicator["type"] == "Malware"
    assert indicator["relationships"] == []


def test_fetch_threat_actor(mocker):
    import ThreatIntelligence

    raw_response = {
        "id": "threat-actor--7a39953e-0dae-569a-9d49-d52a4a8865b1",
        "name": "APT29",
        "description": "APT29 is a cyber espionage actor with a Russia nexus. Historically, targets have included Western governments, foreign affairs and policymaking bodies, government contractors, universities, and possibly international news outlets. Based on available data, we assess that APT29 is a nation-state-sponsored group located in Russia. The group appears to have formidable capabilities, to include a range of custom developed tools, extensive command and control (C2) infrastructure that includes compromised and satellite infrastructure (via apparent service providers), and significant operational security. In investigations we worked where APT29 was present, they demonstrated a high regard for operational security but were also fairly aggressive in their continued operations and efforts to evade investigators and remediation attempts.",
        "type": "threat-actor",
        "last_updated": "2022-10-11T05:52:23.000Z",
        "motivations": [
            {
                "id": "motivation--1b8ca82a-7cff-5622-bedd-965c11d38a9e",
                "name": "Espionage",
                "attribution_scope": "confirmed",
            }
        ],
        "aliases": [
            {"name": "APT-C-42 (Qihoo)", "attribution_scope": "possible"},
            {"name": "APT29 (NCSC)", "attribution_scope": "possible"},
            {"name": "APT29 (Volexity)", "attribution_scope": "confirmed"},
            {
                "name": "Cloaked Ursa (Palo Alto Networks)",
                "attribution_scope": "confirmed",
            },
            {"name": "Cozy Bear (CrowdStrike)", "attribution_scope": "confirmed"},
            {"name": "Dark Halo (Volexity)", "attribution_scope": "confirmed"},
            {"name": "Dukes (ESET)", "attribution_scope": "confirmed"},
            {"name": "NobelBaron (SentinelOne)", "attribution_scope": "confirmed"},
            {"name": "Nobelium (ANSSI)", "attribution_scope": "confirmed"},
            {"name": "Nobelium (Microsoft)", "attribution_scope": "confirmed"},
            {"name": "Nobelium (Recorded Future)", "attribution_scope": "confirmed"},
            {
                "name": "SolarStorm (Palo Alto Networks)",
                "attribution_scope": "confirmed",
            },
            {"name": "TEMP.Monkey", "attribution_scope": "confirmed"},
            {"name": "The Dukes (F-Secure)", "attribution_scope": "confirmed"},
            {"name": "The Dukes (Volexity)", "attribution_scope": "confirmed"},
        ],
        "industries": [
            {
                "id": "identity--cc593632-0c42-500c-8d0b-d38e97b90f1d",
                "name": "Aerospace & Defense",
                "attribution_scope": "confirmed",
                "first_seen": "2020-05-06T23:30:21.000Z",
                "last_seen": "2020-07-18T19:36:20.000Z",
            },
            {
                "id": "identity--41930e54-396f-508e-8f65-418dd09f935d",
                "name": "Automotive",
                "attribution_scope": "confirmed",
            },
            {
                "id": "identity--a93f63bc-bbfc-52ab-88c0-794c74f5bec0",
                "name": "Chemicals & Materials",
                "attribution_scope": "confirmed",
                "first_seen": "2020-03-24T13:53:42.000Z",
                "last_seen": "2022-01-29T06:21:38.000Z",
            },
            {
                "id": "identity--65be572d-bd1a-5e1d-96e5-a5fb1d7f2bab",
                "name": "Civil Society & Non-Profits",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-21T12:55:42.000Z",
                "last_seen": "2021-05-25T14:46:20.000Z",
            },
            {
                "id": "identity--5b3cb2f9-14d8-5e48-bc4e-3ef3cd477ce1",
                "name": "Construction & Engineering",
                "attribution_scope": "confirmed",
                "first_seen": "2020-03-24T13:53:42.000Z",
                "last_seen": "2022-01-25T13:41:53.000Z",
            },
            {
                "id": "identity--74d68d1c-7ad3-5eb5-a594-5519c1ee2661",
                "name": "Education",
                "attribution_scope": "confirmed",
                "first_seen": "2009-09-10T12:08:32.000Z",
                "last_seen": "2020-12-18T19:29:43.000Z",
            },
            {
                "id": "identity--c5e884ab-d62f-5632-9fc8-3ab3fb752598",
                "name": "Energy & Utilities",
                "attribution_scope": "confirmed",
                "first_seen": "2019-10-10T23:28:10.000Z",
                "last_seen": "2020-12-21T20:01:26.000Z",
            },
            {
                "id": "identity--eaaa8a1a-0db8-5c22-a895-3b0327e3eff1",
                "name": "Financial Services",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-21T00:00:00.000Z",
                "last_seen": "2021-11-11T16:18:41.000Z",
            },
            {
                "id": "identity--8d0881d8-d199-5e5a-bef9-be3ca6bb8f0d",
                "name": "Governments",
                "attribution_scope": "confirmed",
                "first_seen": "2014-08-05T00:00:00.000Z",
                "last_seen": "2022-06-30T13:58:21.000Z",
            },
            {
                "id": "identity--cacd2de0-d89e-54e3-a8af-88a41d312a12",
                "name": "Healthcare",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-21T14:39:39.000Z",
                "last_seen": "2022-02-11T22:43:54.000Z",
            },
            {
                "id": "identity--5a90f5ac-2ac0-5cbe-ae22-eb07a4da67c9",
                "name": "Hospitality",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-21T14:37:39.000Z",
                "last_seen": "2021-12-01T00:00:00.000Z",
            },
            {
                "id": "identity--846d258f-ee99-5097-b0b2-ac2d3f34e2c9",
                "name": "Insurance",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-21T00:00:00.000Z",
                "last_seen": "2021-11-11T16:18:41.000Z",
            },
            {
                "id": "identity--8b245566-834c-5039-95ae-f6a4ffc03b44",
                "name": "Legal & Professional Services",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-01T00:00:00.000Z",
                "last_seen": "2022-08-11T17:21:36.000Z",
            },
            {
                "id": "identity--e0fc24e1-1f79-556a-b8f4-b56735ccf42b",
                "name": "Manufacturing",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-21T15:03:09.000Z",
                "last_seen": "2022-02-11T22:43:54.000Z",
            },
            {
                "id": "identity--5d058af8-02a8-5266-8076-27cc2751e64e",
                "name": "Media & Entertainment",
                "attribution_scope": "confirmed",
                "first_seen": "2019-10-10T07:28:10.000Z",
                "last_seen": "2020-12-16T16:06:46.000Z",
            },
            {
                "id": "identity--60c05066-3b67-5783-b32e-4104b86d06c1",
                "name": "Oil & Gas",
                "attribution_scope": "confirmed",
                "first_seen": "2020-05-12T03:24:32.000Z",
                "last_seen": "2020-12-14T19:23:38.000Z",
            },
            {
                "id": "identity--c9000eb7-82e8-5859-9845-17c4760400cb",
                "name": "Pharmaceuticals",
                "attribution_scope": "confirmed",
                "first_seen": "2018-11-14T16:02:10.000Z",
                "last_seen": "2020-12-16T16:12:44.000Z",
            },
            {
                "id": "identity--c09ecb05-79d5-5a2b-b47f-65c1092a3a56",
                "name": "Retail",
                "attribution_scope": "confirmed",
                "first_seen": "2019-10-10T19:28:10.000Z",
                "last_seen": "2022-01-27T00:00:00.000Z",
            },
            {
                "id": "identity--02142d73-54af-5e18-a4f5-70b194ca002b",
                "name": "Technology",
                "attribution_scope": "confirmed",
                "first_seen": "2016-07-16T13:18:47.000Z",
                "last_seen": "2021-02-04T22:57:41.000Z",
            },
            {
                "id": "identity--93209517-b16c-5893-b55e-b7edc9b478d0",
                "name": "Telecommunications",
                "attribution_scope": "confirmed",
                "first_seen": "2018-09-27T19:49:52.000Z",
                "last_seen": "2021-09-16T08:36:04.000Z",
            },
            {
                "id": "identity--8768c9d0-830d-5c94-88d1-1506fef6c838",
                "name": "Transportation",
                "attribution_scope": "confirmed",
                "first_seen": "2019-10-10T19:28:10.000Z",
                "last_seen": "2021-07-29T00:00:00.000Z",
            },
        ],
        "observed": [
            {
                "earliest": "2011-01-29T00:00:00.000Z",
                "recent": "2015-03-12T00:00:00.000Z",
                "attribution_scope": "suspected",
            },
            {
                "earliest": "2020-04-07T10:02:36.000Z",
                "recent": "2021-08-26T15:00:34.000Z",
                "attribution_scope": "possible",
            },
            {
                "earliest": "2002-11-17T00:00:00.000Z",
                "recent": "2022-08-11T14:29:04.000Z",
                "attribution_scope": "confirmed",
            },
        ],
        "malware": [
            {
                "id": "malware--0e538ca1-3abc-5580-83c2-4612ecb8ec9a",
                "name": "BABYDUKE",
                "attribution_scope": "confirmed",
                "first_seen": "2014-06-05T12:06:33.000Z",
                "last_seen": "2014-08-28T01:38:11.000Z",
            },
            {
                "id": "malware--448e822d-8496-5021-88cb-599062f74176",
                "name": "BEACON",
                "attribution_scope": "confirmed",
                "first_seen": "2020-06-24T13:06:21.000Z",
                "last_seen": "2022-01-18T16:49:42.000Z",
            },
            {
                "id": "malware--81b6c216-1690-5733-a063-ff074e641709",
                "name": "BEATDROP",
                "attribution_scope": "confirmed",
                "first_seen": "2022-01-17T12:24:26.000Z",
                "last_seen": "2022-01-25T12:34:40.000Z",
            },
            {
                "id": "malware--8ce80eb5-0e00-5766-84f7-d6370290717e",
                "name": "BOOMMIC",
                "attribution_scope": "confirmed",
                "first_seen": "2022-01-18T14:03:09.000Z",
                "last_seen": "2022-01-18T15:29:05.000Z",
            },
            {
                "id": "malware--d6aafc1a-b026-563d-ba75-fb63ccb4477f",
                "name": "CARWRECK",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--29f1ecf0-3de8-5a6a-9321-ace9ee9a33e9",
                "name": "CEELOADER",
                "attribution_scope": "confirmed",
                "first_seen": "2017-02-08T14:40:22.000Z",
                "last_seen": "2021-08-17T16:33:14.000Z",
            },
            {
                "id": "malware--674dd39b-12f4-585d-a198-3c61bc85f8c0",
                "name": "CHAINLNK",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--f4dd812f-58b6-5458-af39-409c5df36319",
                "name": "COZYCAR",
                "attribution_scope": "confirmed",
                "first_seen": "2014-08-12T09:48:00.000Z",
                "last_seen": "2014-08-12T11:13:08.000Z",
            },
            {
                "id": "malware--1d33286f-8ca6-5432-a756-b7c7f3d41dd0",
                "name": "CRASHDUMMY",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--02176060-4e76-5ad9-bcb0-83a018d1a283",
                "name": "CRIMSONBOX",
                "attribution_scope": "confirmed",
                "first_seen": "2020-09-17T18:32:07.000Z",
                "last_seen": "2020-09-17T18:32:07.000Z",
            },
            {
                "id": "malware--3b2988ea-a50e-5091-978c-bf58818a5229",
                "name": "CROOKEDROOK",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--b728b2eb-d5f4-5a99-88d3-de5de4c3e27b",
                "name": "DAVESHELL",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--c979be39-5da1-5421-9ed0-36d62236046a",
                "name": "FLATTOP",
                "attribution_scope": "confirmed",
                "first_seen": "2016-08-16T13:39:26.000Z",
                "last_seen": "2016-08-16T14:32:31.000Z",
            },
            {
                "id": "malware--7348f904-f00f-59fd-b7e0-9bb2ea937f0b",
                "name": "FOGGYKEY",
                "attribution_scope": "possible",
            },
            {
                "id": "malware--39154d89-bbd5-5834-a364-7732303568f9",
                "name": "GREEDYHEIR",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--6cd697cd-43d2-5e56-8432-372b23420388",
                "name": "GSSBOT",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--d7b72cf6-c413-59e1-9bb2-e06c861bded4",
                "name": "HAMMERTOSS",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--b0e965fb-1737-5c63-85c7-e90a323b1e27",
                "name": "HTRAN",
                "attribution_scope": "confirmed",
                "first_seen": "2014-08-11T08:35:40.000Z",
                "last_seen": "2016-06-02T15:44:12.000Z",
            },
            {
                "id": "malware--bdf583a4-60a8-5dd0-b184-c30a62f6dcc2",
                "name": "ICEBREAKER",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--c8a2bee7-35fc-565c-9c0b-5c87fdcb2815",
                "name": "KINGCRAB",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--cbb4818d-53e8-5826-baf0-91fc01c5e0b4",
                "name": "KINGPRAWN",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--e93a6526-c471-5e8a-a8e4-2bb202488d27",
                "name": "LINKSHELL",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--15cb3780-b840-5efc-b9cb-3b86a28367a9",
                "name": "LOUDGUEST",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--039a0d4a-6fed-546c-a9df-a312e512bbf5",
                "name": "MAMADOGS",
                "attribution_scope": "confirmed",
                "first_seen": "2020-05-29T11:25:55.000Z",
                "last_seen": "2020-05-29T14:19:31.000Z",
            },
            {
                "id": "malware--1665bbb9-a601-5cb2-b723-cecd230e0659",
                "name": "MINIDIONIS",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-01T00:00:00.000Z",
                "last_seen": "2015-07-21T17:03:03.000Z",
            },
            {
                "id": "malware--06f475b3-d8c2-5a08-b80d-8e0e3c13a75d",
                "name": "MINIDUKE",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--fd6309a1-44fe-5085-a091-d2ff88b01a27",
                "name": "NOSEDIVE",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--c344318c-36db-5f6b-b193-9c59df74cca7",
                "name": "ONIONDUKE",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--a027c53b-4940-5021-b3df-5a8f7eccf6fc",
                "name": "PASTQUEEN",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--52f7afd9-e657-52ac-93a7-c8eff2fdc77a",
                "name": "POSHSPY",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--3188e217-433f-5920-8695-ddf25955cf25",
                "name": "QUEENBEE",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--795f28df-dace-5716-82e2-6f735d1e68ea",
                "name": "QUEENPIECE",
                "attribution_scope": "confirmed",
                "first_seen": "2014-06-05T12:06:33.000Z",
                "last_seen": "2014-06-11T14:07:52.000Z",
            },
            {
                "id": "malware--4b6ff91f-0171-52ac-aac9-5d0ff369cdc5",
                "name": "QUIETEXIT",
                "attribution_scope": "confirmed",
                "first_seen": "2019-12-21T00:00:52.000Z",
                "last_seen": "2022-01-17T19:59:11.000Z",
            },
            {
                "id": "malware--5013252b-fa46-5698-a22c-1be309238ba5",
                "name": "RAINDROP",
                "attribution_scope": "confirmed",
                "first_seen": "2016-07-16T13:18:47.000Z",
                "last_seen": "2020-12-24T20:20:27.000Z",
            },
            {
                "id": "malware--33065e77-067e-5554-a325-86f0e95968dc",
                "name": "REGEORG",
                "attribution_scope": "confirmed",
                "first_seen": "2020-07-14T13:58:39.000Z",
                "last_seen": "2021-02-13T12:59:21.000Z",
            },
            {
                "id": "malware--684b0b84-4e04-517c-ae2c-eaf14193e392",
                "name": "REMCOM",
                "attribution_scope": "confirmed",
                "first_seen": "2014-08-01T13:10:03.000Z",
                "last_seen": "2014-08-01T13:10:03.000Z",
            },
            {
                "id": "malware--9bc0786c-b2c1-5250-9e1f-cbffaef5524f",
                "name": "ROOTSAW",
                "attribution_scope": "confirmed",
                "first_seen": "2021-04-22T15:32:39.000Z",
                "last_seen": "2022-06-30T15:29:04.000Z",
            },
            {
                "id": "malware--36123d95-7c63-515d-adf5-7e2f54a4bd9f",
                "name": "ROYALCOURT",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--633c7859-cf91-5d15-a33d-0ba63a1d0b0c",
                "name": "SALTSHAKER",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--3eaeb7ec-8001-5a2d-84e9-02b70234b68c",
                "name": "SAYWHAT",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--9ec804f7-cbb7-5e79-9d42-d2e3bd44bbb8",
                "name": "SEADADDY",
                "attribution_scope": "confirmed",
                "first_seen": "2014-07-29T10:29:26.000Z",
                "last_seen": "2015-08-12T11:11:24.000Z",
            },
            {
                "id": "malware--1ac81840-5592-5354-b3d4-f24e2a3c643d",
                "name": "SEVENMINUS",
                "attribution_scope": "possible",
            },
            {
                "id": "malware--54f0093d-baa0-5461-ba56-74e50ad6f911",
                "name": "SICKINVITE",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--00328b1e-3a1e-56b2-b9ba-83e08813415d",
                "name": "SIXPLUS",
                "attribution_scope": "possible",
                "first_seen": "2020-04-16T16:57:03.000Z",
                "last_seen": "2020-04-19T16:47:01.000Z",
            },
            {
                "id": "malware--6ee30fbe-3bb4-5cc2-b38e-8b99381c62fb",
                "name": "SMALLBULB",
                "attribution_scope": "suspected",
            },
            {
                "id": "malware--3edafaf6-11fd-58c7-892b-e52ca019a309",
                "name": "SPIKERUSH",
                "attribution_scope": "confirmed",
                "first_seen": "2016-08-30T15:19:36.000Z",
                "last_seen": "2016-10-14T01:03:09.000Z",
            },
            {
                "id": "malware--4d299cfd-ffd7-5e46-b30c-cc88ac5a57c1",
                "name": "SUNBURST",
                "attribution_scope": "confirmed",
                "first_seen": "2019-10-10T15:28:10.000Z",
                "last_seen": "2021-11-11T16:18:41.000Z",
            },
            {
                "id": "malware--fe962d3c-6a16-561f-811d-76398556e16d",
                "name": "SUNSHUTTLE",
                "attribution_scope": "confirmed",
                "first_seen": "2019-11-19T08:17:10.000Z",
                "last_seen": "2021-08-20T14:19:10.000Z",
            },
            {
                "id": "malware--5d79a161-10eb-5ad3-a13d-ac2b456499f8",
                "name": "SWIFTKICK",
                "attribution_scope": "confirmed",
                "first_seen": "2015-07-07T14:30:37.000Z",
                "last_seen": "2015-07-09T11:29:55.000Z",
            },
            {
                "id": "malware--75bfd96f-bf08-5aab-b54f-7c94dd547cb8",
                "name": "TADPOLE",
                "attribution_scope": "confirmed",
                "first_seen": "2016-08-10T15:12:22.000Z",
                "last_seen": "2016-08-10T16:10:11.000Z",
            },
            {
                "id": "malware--3baa3d65-a3fe-5284-a3ab-8007fff7fe78",
                "name": "TEARDROP",
                "attribution_scope": "confirmed",
                "first_seen": "2020-06-01T10:13:54.000Z",
                "last_seen": "2020-08-31T09:26:59.000Z",
            },
            {
                "id": "malware--545e4107-0c07-57ee-9757-fd8fd6d1f5fd",
                "name": "VERNALDROP",
                "attribution_scope": "confirmed",
                "first_seen": "2016-08-10T15:12:22.000Z",
                "last_seen": "2016-08-25T14:15:27.000Z",
            },
            {
                "id": "malware--9e650610-c8ce-5889-a219-8ce51c22e99b",
                "name": "ZOOTSUIT",
                "attribution_scope": "possible",
            },
        ],
        "tools": [
            {
                "id": "malware--fee46624-b54f-521a-8cbd-3f84a0c10e23",
                "name": "BITVISE",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--4fb0b16d-53d6-56e5-975f-10458225f317",
                "name": "COBALTSTRIKE",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--777576be-814f-5c51-8af5-e18a3adc86f3",
                "name": "PSCP",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--bd261c86-ce9f-50ec-89a7-aec768a70dd9",
                "name": "ADFIND",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--188eea74-6a07-55f2-b73f-6a109121a940",
                "name": "SHOVIV",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--125d583e-0617-5192-bc27-9f3377bb98c3",
                "name": "WINRAR",
                "attribution_scope": "possible",
            },
            {
                "id": "malware--7b17a6c3-b71c-53ee-9c05-5af3bed0265d",
                "name": "PSKILL",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--778e06b6-ab96-53d6-a759-41650db7b2eb",
                "name": "PORTQRY",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--b2bb2d97-675e-5023-9cdd-a4274893b4a7",
                "name": "SFXRAR",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--9d2690f2-35ac-5776-9e2d-72da1618bb67",
                "name": "PSLOGGEDON",
                "attribution_scope": "possible",
            },
            {
                "id": "malware--fed3481f-0095-53f2-8c32-7e286013233b",
                "name": "DSQUERY",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--76dd491b-1e9d-5b83-b727-455609de7ed0",
                "name": "RUBEUS",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--e224f74a-ca0e-540b-884f-03753787316f",
                "name": "NLTEST",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--934dcadf-f9a8-52c1-9c90-353a1c3144d5",
                "name": "PSEXEC",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--f5a8a4cc-c312-5829-871a-0446a670d98e",
                "name": "RCLONE",
                "attribution_scope": "possible",
            },
            {
                "id": "malware--cb6874ee-49ae-5909-ac1f-0caf9fadadda",
                "name": "IMPACKET.WMIEXEC",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--5c2bfbf2-44a7-50f1-b20e-e7d2efb4baa0",
                "name": "AADINTERNALS",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--666abf8a-4b7e-51e4-8991-014a95d45ef4",
                "name": "WEXTRACT",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--f872b3e0-c277-5716-baae-885a9c410398",
                "name": "WHOAMI",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--47530422-6b2d-5329-95c1-fcf7698edeee",
                "name": "7ZIP",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--5d383d23-028b-5f12-b55c-e1464669074c",
                "name": "POWERSPLOIT",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--405817d8-a607-5231-a5f1-e0d1cb4226df",
                "name": "AADCONNECT",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--f7b14ce3-c453-5dab-a1bd-0a5f5b673866",
                "name": "GIT",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--0c7945de-0968-55e3-ad4e-1600ddfc6b36",
                "name": "PROCDUMP",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--5fcb13d7-0fc1-55e7-9ab4-6e8400bffb2a",
                "name": "TOR",
                "attribution_scope": "confirmed",
            },
            {
                "id": "malware--bf2fc1e5-7850-5ecd-87a7-263e6da5708d",
                "name": "MIMIKATZ",
                "attribution_scope": "confirmed",
            },
        ],
        "locations": {
            "source": [
                {
                    "region": {
                        "id": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                        "name": "Europe",
                        "attribution_scope": "confirmed",
                    },
                    "sub_region": {
                        "id": "location--57644af5-a064-5e14-be58-05b22d2768be",
                        "name": "East Europe",
                        "attribution_scope": "confirmed",
                    },
                    "country": {
                        "id": "location--188145fd-6fd1-5bd6-a70c-8e33ed149584",
                        "name": "Russia",
                        "iso2": "RU",
                        "attribution_scope": "confirmed",
                    },
                }
            ],
            "target": [
                {
                    "id": "location--87f90bb2-973b-596e-9131-d2a2b4e1e424",
                    "name": "Albania",
                    "iso2": "AL",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "South Europe",
                },
                {
                    "id": "location--27a1d59f-56ec-5da4-963c-ce1f9c6c0402",
                    "name": "Australia",
                    "iso2": "AU",
                    "region": "Oceania",
                    "attribution_scope": "confirmed",
                    "sub-region": "Australia and New Zealand",
                },
                {
                    "id": "location--826ca4ac-8555-5c47-b794-55d00fe0ddde",
                    "name": "Austria",
                    "iso2": "AT",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Europe",
                },
                {
                    "id": "location--a509dfc8-789b-595b-a201-29c7af1dc0bb",
                    "name": "Belgium",
                    "iso2": "BE",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Europe",
                },
                {
                    "id": "location--fde14246-c07b-5f3f-9ac8-8d4d50910f15",
                    "name": "Canada",
                    "iso2": "CA",
                    "region": "Americas",
                    "attribution_scope": "confirmed",
                    "sub-region": "North America",
                },
                {
                    "id": "location--d6f7955e-1887-5e6c-aed2-e8ec5f9a1436",
                    "name": "Croatia",
                    "iso2": "HR",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "South Europe",
                },
                {
                    "id": "location--b1f13d3f-b956-511a-a8f4-1b89d1e8ed4a",
                    "name": "Denmark",
                    "iso2": "DK",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "North Europe",
                },
                {
                    "id": "location--48b6c887-9123-53a0-9f33-92194a8c5850",
                    "name": "Estonia",
                    "iso2": "EE",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "North Europe",
                },
                {
                    "id": "location--339d906b-89a6-5807-bfe8-0cd8bb32b10c",
                    "name": "France",
                    "iso2": "FR",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Europe",
                },
                {
                    "id": "location--0342c53c-190f-5cff-b39d-e20cd2608d65",
                    "name": "Georgia",
                    "iso2": "GE",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Asia",
                },
                {
                    "id": "location--a0662aac-87ac-53a8-b3a9-7a8ee72f8059",
                    "name": "Germany",
                    "iso2": "DE",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Europe",
                },
                {
                    "id": "location--f7ff6ed1-f6f6-5f4b-b085-6174315521a1",
                    "name": "Hong Kong",
                    "iso2": "HK",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "East Asia",
                },
                {
                    "id": "location--ddf9cac3-4310-5b20-abd7-6bdd7a010ef4",
                    "name": "Hungary",
                    "iso2": "HU",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "East Europe",
                },
                {
                    "id": "location--1543356e-c02c-52c3-a571-e6c44d34f35a",
                    "name": "Ireland",
                    "iso2": "IE",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "North Europe",
                },
                {
                    "id": "location--2695d13c-64c9-544b-9804-a951b9331252",
                    "name": "Israel",
                    "iso2": "IL",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Asia",
                },
                {
                    "id": "location--484d0c02-5e35-59f5-b308-99ebffd9adcd",
                    "name": "Italy",
                    "iso2": "IT",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "South Europe",
                },
                {
                    "id": "location--8309810a-48ea-58ae-8d57-04080bc634d6",
                    "name": "Jordan",
                    "iso2": "JO",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Asia",
                },
                {
                    "id": "location--dce9cb57-4cce-5288-94ed-6910167e3910",
                    "name": "Latvia",
                    "iso2": "LV",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "North Europe",
                },
                {
                    "id": "location--99bc8abc-8306-56a8-9ac1-217f4de4f8a6",
                    "name": "Liechtenstein",
                    "iso2": "LI",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Europe",
                },
                {
                    "id": "location--f3ad40a3-e452-52bc-9541-49ab64fe9734",
                    "name": "Macedonia",
                    "iso2": "MK",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "South Europe",
                },
                {
                    "id": "location--6c024343-c218-5432-8a12-f0c81063fe0c",
                    "name": "Netherlands",
                    "iso2": "NL",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Europe",
                },
                {
                    "id": "location--6e754937-5110-521c-bcc9-ac1ffb42ba0d",
                    "name": "New Zealand",
                    "iso2": "NZ",
                    "region": "Oceania",
                    "attribution_scope": "confirmed",
                    "sub-region": "Australia and New Zealand",
                },
                {
                    "id": "location--77afbac1-8250-5f6d-9586-0cedcc138eb1",
                    "name": "Norway",
                    "iso2": "NO",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "North Europe",
                },
                {
                    "id": "location--86d78cd7-6571-59e3-ae8d-5f5ed95c4685",
                    "name": "Philippines",
                    "iso2": "PH",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "South East Asia",
                },
                {
                    "id": "location--3f3a8e8f-248f-56d0-be34-8052ea441f62",
                    "name": "Poland",
                    "iso2": "PL",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "East Europe",
                },
                {
                    "id": "location--72f0758a-5a47-535f-a138-6ed31de50ae3",
                    "name": "Portugal",
                    "iso2": "PT",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "South Europe",
                },
                {
                    "id": "location--66ef0e72-11dd-5e36-ba9d-178ad16f8d53",
                    "name": "Qatar",
                    "iso2": "QA",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Asia",
                },
                {
                    "id": "location--76146154-586b-5821-ae92-2a442a7a5c1e",
                    "name": "Saudi Arabia",
                    "iso2": "SA",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Asia",
                },
                {
                    "id": "location--00ab0ba1-a1d2-56b9-a039-73c9e2e4cb4f",
                    "name": "Singapore",
                    "iso2": "SG",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "South East Asia",
                },
                {
                    "id": "location--9ca4bff3-2cfc-5401-80bf-4eebf0717455",
                    "name": "South Africa",
                    "iso2": "ZA",
                    "region": "Africa",
                    "attribution_scope": "confirmed",
                    "sub-region": "South Africa",
                },
                {
                    "id": "location--e4dfef14-268e-5eb6-a9da-ba4d044ffc96",
                    "name": "Spain",
                    "iso2": "ES",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "South Europe",
                },
                {
                    "id": "location--05f7f948-55eb-5994-9003-c5e44ccf3ba9",
                    "name": "Sweden",
                    "iso2": "SE",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "North Europe",
                },
                {
                    "id": "location--daeba678-894d-59fe-a00c-f1aec473c62f",
                    "name": "Switzerland",
                    "iso2": "CH",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Europe",
                },
                {
                    "id": "location--1228220c-7de8-5dc6-94bf-98b2fa79bb7f",
                    "name": "Ukraine",
                    "iso2": "UA",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "East Europe",
                },
                {
                    "id": "location--322cae79-a217-5c63-8005-de217f336e6b",
                    "name": "United Arab Emirates",
                    "iso2": "AE",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                    "sub-region": "West Asia",
                },
                {
                    "id": "location--f66d95f4-10dc-55f9-a444-81dc49fcf238",
                    "name": "United Kingdom",
                    "iso2": "GB",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                    "sub-region": "North Europe",
                },
                {
                    "id": "location--5c5b39aa-9308-52a6-9daf-0547d5aaa160",
                    "name": "United States of America",
                    "iso2": "US",
                    "region": "Americas",
                    "attribution_scope": "confirmed",
                    "sub-region": "North America",
                },
            ],
            "target_sub_region": [
                {
                    "id": "location--cdf44f32-c648-5661-be2b-58fbd1479d05",
                    "name": "Australia and New Zealand",
                    "key": "australiaandnewzealand",
                    "region": "Oceania",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--7b33370b-da4b-5c48-9741-b69f69febb77",
                    "name": "East Asia",
                    "key": "eastasia",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--57644af5-a064-5e14-be58-05b22d2768be",
                    "name": "East Europe",
                    "key": "easteurope",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--0daadcfb-ad23-5f16-b53b-6c5b09bf20de",
                    "name": "North America",
                    "key": "northamerica",
                    "region": "Americas",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--07071b1c-a0fb-56e7-9619-11397860bd4c",
                    "name": "North Europe",
                    "key": "northeurope",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--9ca4bff3-2cfc-5401-80bf-4eebf0717455",
                    "name": "South Africa",
                    "key": "southafrica",
                    "region": "Africa",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--afcfcb4e-cd47-5c76-91e7-d52cb7d922f0",
                    "name": "South East Asia",
                    "key": "southeastasia",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--51df1368-64cc-59a8-bdec-1add9b59d232",
                    "name": "South Europe",
                    "key": "southeurope",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--68cdd130-61d1-5b6b-a3d8-560810432d8e",
                    "name": "West Asia",
                    "key": "westasia",
                    "region": "Asia",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--34b867a9-0a6c-5559-bd8a-08edbf5287c4",
                    "name": "West Europe",
                    "key": "westeurope",
                    "region": "Europe",
                    "attribution_scope": "confirmed",
                },
            ],
            "target_region": [
                {
                    "id": "location--9488166d-6469-5e54-ba5f-9abf2a385824",
                    "name": "Africa",
                    "key": "africa",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--6d65522f-0166-5e7e-973c-35cf7973e4e3",
                    "name": "Americas",
                    "key": "americas",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--8fc231f3-4e62-57e7-b734-eaee0a734612",
                    "name": "Asia",
                    "key": "asia",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--89b58fc6-de5e-55e4-9d8c-29ba659e770f",
                    "name": "Europe",
                    "key": "europe",
                    "attribution_scope": "confirmed",
                },
                {
                    "id": "location--08d5ce25-021e-5dcf-8b1b-52483dfe1589",
                    "name": "Oceania",
                    "key": "oceania",
                    "attribution_scope": "confirmed",
                },
            ],
        },
        "cve": [
            {
                "id": "vulnerability--033082b3-ae89-53f0-9f13-9cad3e2bbee1",
                "cve_id": "CVE-2013-0641",
                "attribution_scope": "suspected",
            },
            {
                "id": "vulnerability--1a869fc9-5449-5108-a710-b1220c881940",
                "cve_id": "CVE-2013-0640",
                "attribution_scope": "suspected",
            },
            {
                "id": "vulnerability--a96c30fc-0ca4-5d4a-95aa-416346357ec6",
                "cve_id": "CVE-2013-0632",
                "attribution_scope": "confirmed",
            },
            {
                "id": "vulnerability--f1ff751a-6302-52ac-b910-c138e3f77fd9",
                "cve_id": "CVE-2011-0611",
                "attribution_scope": "suspected",
            },
        ],
        "last_activity_time": "2022-08-11T14:29:04.000Z",
        "suspected_attribution": [],
        "associated_uncs": [
            {
                "id": "threat-actor--99391985-6432-54bf-8660-80987a50070d",
                "name": "UNC122",
                "attribution_scope": "suspected",
            },
            {
                "id": "threat-actor--4e535153-f13e-59fd-a192-f219c6d7f2a0",
                "name": "UNC497",
                "attribution_scope": "suspected",
            },
            {
                "id": "threat-actor--daae8aa0-9131-5cbf-8f81-d523aee1ff06",
                "name": "UNC2062",
                "attribution_scope": "possible",
            },
            {
                "id": "threat-actor--a57eb78a-620f-548c-aa5d-f2b7863c096e",
                "name": "UNC2506",
                "attribution_scope": "possible",
            },
            {
                "id": "threat-actor--99e188f3-83d7-586a-81e5-5b8e652516e8",
                "name": "UNC2507",
                "attribution_scope": "possible",
            },
            {
                "id": "threat-actor--5b6e4fd6-f265-565b-93b9-e8bf34d4ebb0",
                "name": "UNC2598",
                "attribution_scope": "suspected",
            },
            {
                "id": "threat-actor--2f3e43cb-0eb5-520d-8912-a312d7c7c561",
                "name": "UNC2676",
                "attribution_scope": "suspected",
            },
            {
                "id": "threat-actor--aa7369ab-141f-5cc8-b7d6-2fc387cd7c3e",
                "name": "UNC4146",
                "attribution_scope": "possible",
            },
            {
                "id": "threat-actor--21e48808-3556-5572-8fa8-f1474a3773a2",
                "name": "UNC4242",
                "attribution_scope": "possible",
            },
        ],
        "is_publishable": True,
        "intel_free": False,
    }

    client = mock_client()

    mocker.patch.object(client, "_http_request", return_value=raw_response)

    res = ThreatIntelligence.fetch_threat_actor(client, {"actor_name": "A310LOGGER"})

    indicator = res.outputs[0]

    assert indicator["type"] == "Threat Actor"
    assert len(indicator["relationships"]) == 92
