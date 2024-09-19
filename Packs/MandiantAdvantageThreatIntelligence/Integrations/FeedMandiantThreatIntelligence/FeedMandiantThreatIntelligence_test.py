import FeedMandiantThreatIntelligence
import pytest

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import


MOCK_IP_INDICATOR = {
    "id": "ipv4--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "ipv4",
    "value": "1.2.3.4",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 100
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_DOMAIN_INDICATOR = {
    "id": "fqdn--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "fqdn",
    "value": "domain.test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 10
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_URL_INDICATOR = {
    "id": "url--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "url",
    "value": "https://domain.test/test",
    "is_exclusive": True,
    "is_publishable": True,
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 25
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_FILE_INDICATOR = {
    "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
    "mscore": 100,
    "type": "md5",
    "value": "ae1747c930e9e4f45fbc970a83b52284",
    "is_exclusive": True,
    "is_publishable": True,
    "associated_hashes": [
        {
            "id": "md5--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "md5",
            "value": "ae1747c930e9e4f45fbc970a83b52284"
        },
        {
            "id": "sha1--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha1",
            "value": "638cde28bbe3cfe7b53aa75a7cf6991baa692a4a"
        },
        {
            "id": "sha256--1526529a-8489-55f5-a2f1-603ec2576f6c",
            "type": "sha256",
            "value": "f68ec69a53130a24b0fe53d1d1fe70992d86a6d67006ae45f986f9ef4f450b6c"
        }
    ],
    "sources": [
        {
            "first_seen": "2024-06-08T00:13:46.000+0000",
            "last_seen": "2024-06-09T00:14:03.000+0000",
            "osint": False,
            "category": [],
            "source_name": "Mandiant"
        },
        {
            "first_seen": "2024-06-07T20:30:44.000+0000",
            "last_seen": "2024-06-07T20:30:57.000+0000",
            "osint": False,
            "category": ["control-server"],
            "source_name": "Mandiant"
        }
    ],
    "attributed_associations": [
        {
            "id": "threat-actor--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "ACTOR_NAME",
            "type": "threat-actor"
        },
        {
            "id": "malware--99941acb-6bd7-5f27-8f97-2520f5976fb5",
            "name": "MALWARE_NAME",
            "type": "malware"
        }
    ],
    "threat_rating": {
        "confidence_level": "high",
        "confidence_score": 100,
        "severity_level": "high",
        "severity_reason": [
            "attributed"
        ],
        "threat_score": 25
    },
    "last_updated": "2024-06-09T17:00:26.225Z",
    "first_seen": "2024-06-07T20:30:44.000Z",
    "last_seen": "2024-06-09T00:14:03.000Z",
    "reports": [
        {
            "report_id": "REPORT_ID",
            "type": "REPORT_TYPE",
            "title": "REPORT_TITLE",
            "published_date": "2024-05-31T12:00:53.000Z"
        }
    ],
    "campaigns": [
        {
            "id": "campaign--eda94045-0c6b-5926-8e44-dcb81d538c04",
            "name": "CAMP.123",
            "title": "CAMPAIGN_TITLE"
        }
    ]
}

MOCK_INDICATORS = {
    "indicators": [
        MOCK_IP_INDICATOR,
        MOCK_DOMAIN_INDICATOR,
        MOCK_FILE_INDICATOR,
        MOCK_URL_INDICATOR
    ]
}


@pytest.fixture
def config():
    """Fixture to provide a mock configuration."""
    return {
        "api_key": "test_api_key",
        "secret_key": "test_secret_key",
        "timeout": 60,
        "page_size": 1000,
        "tlp_color": "RED",
        "feedTags": ["tag1", "tag2"],
        "feedReliability": "A - Completely reliable",
        "feedMinimumThreatScore": 80,
        "feedExcludeOSIntel": True,
        "first_fetch": 7
    }


@pytest.fixture
def client(config):
    """Fixture to create a MandiantClient instance with mock config."""
    return FeedMandiantThreatIntelligence.MandiantClient(config)


@pytest.fixture
def mock_http_request(mocker):
    """Fixture to mock the _http_request method."""
    return mocker.patch.object(FeedMandiantThreatIntelligence.MandiantClient, "_http_request", autospec=True)


def test_mandiant_client_init(client, config):
    """Test that the client is initialized correctly."""
    assert client.api_key == config["api_key"]
    assert client.secret_key == config["secret_key"]
    assert client.timeout == config["timeout"]
    assert client.tlp_color == config["tlp_color"]
    assert client.feed_tags == config["feedTags"]
    assert client.reliability == config["feedReliability"]
    assert client.minimum_threat_score == config["feedMinimumThreatScore"]
    assert client.exclude_osint == config["feedExcludeOSIntel"]
    assert client.first_fetch == config["first_fetch"]


def test_get_entitlements(client, mock_http_request):
    """Test getting entitlements."""
    mock_response = {"entitlements": ["Entitlement1"]}
    mock_http_request.return_value = mock_response

    response = client.get_entitlements()
    assert response == mock_response
    assert mock_http_request.call_count == 1


def test_yield_indicators(client, mock_http_request):
    """Test the yield_indicators generator."""
    # Mock multiple API responses with pagination
    mock_responses = [
        {"indicators": [{"id": 1}, {"id": 2}], "next": "page2"},
        {"indicators": [{"id": 3}]},  # No next page
    ]
    mock_http_request.side_effect = mock_responses

    # Iterate over the generator and check the results
    all_indicators = []
    for i in client.yield_indicators(0, 100, 2, 80):
        all_indicators.append(i)
    assert all_indicators == [{"id": 1}, {"id": 2}, {"id": 3}]

    # Ensure _http_request is called with the correct parameters and pagination
    assert mock_http_request.call_count == 2


@pytest.mark.parametrize(
    "indicator, expected_result",
    [
        ({"sources": [{"source_name": "Source1"}]}, True),
        ({"sources": [{"source_name": "Source1"}, {"source_name": "Source2"}]}, True),
        ({"sources": [{"source_name": "Mandiant"}]}, False),
        ({"sources": [{"source_name": "Mandiant"}, {"source_name": "OSINT Blog"}]}, False),
        ({"sources": []}, True),  # No sources, considered OSINT
        ({}, True),  # Empty indicator, considered OSINT
    ],
)
def test_is_osint(indicator, expected_result):
    result = FeedMandiantThreatIntelligence.is_osint(indicator)
    assert result == expected_result


@pytest.mark.parametrize(
    "indicator, expected_result",
    [
        ({"threat_rating": {"threat_score": 100}}, 100),
        ({"threat_rating": {}}, 0),
        ({}, 0),
        ({"threat_rating": {"threat_score": "high"}}, 0)
    ],
)
def test_get_threat_score(indicator, expected_result):
    result = FeedMandiantThreatIntelligence.get_threat_score(indicator)
    assert result == expected_result


@pytest.mark.parametrize(
    "indicator, exclude_osint, min_threat_score, expected",
    [
        # Test cases
        ({"sources": [{"source_name": "source1"}], "threat_rating": {"threat_score": 80}}, False, 75, True),
        ({"sources": [{"source_name": "source1"}], "threat_rating": {"threat_score": 60}}, False, 75, False),
        ({"sources": [{"source_name": "osint_source"}], "threat_rating": {"threat_score": 90}}, True, 75, False),
        ({"sources": [{"source_name": "Mandiant"}], "threat_rating": {"threat_score": 80}}, True, 75, True),
        ({"sources": [{"source_name": "source1"}]}, False, 75, False),
    ],
)
def test_include_in_feed(indicator, exclude_osint, min_threat_score, expected):
    result = FeedMandiantThreatIntelligence.include_in_feed(indicator, exclude_osint, min_threat_score)
    assert result == expected


@pytest.mark.parametrize(
    "indicator, hash_type, expected_hash_value",
    [
        (
            {"associated_hashes": [{"type": "md5", "value": "abcdef123"}]},
            "md5",
            "abcdef123",
        ),
        (
            {"associated_hashes": [{"type": "sha256", "value": ""}]},
            "sha256",
            "",
        ),
        (
            {"associated_hashes": [{"type": "sha1", "value": "zyx987"}]},
            "md5",
            "",
        ),
        ({"associated_hashes": []}, "md5", ""),
        ({}, "md5", ""),
    ],
)
def test_get_hash_value(indicator, hash_type, expected_hash_value):
    assert FeedMandiantThreatIntelligence.get_hash_value(indicator, hash_type) == expected_hash_value


@pytest.mark.parametrize(
    "sources, expected_categories",
    [
        ([], []),  # Empty input
        ([{"name": "source1"}], []),  # No category
        ([{"name": "source2", "category": ["A"]}], ["a"]),  # Single category
        ([{"name": "source3", "category": ["A", "B"]}], ["a", "b"]),  # Multiple categories
        (
            [
                {"name": "source4", "category": ["A", "B"]},
                {"name": "source5", "category": ["B", "C"]},
            ],
            ["a", "b", "c"],
        ),  # Overlapping categories
        (
            [
                {"name": "source4", "category": ["A", "B"]},
                {"name": "source5", "category": ["b", "C"]},
            ],
            ["a", "b", "c"],
        ),  # Overlapping categories with lower and upper case
    ],
)
def test_get_categories(sources, expected_categories):
    result = FeedMandiantThreatIntelligence.get_categories(sources)
    assert sorted(result) == sorted(expected_categories)


@pytest.mark.parametrize(
    "value_, indicator, expected_relationships",
    [
        # Threat Actor Relationship Test
        (
            "1.2.3.4",
            {"type": "IP", "attributed_associations": [{"type": "threat-actor", "name": "APT29"}]},
            [
                EntityRelationship(
                    name="uses",
                    reverse_name="used-by",
                    entity_a="1.2.3.4",
                    entity_a_type="IP",
                    entity_b="APT29",
                    entity_b_type="Threat Actor",
                ).to_indicator()
            ],
        ),
        # Malware Relationship Test
        (
            "evil.com",
            {"type": "Domain", "attributed_associations": [{"type": "malware", "name": "TrickBot"}]},
            [
                EntityRelationship(
                    name="indicates",
                    reverse_name="indicated-by",
                    entity_a="evil.com",
                    entity_a_type="Domain",
                    entity_b="TrickBot",
                    entity_b_type="Malware",
                ).to_indicator()
            ],
        ),
        # Campaign Relationship Test
        (
            "phishing.site",
            {"type": "URL", "campaigns": [{"title": "Phishing Campaign X", "name": "campaign-x"}]},
            [
                EntityRelationship(
                    name="indicates",
                    reverse_name="indicated-by",
                    entity_a="phishing.site",
                    entity_a_type="URL",
                    entity_b="Phishing Campaign X (campaign-x)",
                    entity_b_type="Campaign",
                ).to_indicator()
            ],
        ),
        # No Relationships Test
        ("asdf", {"type": "File"}, []),  # Empty indicator
    ],
)
def test_build_indicator_relationships(value_, indicator, expected_relationships):
    relationships = FeedMandiantThreatIntelligence.build_indicator_relationships(value_, indicator)
    assert relationships == expected_relationships


def test_fetch_indicators_command(client, mock_http_request):
    mock_http_request.return_value = MOCK_INDICATORS
    processed, skipped, ingested = FeedMandiantThreatIntelligence.fetch_indicators_command(client)
    assert processed == 4
    assert skipped == 3
    assert ingested == 1


def test_test_module(client, mock_http_request):
    mock_response = {"entitlements": ["Entitlement1"]}
    mock_http_request.return_value = mock_response

    result = FeedMandiantThreatIntelligence.test_module(client)

    assert result == "ok"
