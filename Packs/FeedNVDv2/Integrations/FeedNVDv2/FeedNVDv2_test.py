import json
import ast
import pytest
from FeedNVDv2 import parse_cpe_command, retrieve_cves, build_indicators, Client
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


BASE_URL = "https://services.nvd.nist.gov"  # disable-secrets-detection
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
    
def open_json(path):
            with open(path) as f:
                return json.loads(f.read())

def test_build_indicators_command():
    """
    Test function for the parse_cpe_command command

    Args:
        None

    Returns:
        Assertions if the tests fail for tag/relationship parsing of a CPE
    """
    client = Client(
        base_url=BASE_URL,
        proxy=False,
        api_key='',
        tlp_color='',
        has_kev=None,
        feed_tags='',
        first_fetch='1 day'
    )

    raw_cve = [open_json('./test_data/test_retrieve_cves_response.json')]
    response = build_indicators(client, raw_cve)
    expected_response = open_json('./test_data/test_build_indicators_response.json')

    assert all(item in expected_response[0] for item in response[0]), "BuildIndicators dictionaries are not equal"


@pytest.mark.parametrize("cpe, expected_output, expected_relationships", [
    (["cpe:2.3:a:vendor:product"],
     ["Vendor", "Product", "Application"],
     [EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='Vendor',
                         entity_b_type="identity").to_context(),
      EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='Product',
                         entity_b_type="software").to_context()]),
    (["cpe:2.3:h:a\:_vendor"],
     ["A: vendor", "Hardware"],
     [EntityRelationship(name="targets",
                         entity_a='CVE-2022-1111',
                         entity_a_type="cve",
                         entity_b='A: vendor',
                         entity_b_type="identity").to_context()]),
    (["cpe:2.3:o:::"],
     ["Operating-System"],
     []),
])
def test_parse_cpe(cpe, expected_output, expected_relationships):
    """
    Given:
        A CPE represented as a list of strings

    When:
        when parse_cpe is called

    Then:
        return a tuple of a list of tags (no empty strings) and a list of EntityRelationship objects.
    """

    tags, relationships = parse_cpe_command(cpe, 'CVE-2022-1111')
    assert set(tags) == set(expected_output)
    assert [relationship.to_context() for relationship in relationships] == expected_relationships
