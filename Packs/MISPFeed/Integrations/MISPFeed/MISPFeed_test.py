import pytest
import json

from CommonServerPython import DemistoException
from Packs.MISPFeed.Integrations.MISPFeed.MISPFeed import clean_user_query


def test_clean_user_query_success():
    """
    Given
        - A json string query
    When
        - query is good
    Then
        - create a dict from json string
    """
    querystr = '{"returnFormat": "json", "type": {"OR": ["ip-src"]}, "tags": {"OR": ["tlp:%"]}}'
    params = clean_user_query(querystr)
    assert len(params) == 3


def test_clean_user_query_bad_query():
    """
    Given
        - A json string query
    When
        - json syntax is incorrect
    Then
        - raise a DemistoException
    """
    with pytest.raises(DemistoException):
        querystr = '{"returnFormat": "json", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]'
        clean_user_query(querystr)


def test_clean_user_query_change_format():
    """
    Given
        - A json parsed result from qualys
    When
        - query has a unsupported return format
    Then
        - change return format to json
    """
    querystr = '{"returnFormat": "xml", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    params = clean_user_query(querystr)
    assert params["returnFormat"] == "json"


def test_clean_user_query_remove_timestamp():
    """
    Given
        - A json parsed result from qualys
    When
        - query has timestamp parameter
    Then
        - Return query without the timestamp parameter
    """
    good_query = '{"returnFormat": "json", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    querystr = '{"returnFormat": "json", "timestamp": "1617875568", "type": {"OR": ["md5"]}, "tags": {"OR": ["tlp:%"]}}'
    params = clean_user_query(querystr)
    assert good_query == json.dumps(params)
