import pytest
from CommonServerPython import string_to_table_header, tableToMarkdown


import json
import plyara
import dateparser
from freezegun import freeze_time


URL = "https://openphish.com/feed.txt"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())

def util_load_txt(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

def mock_client():
    """
        Create a mock client for testing.
    """
    from FeedGitHub import Client
    return Client(
        base_url="example.com",
        verify=False,
        proxy=False,
        owner="",
        repo="",
        headers={},
    )
    
def test_get_base_head_commits_sha(mocker):
    pass

def test_extract_commits(mocker):
    response = util_load_json('test_data/extract_commit_response.json')
    client = mock_client()
    list_commits = client.extract_commits(response)
    
    pass

def test_filter_out_files_by_status():
    pass
    
    
def test_get_content_files_from_repo():
    pass

@freeze_time("2024-05-12T15:30:49.330015")
def test_parse_and_map_yara_content():
    """
    """
    from FeedGitHub import parse_and_map_yara_content
    rule_1_input = {'example.com': util_load_txt("test_data/yara-rule-1.yar")}
    rule_2_input = {'example.com': util_load_txt("test_data/yara-rule-2.yar")}
    rule_3_input = {'example.com': util_load_txt("test_data/yara-rule-3.yar")}
    
    parsed_rule1 = parse_and_map_yara_content(rule_1_input)
    parsed_rule2 = parse_and_map_yara_content(rule_2_input)
    parsed_rule3 = parse_and_map_yara_content(rule_3_input)
    
    assert parsed_rule1 == util_load_json("test_data/yara-rule-1-res.json")
    assert parsed_rule2 == util_load_json("test_data/yara-rule-2-res.json")
    assert parsed_rule3 == util_load_json("test_data/yara-rule-3-res.json")
    
    
@freeze_time("2024-05-12T15:30:49.330015")
def test_extract_text_indicators():
    from FeedGitHub import extract_text_indicators
    ioc_indicators_input = {"example.com": util_load_txt("test_data/test-ioc-indicators.txt")}
    params = {"owner": "example.owner", "repo": "example.repo"}
    res_indicators = extract_text_indicators(ioc_indicators_input, params)
    assert res_indicators == util_load_json("test_data/iocs-res.json")
    

def test_get_stix_indicators():
    """
    Given:
        - Output of the STIX feed API
    When:
        - When calling the 'get_stix_indicators' method
    Then:
        - Returns a list of the STIX indicators parsed from "STIX2XSOARParser client"
    """
    from FeedGitHub import get_stix_indicators
    stix_indicators_input = util_load_json("test_data/taxii_test.json")
    res_indicators = get_stix_indicators(stix_indicators_input)
    assert res_indicators == util_load_json("test_data/taxii_test_res.json")
    
def test_negative_limit():
    """
        Given: A negative limit.
        When: Calling get_indicators.
        Then: Ensure ValueError is raised with the right message.
    """
    from FeedGitHub import get_indicators_command
    args = {'limit' : '-1'}
    client = mock_client()

    with pytest.raises(ValueError) as ve:
        get_indicators_command(client, {}, args)
    assert ve.value.args[0] == "get_indicators_command return with error. \n\nError massage: Limit must be a positive number."
    
    

    
# def test_build_iterator(requests_mock):
#     """

#     Given:
#         - Output of the feed API
#     When:
#         - When calling fetch_indicators or get_indicators
#     Then:
#         - Returns a list of the indicators parsed from the API's response

#     """
#     with open("test_data/FeedHelloWorld_mock.txt") as file:
#         response = file.read()
#     requests_mock.get(URL, text=response)
#     expected_url = "https://url1.com"
#     client = mock_client()
#     indicators = client.build_iterator()
#     url_indicators = {
#         indicator["value"] for indicator in indicators if indicator["type"] == "URL"
#     }
#     assert expected_url in url_indicators


# def test_fetch_indicators(mocker):
#     """

#     Given:
#         - Output of the feed API as list
#     When:
#         - Fetching indicators from the API
#     Then:
#         - Create indicator objects list

#     """
#     client = Client(base_url=URL)
#     mocker.patch.object(
#         Client,
#         "build_iterator",
#         return_value=util_load_json("./test_data/build_iterator_results.json"),
#     )
#     results = fetch_indicators_command(client, params={"tlp_color": "RED"})
#     assert results == util_load_json("./test_data/get_indicators_command_results.json")


# def test_get_indicators_command(mocker):
#     """

#     Given:
#         - Output of the feed API as list
#     When:
#         - Getting a limited number of indicators from the API
#     Then:
#         - Return results as war-room entry

#     """
#     client = Client(base_url=URL)
#     indicators_list = util_load_json("./test_data/build_iterator_results.json")[:10]
#     mocker.patch.object(Client, "build_iterator", return_value=indicators_list)
#     results = get_indicators_command(
#         client, params={"tlp_color": "RED"}, args={"limit": "10"}
#     )
#     human_readable = tableToMarkdown(
#         "Indicators from HelloWorld Feed:",
#         indicators_list,
#         headers=["value", "type"],
#         headerTransform=string_to_table_header,
#         removeNull=True,
#     )
#     assert results.readable_output == human_readable
    
