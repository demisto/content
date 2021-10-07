"""
"""

from AutoFocusTagsFeed import Client, get_indicators_command, fetch_indicators_command
from CommonServerPython import tableToMarkdown, string_to_table_header
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_build_iterator(mocker):
    """
    Given:
        - Output of the feed API
    When:
        - When calling fetch_indicators or get_indicators
    Then:
        - Returns a list of the indicators parsed from the API's response
    """

    client = Client(api_key='1234', verify=False, proxy=False)
    mocker.patch.object(client, 'get_tags', return_value=util_load_json('test_data/all_tags_result.json'))
    mocker.patch.object(client, 'get_tag_details', return_value={'tag': []})
    indicators = client.build_iterator(is_get_command=True)
    assert len(indicators) == 2


def test_fetch_indicators(mocker):
    """
    Given:
        - Output of the feed API as list
    When:
        - Fetching indicators from the API
    Then:
        - Create indicator objects list
    """

    client = Client(api_key='1234', verify=False, proxy=False)
    mocker.patch.object(Client, 'build_iterator', return_value=util_load_json('test_data/build_iterator_results.json'))
    results = fetch_indicators_command(client, params={'tlp_color': 'RED'})
    assert results == util_load_json('test_data/get_indicators_command_results.json')


def test_get_indicators_command(mocker):
    """

    Given:
        - Output of the feed API as list
    When:
        - Getting a limited number of indicators from the API
    Then:
        - Return results as war-room entry

    """
    client = Client(api_key='1234', verify=False, proxy=False)
    indicators_list = util_load_json('test_data/build_iterator_results.json')[:2]
    mocker.patch.object(Client, 'build_iterator', return_value=indicators_list)
    tag_details = util_load_json('test_data/tag_details_result.json')
    mocker.patch.object(Client, 'get_tag_details', return_value=tag_details)
    results = get_indicators_command(client, params={'tlp_color': 'RED'}, args={'limit': '2'})
    human_readable = tableToMarkdown('Indicators from AutoFocus Tags Feed:', indicators_list,
                                     headers=['value', 'type', 'fields'], headerTransform=string_to_table_header,
                                     removeNull=True)
    assert results.readable_output == human_readable
