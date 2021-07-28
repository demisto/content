import io
import json
from CommonServerPython import tableToMarkdown
import pytest
from IOCParser import Client, \
    ioc_from_url_command, \
    ioc_from_json_text_command, \
    ioc_from_twitter_command, \
    ioc_from_raw_text_command


def create_client():
    return Client()


''' VARIABLES FOR PARSE_FROM_URL COMMAND '''

DUMMY_URL = 'https://example.com/url'

INVALID_URL = 'iamnotavalidurl'

EXPECTED_TABLE_PARSE_URL_DOMAIN_ALL_RESULTS = tableToMarkdown(f'results for DOMAIN from {DUMMY_URL}',
                                                              ["a1.com", "b2.com"],
                                                              headers='DOMAIN')

EXPECTED_TABLE_PARSE_URL_DOMAIN_LIMIT1_RESULTS = tableToMarkdown(f'results for DOMAIN from {DUMMY_URL}',
                                                                 ["a1.com"],
                                                                 headers='DOMAIN')

EXPECTED_TABLE_PARSE_URL_URL_ALL_RESULTS = tableToMarkdown(f'results for URL from {DUMMY_URL}',
                                                           ["https://a1.com"],
                                                           headers='URL')

EXPECTED_OUTPUTS_PARSE_URL_NO_KEYS_NO_LIMIT = {'url': DUMMY_URL,
                                               'Results': [{'type': 'DOMAIN', 'value': "a1.com"},
                                                           {'type': 'DOMAIN', 'value': "b2.com"},
                                                           {'type': 'URL', 'value': "https://a1.com"}]}

EXPECTED_OUTPUTS_PARSE_URL_DOMAIN_KEYS_1_LIMIT = {'url': DUMMY_URL,
                                                  'Results': [{'type': 'DOMAIN', 'value': "a1.com"}]}

EXPECTED_OUTPUTS_PARSE_URL_URL_KEYS_NO_LIMIT = {'url': DUMMY_URL,
                                                'Results': [{'type': 'URL', 'value': "https://a1.com"}]}

IOC_FROM_ULR_LIST = [
    ({'url': DUMMY_URL},
     "./test_data/ioc_from_url_response_1.json",
     [EXPECTED_TABLE_PARSE_URL_DOMAIN_ALL_RESULTS,
      EXPECTED_TABLE_PARSE_URL_URL_ALL_RESULTS],
     EXPECTED_OUTPUTS_PARSE_URL_NO_KEYS_NO_LIMIT),
    ({'url': DUMMY_URL, 'keys': ['DOMAIN'], 'limit':1},
     "./test_data/ioc_from_url_response_1.json",
     [EXPECTED_TABLE_PARSE_URL_DOMAIN_LIMIT1_RESULTS],
     EXPECTED_OUTPUTS_PARSE_URL_DOMAIN_KEYS_1_LIMIT),
    ({'url': DUMMY_URL, 'keys': ['url']},
     "./test_data/ioc_from_url_response_1.json",
     [EXPECTED_TABLE_PARSE_URL_URL_ALL_RESULTS],
     EXPECTED_OUTPUTS_PARSE_URL_URL_KEYS_NO_LIMIT)]


''' VARIABLES FOR PARSE_FROM_JSON_TEXT COMMAND '''


DUMMY_JSON_TEXT = '{"Dummy": ["jsontext"]}'


EXPECTED_TABLE_PARSE_JSON_TEXT_DOMAIN_ALL_RESULTS = tableToMarkdown(f'results for DOMAIN',
                                                                    ["a1.com"],
                                                                    headers='DOMAIN')

EXPECTED_TABLE_PARSE_JSON_TEXT_DOMAIN_LIMIT1_RESULTS = tableToMarkdown(f'results for DOMAIN',
                                                                       ["a1.com"],
                                                                       headers='DOMAIN')

EXPECTED_TABLE_PARSE_JSON_TEXT_FILE_HASH_SHA256_ALL_RESULTS = tableToMarkdown(f'results for FILE_HASH_SHA256',
                                                                              ["dummysha256"],
                                                                              headers='FILE_HASH_SHA256')

EXPECTED_OUTPUTS_PARSE_JSON_TEXT_NO_KEYS_NO_LIMIT = {'data': DUMMY_JSON_TEXT,
                                                     'Results': [{'type': 'DOMAIN', 'value': "a1.com"},
                                                                 {'type': 'FILE_HASH_SHA256', 'value': "dummysha256"}]}

EXPECTED_OUTPUTS_PARSE_JSON_TEXT_DOMAIN_KEYS_1_LIMIT = {'data': DUMMY_JSON_TEXT,
                                                        'Results': [{'type': 'DOMAIN', 'value': "a1.com"}]}

EXPECTED_OUTPUTS_PARSE_JSON_TEXT_FILE_HASH_SHA256_KEYS_NO_LIMIT = {'data': DUMMY_JSON_TEXT,
                                                                   'Results':
                                                                       [{'type': 'FILE_HASH_SHA256',
                                                                         'value': "dummysha256"}]}

IOC_FROM_JSON_TEXT_LIST = [
    ({'data': DUMMY_JSON_TEXT},
     "./test_data/ioc_from_json_text_response_1.json",
     [EXPECTED_TABLE_PARSE_JSON_TEXT_DOMAIN_ALL_RESULTS,
      EXPECTED_TABLE_PARSE_JSON_TEXT_FILE_HASH_SHA256_ALL_RESULTS],
     EXPECTED_OUTPUTS_PARSE_JSON_TEXT_NO_KEYS_NO_LIMIT),
    ({'data': DUMMY_JSON_TEXT, 'keys': ['DOMAIN'], 'limit':1},
     "./test_data/ioc_from_json_text_response_1.json",
     [EXPECTED_TABLE_PARSE_JSON_TEXT_DOMAIN_LIMIT1_RESULTS],
     EXPECTED_OUTPUTS_PARSE_JSON_TEXT_DOMAIN_KEYS_1_LIMIT),
    ({'data': DUMMY_JSON_TEXT, 'keys': ['FILE_HASH_SHA256']},
     "./test_data/ioc_from_json_text_response_1.json",
     [EXPECTED_TABLE_PARSE_JSON_TEXT_FILE_HASH_SHA256_ALL_RESULTS],
     EXPECTED_OUTPUTS_PARSE_JSON_TEXT_FILE_HASH_SHA256_KEYS_NO_LIMIT)]


''' VARIABLES FOR PARSE_FROM_TWITTER COMMAND '''

DUMMY_USERNAME = "dummy"

EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS = tableToMarkdown(f'results for DOMAIN from {DUMMY_USERNAME}',
                                                                  ["a1.com"],
                                                                  headers='DOMAIN')

EXPECTED_TABLE_PARSE_TWITTER_FILE_HASH_SHA256_ALL_RESULTS = tableToMarkdown(f'results for FILE_HASH_SHA256 from {DUMMY_USERNAME}',
                                                                            ["dummysha256_0", "dummysha256_1"],
                                                                            headers='FILE_HASH_SHA256')

EXPECTED_TABLE_PARSE_TWITTER_URL_ALL_RESULTS = tableToMarkdown(f'results for URL from {DUMMY_USERNAME}',
                                                               ["https://a1.com"],
                                                               headers='URL')

EXPECTED_OUTPUTS_PARSE_TWITTER_NO_KEYS_NO_LIMIT = {'data': DUMMY_USERNAME,
                                                   'Results': [{'type': 'FILE_HASH_SHA256', 'value': "dummysha256_0"},
                                                               {'type': 'FILE_HASH_SHA256', 'value': "dummysha256_1"},
                                                               {'type': 'DOMAIN', 'value': "a1.com"},
                                                               {'type': 'URL', 'value': "https://a1.com"}]}

EXPECTED_OUTPUTS_PARSE_TWITTER_DOMAIN_KEYS_1_LIMIT = {'data': DUMMY_USERNAME,
                                                      'Results': [{'type': 'DOMAIN', 'value': "a1.com"}]}

EXPECTED_OUTPUTS_PARSE_TWITTER_FILE_HASH_SHA256_KEYS_NO_LIMIT = {'data': DUMMY_USERNAME,
                                                                 'Results':
                                                                     [{'type': 'FILE_HASH_SHA256', 'value': "dummysha256_0"},
                                                                      {'type': 'FILE_HASH_SHA256', 'value': "dummysha256_1"}]}

EXPECTED_OUTPUTS_PARSE_TWITTER_URL_DOMAIN_KEYS_NO_LIMIT = {'data': DUMMY_USERNAME,
                                                           'Results': [{'type': 'DOMAIN', 'value': "a1.com"},
                                                                       {'type': 'URL', 'value': "https://a1.com"}]}

IOC_FROM_TWITTER_LIST = [
    ({'data': DUMMY_USERNAME},
     "./test_data/ioc_from_twitter_response.json",
     [EXPECTED_TABLE_PARSE_TWITTER_FILE_HASH_SHA256_ALL_RESULTS,
      EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS,
      EXPECTED_TABLE_PARSE_TWITTER_URL_ALL_RESULTS],
     EXPECTED_OUTPUTS_PARSE_TWITTER_NO_KEYS_NO_LIMIT),
    ({'data': DUMMY_USERNAME, 'keys': ['DOMAIN'], 'limit':1},
     "./test_data/ioc_from_twitter_response.json",
     [EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS],
     EXPECTED_OUTPUTS_PARSE_TWITTER_DOMAIN_KEYS_1_LIMIT),
    ({'data': DUMMY_USERNAME, 'keys': ['URL', 'DOMAIN']},
     "./test_data/ioc_from_twitter_response.json",
     [EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS,
      EXPECTED_TABLE_PARSE_TWITTER_URL_ALL_RESULTS],
     EXPECTED_OUTPUTS_PARSE_TWITTER_URL_DOMAIN_KEYS_NO_LIMIT)]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('args, response_file_name, expected_tables, expected_outputs', IOC_FROM_ULR_LIST)
def test_ioc_from_url_command_valid_response(mocker, args, response_file_name, expected_tables, expected_outputs):
    """
    Given:
        -
    When:
        -
    Then:
        - Verify
    """
    client = create_client()
    response_json = util_load_json(response_file_name)
    mocker.patch.object(client, 'ioc_from_url', return_value=response_json)
    actual_command_results = ioc_from_url_command(client, args)
    for i in range(len(actual_command_results) - 1):
        tmp = actual_command_results[i].readable_output
        assert actual_command_results[i].readable_output == expected_tables[i]
        assert actual_command_results[i].outputs == expected_outputs


@pytest.mark.parametrize('args, response_file_name, expected_tables, expected_outputs', IOC_FROM_JSON_TEXT_LIST)
def test_ioc_from_json_text_command_valid_response(mocker, args, response_file_name, expected_tables, expected_outputs):
    """
    Given:
        -
    When:
        -
    Then:
        - Verify
    """
    client = create_client()
    response_json = util_load_json(response_file_name)
    mocker.patch.object(client, 'ioc_from_json_text', return_value=response_json)
    actual_command_results = ioc_from_json_text_command(client, args)
    for i in range(len(actual_command_results) - 1):
        tmp = actual_command_results[i].readable_output
        assert actual_command_results[i].readable_output == expected_tables[i]
        assert actual_command_results[i].outputs == expected_outputs


@pytest.mark.parametrize('args', [{'data': "not_a_valid_json"}])
def test_ioc_from_json_text_command_invalid_text(mocker, args):
    """
    Given:
        -
    When:
        -
    Then:
        - Verify
    """
    client = create_client()
    mocker.patch.object(client, 'ioc_from_json_text')
    with pytest.raises(ValueError) as e:
        ioc_from_json_text_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args, response_file_name, expected_tables, expected_outputs', IOC_FROM_TWITTER_LIST)
def test_ioc_from_twitter_command_valid_response(mocker, args, response_file_name, expected_tables, expected_outputs):
    """
    Given:
        -
    When:
        -
    Then:
        - Verify
    """
    client = create_client()
    response_json = util_load_json(response_file_name)
    mocker.patch.object(client, 'ioc_from_twitter', return_value=response_json)
    actual_command_results = ioc_from_twitter_command(client, args)
    for i in range(len(actual_command_results) - 1):
        tmp = actual_command_results[i].readable_output
        assert actual_command_results[i].readable_output == expected_tables[i]
        assert actual_command_results[i].outputs == expected_outputs
