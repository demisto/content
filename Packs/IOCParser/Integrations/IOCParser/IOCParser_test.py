import io
import json
from CommonServerPython import tableToMarkdown, DemistoException
import demistomock as demisto
import pytest
from IOCParser import Client, \
    ioc_from_url_command, \
    ioc_from_json_text_command, \
    ioc_from_twitter_command, \
    ioc_from_raw_text_command


def create_client():
    return Client()


''' VARIABLES FOR PARSE_FROM_URL COMMAND '''

MOCK_URL = 'https://example.com/url'

INVALID_URL = 'iamnotavalidurl'

EXPECTED_TABLE_PARSE_URL_DOMAIN_ALL_RESULTS = \
    tableToMarkdown(
        f'results for DOMAIN from {MOCK_URL}',
        ["a1.com", "b2.com"],
        headers='DOMAIN'
    )

EXPECTED_TABLE_PARSE_URL_DOMAIN_LIMIT1_RESULTS = \
    tableToMarkdown(
        f'results for DOMAIN from {MOCK_URL}',
        ["a1.com"],
        headers='DOMAIN'
    )

EXPECTED_TABLE_PARSE_URL_URL_ALL_RESULTS = \
    tableToMarkdown(
        f'results for URL from {MOCK_URL}',
        ["https://a1.com"],
        headers='URL'
    )

EXPECTED_OUTPUTS_PARSE_URL_NO_KEYS_NO_LIMIT = \
    {
        'url': MOCK_URL,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"},
            {'type': 'DOMAIN', 'value': "b2.com"},
            {'type': 'URL', 'value': "https://a1.com"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_URL_DOMAIN_KEYS_1_LIMIT = \
    {
        'url': MOCK_URL,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_URL_URL_KEYS_NO_LIMIT = \
    {
        'url': MOCK_URL,
        'Results': [
            {'type': 'URL', 'value': "https://a1.com"}
        ]
    }

IOC_FROM_ULR_LIST = [
    (
        {'url': MOCK_URL},
        "./test_data/ioc_from_url_response_1.json",
        [
            EXPECTED_TABLE_PARSE_URL_DOMAIN_ALL_RESULTS,
            EXPECTED_TABLE_PARSE_URL_URL_ALL_RESULTS
        ],
        EXPECTED_OUTPUTS_PARSE_URL_NO_KEYS_NO_LIMIT
    ),
    (
        {'url': MOCK_URL,
         'keys': ['DOMAIN'],
         'limit': 1
         },
        "./test_data/ioc_from_url_response_1.json",
        [EXPECTED_TABLE_PARSE_URL_DOMAIN_LIMIT1_RESULTS],
        EXPECTED_OUTPUTS_PARSE_URL_DOMAIN_KEYS_1_LIMIT),
    (
        {'url': MOCK_URL,
         'keys': ['url']
         },
        "./test_data/ioc_from_url_response_1.json",
        [EXPECTED_TABLE_PARSE_URL_URL_ALL_RESULTS],
        EXPECTED_OUTPUTS_PARSE_URL_URL_KEYS_NO_LIMIT
    )
]

''' VARIABLES FOR PARSE_FROM_JSON_TEXT COMMAND '''

MOCK_JSON_TEXT = '{"Dummy": ["jsontext"]}'

MOCK_RAW_TEXT = 'i am a dummy raw text'

MOCK_ENTRY_ID = '@123'

EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_DOMAIN_ALL_RESULTS = \
    tableToMarkdown(
        'results for DOMAIN',
        ["a1.com"],
        headers='DOMAIN'
    )

EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_DOMAIN_LIMIT1_RESULTS = \
    tableToMarkdown(
        'results for DOMAIN',
        ["a1.com"],
        headers='DOMAIN'
    )

EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_FILE_HASH_SHA256_ALL_RESULTS = \
    tableToMarkdown(
        'results for FILE_HASH_SHA256',
        ["dummysha256"],
        headers='FILE_HASH_SHA256'
    )

EXPECTED_OUTPUTS_PARSE_JSON_TEXT_NO_KEYS_NO_LIMIT = \
    {
        'data': MOCK_JSON_TEXT,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"},
            {'type': 'FILE_HASH_SHA256', 'value': "dummysha256"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_JSON_TEXT_DOMAIN_KEYS_1_LIMIT = \
    {
        'data': MOCK_JSON_TEXT,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_JSON_TEXT_FILE_HASH_SHA256_KEYS_NO_LIMIT = \
    {'data': MOCK_JSON_TEXT,
     'Results': [
         {'type': 'FILE_HASH_SHA256', 'value': "dummysha256"}
     ]
     }

EXPECTED_OUTPUTS_PARSE_RAW_TEXT_NO_KEYS_NO_LIMIT = \
    {
        'data': MOCK_RAW_TEXT,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"},
            {'type': 'FILE_HASH_SHA256', 'value': "dummysha256"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_RAW_TEXT_DOMAIN_KEYS_1_LIMIT = \
    {
        'data': MOCK_RAW_TEXT,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_RAW_TEXT_FILE_HASH_SHA256_KEYS_NO_LIMIT = \
    {
        'data': MOCK_RAW_TEXT,
        'Results': [
            {'type': 'FILE_HASH_SHA256', 'value': "dummysha256"}
        ]
    }

IOC_FROM_JSON_TEXT_LIST = [
    (
        {'data': MOCK_JSON_TEXT},
        "./test_data/ioc_from_json_and_raw_text_response.json",
        [
            EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_DOMAIN_ALL_RESULTS,
            EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_FILE_HASH_SHA256_ALL_RESULTS
        ],
        EXPECTED_OUTPUTS_PARSE_JSON_TEXT_NO_KEYS_NO_LIMIT
    ),
    (
        {'data': MOCK_JSON_TEXT,
         'keys': ['DOMAIN'],
         'limit': 1
         },
        "./test_data/ioc_from_json_and_raw_text_response.json",
        [EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_DOMAIN_LIMIT1_RESULTS],
        EXPECTED_OUTPUTS_PARSE_JSON_TEXT_DOMAIN_KEYS_1_LIMIT
    ),
    (
        {'data': MOCK_JSON_TEXT,
         'keys': ['FILE_HASH_SHA256']
         },
        "./test_data/ioc_from_json_and_raw_text_response.json",
        [EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_FILE_HASH_SHA256_ALL_RESULTS],
        EXPECTED_OUTPUTS_PARSE_JSON_TEXT_FILE_HASH_SHA256_KEYS_NO_LIMIT
    )
]

IOC_FROM_RAW_TEXT_LIST = [
    (
        {'data': MOCK_RAW_TEXT},
        "./test_data/ioc_from_json_and_raw_text_response.json",
        [
            EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_DOMAIN_ALL_RESULTS,
            EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_FILE_HASH_SHA256_ALL_RESULTS
        ],
        EXPECTED_OUTPUTS_PARSE_RAW_TEXT_NO_KEYS_NO_LIMIT
    ),
    (
        {'data': MOCK_RAW_TEXT,
         'keys': ['DOMAIN'],
         'limit': 1
         },
        "./test_data/ioc_from_json_and_raw_text_response.json",
        [EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_DOMAIN_LIMIT1_RESULTS],
        EXPECTED_OUTPUTS_PARSE_RAW_TEXT_DOMAIN_KEYS_1_LIMIT
    ),
    (
        {'data': MOCK_RAW_TEXT,
         'keys': ['FILE_HASH_SHA256']
         },
        "./test_data/ioc_from_json_and_raw_text_response.json",
        [EXPECTED_TABLE_PARSE_JSON_AND_RAW_TEXT_FILE_HASH_SHA256_ALL_RESULTS],
        EXPECTED_OUTPUTS_PARSE_RAW_TEXT_FILE_HASH_SHA256_KEYS_NO_LIMIT
    )
]

''' VARIABLES FOR PARSE_FROM_TWITTER COMMAND '''

MOCK_USERNAME = "MOCK"

EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS = \
    tableToMarkdown(
        f'results for DOMAIN from {MOCK_USERNAME}',
        ["a1.com"],
        headers='DOMAIN',
    )

EXPECTED_TABLE_PARSE_TWITTER_FILE_HASH_SHA256_ALL_RESULTS = \
    tableToMarkdown(
        f'results for FILE_HASH_SHA256 from {MOCK_USERNAME}',
        ["dummysha256_0", "dummysha256_1"],
        headers='FILE_HASH_SHA256'
    )

EXPECTED_TABLE_PARSE_TWITTER_URL_ALL_RESULTS = \
    tableToMarkdown(
        f'results for URL from {MOCK_USERNAME}',
        ["https://a1.com"],
        headers='URL'
    )

EXPECTED_OUTPUTS_PARSE_TWITTER_NO_KEYS_NO_LIMIT = \
    {
        'data': MOCK_USERNAME,
        'Results': [
            {'type': 'FILE_HASH_SHA256', 'value': "dummysha256_0"},
            {'type': 'FILE_HASH_SHA256', 'value': "dummysha256_1"},
            {'type': 'DOMAIN', 'value': "a1.com"},
            {'type': 'URL', 'value': "https://a1.com"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_TWITTER_DOMAIN_KEYS_1_LIMIT = \
    {
        'data': MOCK_USERNAME,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_TWITTER_FILE_HASH_SHA256_KEYS_NO_LIMIT = \
    {
        'data': MOCK_USERNAME,
        'Results': [
            {'type': 'FILE_HASH_SHA256', 'value': "dummysha256_0"},
            {'type': 'FILE_HASH_SHA256', 'value': "dummysha256_1"}
        ]
    }

EXPECTED_OUTPUTS_PARSE_TWITTER_URL_DOMAIN_KEYS_NO_LIMIT = \
    {
        'data': MOCK_USERNAME,
        'Results': [
            {'type': 'DOMAIN', 'value': "a1.com"},
            {'type': 'URL', 'value': "https://a1.com"}
        ]
    }

IOC_FROM_TWITTER_LIST = [
    (
        {'data': MOCK_USERNAME},
        "./test_data/ioc_from_twitter_response.json",
        [
            EXPECTED_TABLE_PARSE_TWITTER_FILE_HASH_SHA256_ALL_RESULTS,
            EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS,
            EXPECTED_TABLE_PARSE_TWITTER_URL_ALL_RESULTS
        ],
        EXPECTED_OUTPUTS_PARSE_TWITTER_NO_KEYS_NO_LIMIT
    ),
    (
        {'data': MOCK_USERNAME,
         'keys': ['DOMAIN'],
         'limit': 1
         },
        "./test_data/ioc_from_twitter_response.json",
        [EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS],
        EXPECTED_OUTPUTS_PARSE_TWITTER_DOMAIN_KEYS_1_LIMIT
    ),
    (
        {'data': MOCK_USERNAME,
         'keys': ['URL', 'DOMAIN']
         },
        "./test_data/ioc_from_twitter_response.json",
        [
            EXPECTED_TABLE_PARSE_TWITTER_DOMAIN_ALL_RESULTS,
            EXPECTED_TABLE_PARSE_TWITTER_URL_ALL_RESULTS
        ],
        EXPECTED_OUTPUTS_PARSE_TWITTER_URL_DOMAIN_KEYS_NO_LIMIT
    )
]


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('args, response_file_name, expected_tables, expected_outputs', IOC_FROM_ULR_LIST)
def test_ioc_from_url_command_valid_response(mocker, args, response_file_name, expected_tables, expected_outputs):
    """
    Given:
        - Valid url and keys
    When:
        - When the user wants to parse IOCs from url
    Then:
        - Verify that the warroom entry is in the right format
    """
    client = create_client()
    response_json = util_load_json(response_file_name)
    mocker.patch.object(client, 'ioc_from_url', return_value=response_json)
    actual_command_results = ioc_from_url_command(client, args)
    for i in range(len(actual_command_results) - 1):
        assert actual_command_results[i].readable_output == expected_tables[i]
        assert actual_command_results[i].outputs == expected_outputs


@pytest.mark.parametrize('args, response_file_name', [({'url': INVALID_URL},
                                                       './test_data/ioc_from_url_invalid_url_response.json')])
def test_ioc_from_url_command_invalid_url(mocker, args, response_file_name):
    """
    Given:
        - Invalid url
    When:
        - When the user wants to parse IOCs from url
    Then:
        - Verify that ValueError is raised
    """
    client = create_client()
    mocker.patch.object(client, 'ioc_from_url', side_effect=DemistoException("some error message"))
    with pytest.raises(ValueError) as e:
        ioc_from_url_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args', [({'url': MOCK_URL})])
def test_ioc_from_url_command_empty_response(mocker, args):
    """
    Given:
        - A url that does not contain IOCs
    When:
        - When the user wants to parse IOCs from url
    Then:
        - Verify that ValueError is raised
    """
    client = create_client()
    mocker.patch.object(client, 'ioc_from_url', return_value="")
    with pytest.raises(ValueError) as e:
        ioc_from_url_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args, response_file_name, expected_tables, expected_outputs', IOC_FROM_JSON_TEXT_LIST)
def test_ioc_from_json_text_command_valid_response(mocker, args, response_file_name, expected_tables, expected_outputs):
    """
    Given:
        - Valid JSON text and keys
    When:
        - When the user wants to parse IOCs from JSON text
    Then:
        - Verify that the warroom entry is in the right format
    """
    client = create_client()
    response_json = util_load_json(response_file_name)
    mocker.patch.object(client, 'ioc_from_json_text', return_value=response_json)
    actual_command_results = ioc_from_json_text_command(client, args)
    for i in range(len(actual_command_results) - 1):
        assert actual_command_results[i].readable_output == expected_tables[i]
        assert actual_command_results[i].outputs == expected_outputs


@pytest.mark.parametrize('args', [{'data': "not_a_valid_json"}])
def test_ioc_from_json_text_command_invalid_json_format(mocker, args):
    """
    Given:
        - Invalid JSON text
    When:
        - When the user wants to parse IOCs from JSON text
    Then:
        - Verify that an ValueError is raised
    """
    client = create_client()
    with pytest.raises(ValueError) as e:
        ioc_from_json_text_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args', [({'data': MOCK_JSON_TEXT})])
def test_ioc_from_json_text_command_empty_response(mocker, args):
    """
    Given:
        - A JSON text that does not contain IOCs
    When:
        - When the user wants to parse IOCs from JSON text
    Then:
        - Verify that ValueError is raised
    """
    client = create_client()
    mocker.patch.object(client, 'ioc_from_json_text', return_value="")
    with pytest.raises(ValueError) as e:
        ioc_from_json_text_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args, response_file_name, expected_tables, expected_outputs', IOC_FROM_RAW_TEXT_LIST)
def test_ioc_from_raw_text_command_valid_response_for_data_field(mocker, args, response_file_name, expected_tables,
                                                                 expected_outputs):
    """
    Given:
        - Valid raw text in the data argument and keys
    When:
        - When the user wants to parse IOCs from raw text
    Then:
        - Verify that the warroom entry is in the right format
    """
    client = create_client()
    response_json = util_load_json(response_file_name)
    mocker.patch.object(client, 'ioc_from_raw_text', return_value=response_json)
    actual_command_results = ioc_from_raw_text_command(client, args)
    for i in range(len(actual_command_results) - 1):
        assert actual_command_results[i].readable_output == expected_tables[i]
        assert actual_command_results[i].outputs == expected_outputs


@pytest.mark.parametrize('args', [{'entry_id': MOCK_ENTRY_ID}])
def test_ioc_from_raw_text_command_invalid_file_format(mocker, args):
    """
        Given:
            - Invalid file path
        When:
            - When the user wants to parse IOCs from raw text
        Then:
            - Verify that an ValueError is raised
    """
    client = create_client()
    mocker.patch.object(demisto, 'getFilePath', return_value=None)
    with pytest.raises(ValueError) as e:
        ioc_from_raw_text_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args', [{'data': MOCK_RAW_TEXT, 'entry_id': MOCK_ENTRY_ID}, {}])
def test_ioc_from_raw_text_command_invalid_command_arguments(mocker, args):
    """
    Given:
        - Both data and entry id arguments
    When:
        - When the user wants to parse IOCs from raw text
    Then:
        - Verify that ValueError is raised
    """
    client = create_client()
    with pytest.raises(ValueError) as e:
        ioc_from_raw_text_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args', [{'entry_id': "@212"}])
def test_ioc_from_raw_text_command_invalid_entry_id(mocker, args):
    """
    Given:
        - Invalid entry id
    When:
        - When the user wants to parse IOCs from raw text
    Then:
        - Verify that an ValueError is raised
    """
    client = create_client()
    mocker.patch.object(demisto, 'getFilePath', return_value={'id': 'id', 'path': 'test/test.pdf', 'name': 'test.pdf'})
    with pytest.raises(ValueError) as e:
        ioc_from_raw_text_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args', [({'data': MOCK_RAW_TEXT})])
def test_ioc_from_raw_text_command_empty_response(mocker, args):
    """
    Given:
        - A raw text that does not contain IOCs
    When:
        - When the user wants to parse IOCs from raw text
    Then:
        - Verify that ValueError is raised
    """
    client = create_client()
    mocker.patch.object(client, 'ioc_from_raw_text', return_value="")
    with pytest.raises(ValueError) as e:
        ioc_from_raw_text_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args, response_file_name, expected_tables, expected_outputs', IOC_FROM_TWITTER_LIST)
def test_ioc_from_twitter_command_valid_response(mocker, args, response_file_name, expected_tables, expected_outputs):
    """
    Given:
        - Valid twitter account and keys
    When:
        - When the user wants to parse IOCs from twitter account
    Then:
        - Verify that the warroom entry is in the right format
    """
    client = create_client()
    response_json = util_load_json(response_file_name)
    mocker.patch.object(client, 'ioc_from_twitter', return_value=response_json)
    actual_command_results = ioc_from_twitter_command(client, args)
    for i in range(len(actual_command_results) - 1):
        assert actual_command_results[i].readable_output == expected_tables[i]
        assert actual_command_results[i].outputs == expected_outputs


@pytest.mark.parametrize('args', [{'data': "notatwitteraccount"}])
def test_ioc_from_twitter_command_invalid_username(mocker, args):
    """
    Given:
        - Invalid twitter account
    When:
        - When the user wants to parse IOCs from twitter account
    Then:
        - Verify that an ValueError is raised
    """
    client = create_client()
    mocker.patch.object(client, 'ioc_from_twitter', side_effect=DemistoException("some error message"))
    with pytest.raises(ValueError) as e:
        ioc_from_twitter_command(client, args)
        if not e:
            assert False


@pytest.mark.parametrize('args', [({'data': MOCK_USERNAME})])
def test_ioc_from_url_command_empty_response(mocker, args):
    """
    Given:
        - A twitter account that does not contain IOCs
    When:
        - When the user wants to parse IOCs from twitter account
    Then:
        - Verify that ValueError is raised
    """
    client = create_client()
    mocker.patch.object(client, 'ioc_from_twitter', return_value="")
    with pytest.raises(ValueError) as e:
        ioc_from_twitter_command(client, args)
        if not e:
            assert False
