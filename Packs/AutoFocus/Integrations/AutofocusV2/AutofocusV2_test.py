import json
import pytest
import requests
import demistomock as demisto
from pytest_mock import MockerFixture
from CommonServerPython import *
from AutofocusV2 import Client

IP_ADDRESS = '127.0.0.1'

FILE_RES_JSON = {
    "indicator": {
        "latestPanVerdicts": {
            "WF_SAMPLE": "MALWARE"
        }
    }
}

IP_RES_JSON = {
    "indicator": {
        "indicatorValue": IP_ADDRESS,
        "indicatorType": "IPV4_ADDRESS",
        "summaryGenerationTs": 1576077539906,
        "latestPanVerdicts": {
            "PAN_DB": "MALWARE"
        },
        "seenByDataSourceIds": [
            "WF_SAMPLE"
        ],
        "wildfireRelatedSampleVerdictCounts": {
            "MALWARE": 95,
            "GRAYWARE": 5
        }
    },
    "tags": [
        {
            "support_id": 1,
            "tag_name": "Upatre",
            "public_tag_name": "Unit42.Upatre",
            "tag_definition_scope_id": 4,
            "tag_definition_status_id": 1,
            "count": 7692947,
            "lasthit": "2019-12-11 02:29:45",
            "description": "The Upatre Trojan typically arrives as an e-mail attachment or through"
                           " an e-mail with a link to the malware. Upatre's function is to download additional"
                           " malware onto the system, in most cases when the malware was initially observed"
                           " downloading the Dyre banking Trojan which then attempts to steal the users online"
                           " banking credentials which may may be used for fraud.\n\nSince then, the operators have"
                           " diversified, with Upatre frequently seen downloading other banking trojans.\n",
            # noqa: E501
            "customer_name": "Palo Alto Networks Unit42",
            "customer_industry": "High Tech",
            "upVotes": 2,
            "downVotes": None,
            "myVote": None,
            "source": "Unit 42",
            "tag_class_id": 3,
            "tag_definition_id": 29449,
            "tagGroups": [
                {
                    "tag_group_name": "Downloader",
                    "description":
                        "This type of malware secretly downloads malicious files from a remote server, "
                        "then installs and executes the files."
                    # noqa: E501
                }
            ],
            "aliases": [
                "Upatre"
            ]
        }
    ]
}

INDICATOR_RES = {
    "IndicatorValue": IP_ADDRESS,
    "IndicatorType": "IPV4_ADDRESS",
    "LatestPanVerdicts": {
        "PAN_DB": "MALWARE"
    },
    "WildfireRelatedSampleVerdictCounts": {
        "MALWARE": 95,
        "GRAYWARE": 5
    },
    "SeenBy": [
        "WF_SAMPLE"
    ],
    "Tags": [
        {
            "PublicTagName": "Unit42.Upatre",
            "TagName": "Upatre",
            "CustomerName": "Palo Alto Networks Unit42",
            "Source": "Unit 42",
            "TagDefinitionScopeID": 4,
            "TagDefinitionStatusID": 1,
            "TagClassID": 3,
            "Count": 7692947,
            "Lasthit": "2019-12-11 02:29:45",
            "Description": "The Upatre Trojan typically arrives as an e-mail attachment or through an e-mail with a"
                           " link to the malware. Upatre's function is to download additional malware onto the system,"
                           " in most cases when the malware was initially observed downloading the Dyre banking Trojan"
                           " which then attempts to steal the users online banking credentials which may may be used "
                           "for fraud.\n\nSince then, the operators have diversified, with Upatre frequently"
                           " seen downloading other banking trojans.\n"
            # noqa: E501
        }
    ]
}

TAGS_DETAILS_RES = {
    'public_tag_name': 'Anon015b57.MYNEWTAGNAME',
    'tag_name': 'MYNEWTAGNAME',
    'customer_name': '',
    'source': 'Palo Alto Networks - InfoSec-Synack Tesing<h1>xxx</h1>',
    'tag_definition_scope': 'public',
    'tag_definition_status': 'disabled',
    'tag_class': 'actor',
    'count': 108737,
    'lasthit': '2021-02-11 22:31:51',
    'description': '<h1>xxx</h1>'
}

RAW_TAGS = [
    {
        "support_id": 1,
        "tag_name": "Upatre1",
        "public_tag_name": "Unit42.Upatre",
        "tag_definition_scope_id": 4,
        "tag_definition_status_id": 1,
        "count": 7692947,
        "lasthit": "2019-12-11 02:29:45",
        "source": "Unit 42",
        "tag_class_id": 1,
        "tag_definition_id": 29449
    },
    {
        "support_id": 1,
        "tag_name": "Upatre2",
        "public_tag_name": "Unit42.Upatre",
        "tag_definition_scope_id": 4,
        "tag_definition_status_id": 1,
        "count": 7692947,
        "lasthit": "2019-12-11 02:29:45",
        "source": "Unit 42",
        "tag_class_id": 2,
        "tag_definition_id": 29449
    },
    {
        "support_id": 1,
        "tag_name": "Upatre3",
        "public_tag_name": "Unit42.Upatre",
        "tag_definition_scope_id": 4,
        "tag_definition_status_id": 1,
        "count": 7692947,
        "lasthit": "2019-12-11 02:29:45",
        "source": "Unit 42",
        "tag_class_id": 3,
        "tag_definition_id": 29449
    },
    {
        "support_id": 1,
        "tag_name": "Upatre5",
        "public_tag_name": "Unit42.Upatre",
        "tag_definition_scope_id": 4,
        "tag_definition_status_id": 1,
        "count": 7692947,
        "lasthit": "2019-12-11 02:29:45",
        "source": "Unit 42",
        "tag_class_id": 5,
        "tag_definition_id": 29449
    }
]

TAGS_FROM_FILE_RES = [
    {
        'PublicTagName': 'Commodity.Sivis',
        'TagName': 'Sivis',
        'CustomerName': 'Palo Alto Networks Unit42',
        'Source': None,
        'TagDefinitionScopeID': 3,
        'TagDefinitionStatusID': 1,
        'TagClassID': 3,
        'Count': 11778017,
        'TagGroups': {'TagGroupName': 'GROUP'},
        'Aliases': 'ALIASES',
        'Lasthit': '2021-02-14 23:56:40',
        'Description': 'A file infector which attempts to enumerate files on the host.'
                       ' Modifies boot.ini and other system files to maintain persistence'
                       ' and spread.'
    }
]

TAGS_FOR_GENERIC_CONTEXT_OUTPUT = [
    {
        'PublicTagName': 'Commodity.Sivis',
        'TagName': 'Sivis',
        'TagGroups': {'TagGroupName': 'GROUP'},
        'Aliases': 'ALIASES',
    }
]


@pytest.fixture(autouse=True)
def init_tests(mocker):
    params = {'api_key': '1234'}
    mocker.patch.object(demisto, 'params', return_value=params)


@pytest.fixture
def autofocusv2_client():
    return Client(url='url', verify=False)


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


class ResMocker:
    def __init__(self, http_response, status_code):
        self.http_response = http_response
        self.status_code = status_code
        self.ok = False
        self.headers = {}

    def json(self):
        return self.http_response

    def raise_for_status(self):
        return


def test_parse_indicator_response():
    from AutofocusV2 import parse_indicator_response
    raw_indicator = IP_RES_JSON['indicator']
    raw_tags = IP_RES_JSON['tags']
    indicator = parse_indicator_response(raw_indicator, raw_tags, 'IP')
    assert json.dumps(indicator) == json.dumps(INDICATOR_RES)


def test_calculate_dbot_score():
    from AutofocusV2 import calculate_dbot_score
    raw_indicator = IP_RES_JSON['indicator']
    score = calculate_dbot_score(raw_indicator, 'IP')
    assert score == 3


def test_calculate_dbot_score_file():
    from AutofocusV2 import calculate_dbot_score
    raw_indicator = IP_RES_JSON['indicator']
    score = calculate_dbot_score(raw_indicator, 'File')
    assert score == 3


def test_connection_error(mocker, autofocusv2_client):
    import AutofocusV2

    def raise_connection_error(url_suffix, method, ok_codes, headers, params, data={}, err_operation=None):
        assert url_suffix == '/tic'
        assert method == 'GET'
        assert headers == {
            'Content-Type': 'application/json',
            'apiKey': '1234'
        }
        assert params == {
            'indicatorType': 'ip',
            'indicatorValue': '8.8.8.8',
            'includeTags': 'true',
        }
        assert ok_codes == (200, 404, 409, 503)
        raise requests.exceptions.ConnectionError

    mocker.patch.object(autofocusv2_client, 'http_request', side_effect=raise_connection_error)

    with pytest.raises(
        AutofocusV2.DemistoException,
        match='Error connecting to server. Check your URL/Proxy/Certificate settings'
    ):
        AutofocusV2.search_indicator(autofocusv2_client, 'ip', '8.8.8.8')


def test_tag_details(mocker, autofocusv2_client):
    """

     Given:
         - The response from calling the command tag_details.
     When:
         - When the user uses 'autofocus-tag-details' for a given tag.
     Then:
         - The fields are being parsed properly in to context.

     """
    import AutofocusV2
    mocker.patch.object(demisto, 'args', return_value={'tag_name': 'Anon015b57.MYNEWTAGNAME'})
    mocker.patch.object(AutofocusV2, 'autofocus_tag_details', return_value=TAGS_DETAILS_RES)
    mocker.patch.object(demisto, 'results')
    AutofocusV2.tag_details_command(autofocusv2_client)
    assert demisto.results.call_args[0][0] == util_load_json('test_data/teg_details_command_outputs.json')


def test_get_tags_for_generic_context():
    """

     Given:
         - The 'Tags' values returned from the API for a given file.
     When:
         - When the user uses 'file' command.
     Then:
         - Only specific keys should be parsed in to context - 'TagGroups.TagGroupName', 'Aliases', 'PublicTagName',
          'TagName'.

     """
    import AutofocusV2
    assert AutofocusV2.get_tags_for_generic_context(TAGS_FROM_FILE_RES) == TAGS_FOR_GENERIC_CONTEXT_OUTPUT


def test_reliability(mocker, autofocusv2_client):
    import AutofocusV2
    import CommonServerPython
    from CommonServerPython import DBotScoreReliability
    mock_data = {'indicator': {'indicatorValue': '1.1.1.1', 'indicatorType': 'IPV4_ADDRESS',
                               'summaryGenerationTs': 1616340557369, 'firstSeenTsGlobal': None,
                               'lastSeenTsGlobal': None, 'latestPanVerdicts': {'Test': 'test'},
                               'seenByDataSourceIds': [], 'wildfireRelatedSampleVerdictCounts': {}}, 'tags': [],
                 }
    mocker.patch.object(AutofocusV2, 'search_indicator', return_value=mock_data)
    mocked_dbot = mocker.patch.object(CommonServerPython.Common, 'DBotScore')
    mocker.patch.object(CommonServerPython.Common, 'IP')
    AutofocusV2.search_ip_command(autofocusv2_client, '1.1.1.1', DBotScoreReliability.B, False)
    assert mocked_dbot.call_args[1].get('reliability') == 'B - Usually reliable'


def test_get_tags_for_tags_and_malware_family_fields():
    """

     Given:
         - The 'Tags' values returned from the API for a given response.
     When:
         - When the user uses 'file' 'ip' 'domain' or 'url' commands.
     Then:
         - Only specific tags should be parsed in to context.

     """
    import AutofocusV2
    tags = AutofocusV2.get_tags_for_tags_and_malware_family_fields(TAGS_FROM_RESPONSE)
    tags.sort()
    assert tags == ['Bladabindi', 'NJRat', 'NanoCoreRAT', 'RemoteAccessTrojan', 'Unit42.NJRat', 'Unit42.NanoCoreRAT']


TAGS_FROM_RESPONSE = [
    {
        "aliases": [
            "Bladabindi"
        ],
        "count": 2273664,
        "customer_industry": "High Tech",
        "customer_name": "Palo Alto Networks Unit42",
        "description": "NJRa.",
        "downVotes": "",
        "lasthit": "2020-11-17 12:04:36",
        "myVote": "",
        "public_tag_name": "Unit42.NJRat",
        "source": "Unit 42",
        "support_id": 1,
        "tagGroups": [
            {
                "description": "Remote",
                "tag_group_name": "RemoteAccessTrojan"
            }
        ],
        "tag_class_id": 3,
        "tag_definition_id": 31426,
        "tag_definition_scope_id": 4,
        "tag_definition_status_id": 1,
        "tag_name": "NJRat",
        "upVotes": 1
    },
    {
        "count": 506972,
        "customer_industry": "High Tech",
        "customer_name": "Palo Alto Networks Unit42",
        "description": "Generally",
        "downVotes": "",
        "lasthit": "2020-11-17 16:31:52",
        "myVote": "",
        "public_tag_name": "Unit42.NanoCoreRAT",
        "source": "Unit 42",
        "support_id": 1,
        "tag_class_id": 3,
        "tag_definition_id": 31987,
        "tag_definition_scope_id": 4,
        "tag_definition_status_id": 1,
        "tag_name": "NanoCoreRAT",
        "tagGroups": [
            {
                "description": "Remote",
                "tag_group_name": "RemoteAccessTrojan"
            }
        ],
        "upVotes": 3
    }
]


def test_create_relationships_list():
    """
     Given:
         - A tags list of the existing kinds of tags from the api.
     When:
         - When running create relationships.
     Then:
         - The relationships that are created contain the expected types and names.
     """
    from AutofocusV2 import create_relationships_list
    expected_entity_b_types = ['Threat Actor', 'Campaign', 'Malware', 'Attack Pattern']
    expected_name = 'indicator-of'
    expected_name_entity_b = ['Upatre1', 'Upatre2', 'Upatre3', 'Upatre5']

    relationships = create_relationships_list(entity_a='Test', entity_a_type='IP',
                                              tags=RAW_TAGS, reliability='B - Usually reliable')
    relation_entry = [relation.to_entry() for relation in relationships]

    for i, relation in enumerate(relation_entry):
        assert relation.get('name') == expected_name
        assert relation.get('entityA') == 'Test'
        assert relation.get('entityB') == expected_name_entity_b[i]
        assert relation.get('entityBType') == expected_entity_b_types[i]


URLS_LIST = [
    ("www.München.com", "www.Mxn--tdanchen.com"),
    ("www.example.com", "www.example.com"),
    ("www.Mününchen.com", "www.Mxn--tdanxn--tdanchen.com"),
    ("www.Müünchen.com", "www.Mxn--tdaanchen.com"),
    ("www.MükÖnchen.com", "www.Mxn--tdakxn--ndanchen.com"),
    ("www.こんにちは.com", 'www.xn--28j2a3ar1p.com'),
    ("https://paloaltonetworks–test.com", "https://paloaltonetworksxn--7ugtest.com")    # noqa: RUF001
]


@pytest.mark.parametrize("url, result", URLS_LIST)
def test_convert_url_to_ascii_character(url, result):
    from AutofocusV2 import convert_url_to_ascii_character
    converted = convert_url_to_ascii_character(url)
    assert converted == result


def test_search_url_command(mocker, autofocusv2_client):
    from AutofocusV2 import search_url_command

    mock_response = {
        'indicator': {
            'indicatorValue': 'www.こんにちは.com',
            'indicatorType': 'URL',
            'latestPanVerdicts': {'PAN_DB': 'BENIGN'}
        },
        'tags': []
    }

    status_code = 200
    response = ResMocker(mock_response, status_code)
    mocker.patch.object(autofocusv2_client, 'http_request', return_value=response)

    result = search_url_command(autofocusv2_client, "www.こんにちは.com", 'B - Usually reliable', True)

    assert result[0].indicator.url == "www.こんにちは.com"
    assert result[0].raw_response["indicator"]["indicatorValue"] == mock_response["indicator"]["indicatorValue"]


@pytest.mark.parametrize('separator, expected_value', [('|', ["https:firstpart,connectedpart"]),
                                                       (None, ["https:firstpart", "connectedpart"])])
def test_search_url_custom_separator(mocker, autofocusv2_client, separator, expected_value):
    from AutofocusV2 import search_url_command
    from CommonServerPython import remove_empty_elements

    # Mock response
    mock_response = {
        'indicator': {
        },
        'tags': []
    }
    status_code = 200
    response = ResMocker(mock_response, status_code)
    mocker.patch.object(autofocusv2_client, 'http_request', return_value=response)

    # Mock argToList
    return_value = []

    def side_effect_function(*args, **kwargs):
        result = argToList(*args, **kwargs)  # Call the original function
        return_value.append(result)
        return result

    mocker.patch('AutofocusV2.argToList', side_effect=side_effect_function)

    # Mock args
    args = {'url': 'https:firstpart,connectedpart',
            'reliability': 'B - Usually reliable',
            'create_relationships': False,
            'separator': separator
            }
    args: dict = remove_empty_elements(args)    # type: ignore
    search_url_command(autofocusv2_client, **args)
    assert return_value[0] == expected_value


def test_search_url_command_args(mocker, autofocusv2_client):
    from AutofocusV2 import search_url_command

    mock_response = {
        'indicator': {
            'indicatorValue': 'www.test.com',
            'indicatorType': 'URL',
            'latestPanVerdicts': {'PAN_DB': 'BENIGN'}
        },
        'tags': []
    }

    status_code = 200

    expected_headers = {'Content-Type': 'application/json', 'apiKey': '1234'}
    expected_params = {'indicatorType': 'url', 'indicatorValue': 'www.test.com', 'includeTags': 'true'}
    expected_ok_codes = (200, 404, 409, 503)

    response = ResMocker(mock_response, status_code)
    http_request = mocker.patch.object(autofocusv2_client, '_http_request', return_value=response)

    search_url_command(autofocusv2_client, "www.test.com", 'B - Usually reliable', True)

    http_request.assert_called_with(method='GET',
                                    url_suffix='/tic',
                                    data=json.dumps({}),
                                    headers=expected_headers,
                                    params=expected_params,
                                    retries=3,
                                    resp_type='response',
                                    ok_codes=expected_ok_codes)


TEST_DATA = [
    (
        'autofocus_md5_response',
        '123456789012345678901234567890ab',
        ['123456789012345678901234567890ab', None, None]
    ),
    (
        'autofocus_sha1_response',
        '1234567890123456789012345678901234567890',
        [None, '1234567890123456789012345678901234567890', None]
    ),
    (
        'autofocus_sha256_response',
        '123456789012345678901234567890123456789012345678901234567890abcd',
        [None, None, '123456789012345678901234567890123456789012345678901234567890abcd']
    ),
    (
        'autofocus_sha256_response_wf_sample_has_null',
        '6833e945695d2609de175c5f67693594748229962759f366b822be5fd568f292',
        [None, None, '6833e945695d2609de175c5f67693594748229962759f366b822be5fd568f292']
    ),
]


@pytest.mark.parametrize('mock_response, file_hash, expected_results', TEST_DATA)
def test_search_file_command(mocker, mock_response, file_hash, expected_results, autofocusv2_client):
    """
     Given:
         - A file hash (md5, sha1, sha256).
     When:
         - When running search_file_command.
     Then:
         - Ensure the indicator contains the correct hash type.
     """

    from AutofocusV2 import search_file_command

    with open(f'test_data/{mock_response}.json') as f:
        response_json = json.load(f)

    status_code = 200
    response = ResMocker(response_json, status_code)
    mocker.patch.object(autofocusv2_client, 'http_request', return_value=response)

    results = search_file_command(autofocusv2_client, file_hash, None, False)

    assert results[0].indicator.md5 == expected_results[0]
    assert results[0].indicator.sha1 == expected_results[1]
    assert results[0].indicator.sha256 == expected_results[2]
    assert results[0].outputs.get('IndicatorValue') in expected_results


@pytest.mark.parametrize(argnames='mock_response, domain',
                         argvalues=[('autofocus_domain_response', 'mail16.amadeus.net')])
def test_search_domain_command(mock_response, domain, mocker, autofocusv2_client):
    """
     Given:
         - A domain.
     When:
         - When running search_domain_command.
     Then:
         - Ensure the indicator contains the correct domain.
     """

    from AutofocusV2 import search_domain_command

    with open(f'test_data/{mock_response}.json') as f:
        response_json = json.load(f)

    status_code = 200
    response = ResMocker(response_json, status_code)
    mocker.patch.object(autofocusv2_client, 'http_request', return_value=response)

    results = search_domain_command(autofocusv2_client, domain, None, False)

    assert results[0].indicator.domain == domain


@pytest.mark.parametrize(argnames='ioc_type, ioc_val',
                         argvalues=[('domain', 'test_domain'),
                                    ('ipv4_address', 'test_ipv4_address'),
                                    ('filehash', '123456789012345678901234567890ab'),
                                    ])
def test_search_indicator_command__no_indicator(mocker, autofocusv2_client, ioc_type, ioc_val):
    """
    Given:
        - Indicator not exist in AutoFocus

    When:
        - Run the reputation command

    Then:
        - Validate the expected result is return with detailed information
    """

    # prepare
    from AutofocusV2 import search_ip_command, search_domain_command, search_file_command
    ioc_type_to_command = {
        'domain': search_domain_command,
        'ipv4_address': search_ip_command,
        'filehash': search_file_command,
    }
    no_indicator_response = {
        'tags': []
    }

    status_code = 200
    response = ResMocker(no_indicator_response, status_code)
    mocker.patch.object(autofocusv2_client, 'http_request', return_value=response)

    # run
    result = ioc_type_to_command[ioc_type](autofocusv2_client, ioc_val, 'B - Usually reliable', True)

    # validate
    assert f'{ioc_val} was not found in AutoFocus' in result[0].readable_output


def test_search_url_command__no_indicator(mocker, autofocusv2_client):
    """
    Given:
        - url not exist in AutoFocus

    When:
        - Run the reputation command

    Then:
        - Validate the expected result is return with detailed information
    """

    # prepare
    from AutofocusV2 import search_url_command
    no_indicator_response = {
        'tags': []
    }
    status_code = 200
    response = ResMocker(no_indicator_response, status_code)
    mocker.patch.object(autofocusv2_client, 'http_request', return_value=response)

    # run
    result = search_url_command(autofocusv2_client, 'test_url', 'B - Usually reliable', True)

    # validate
    assert 'test_url was not found in AutoFocus' in result[0].readable_output


@pytest.mark.parametrize('range_num,res_count', [(98, 1), (250, 3)])
def test_search_session(mocker, autofocusv2_client, range_num, res_count):
    """
    Given:
        - Large amount of IPs to search sessions on.

    When:
        - Running the search_session.

    Then:
        - Validate the search is done for each batch of 100 IPs and the cookies are returned accordingly.
    """

    from AutofocusV2 import search_sessions

    status_code = 200
    response = ResMocker({'af_cookie': 'auto-focus-cookie'}, status_code)
    mocker.patch.object(autofocusv2_client, '_http_request', return_value=response)

    ips = [f'{i}.{i}.{i}.{i}' for i in range(range_num)]
    res = search_sessions(client=autofocusv2_client, ip=ips)

    assert len(res) == res_count
    for r in res:
        assert r.get('AFCookie') == 'auto-focus-cookie'


@pytest.mark.parametrize('range_num,res_count', [(98, 1), (250, 3)])
def test_search_samples(mocker, autofocusv2_client, range_num, res_count):
    """
    Given:
        - Large amount of IPs to search samples on.

    When:
        - Running the search_samples.

    Then:
        - Validate the search is done for each batch of 100 IPs and the cookies are returned accordingly.
    """

    from AutofocusV2 import search_samples

    status_code = 200
    response = ResMocker({'af_cookie': 'auto-focus-cookie'}, status_code)
    mocker.patch.object(autofocusv2_client, '_http_request', return_value=response)

    ips = [f'{i}.{i}.{i}.{i}' for i in range(range_num)]
    res = search_samples(client=autofocusv2_client, ip=ips)

    assert len(res) == res_count
    for r in res:
        assert r.get('AFCookie') == 'auto-focus-cookie'


def test_metrics(mocker: MockerFixture, autofocusv2_client):
    import AutofocusV2

    bucket_info = {
        'bucket_info': {
            "minute_points": 200,
            "daily_points": 30000,
            "minute_points_remaining": 0,
            "daily_points_remaining": 4578,
            "minute_bucket_start": "2015-09-02 10:55:33",
            "daily_bucket_start": "2015-09-01 17:08:40",
            "wait_in_seconds": 20.5,
        }
    }

    mocker.patch.object(demisto, 'command', return_value='autofocus-top-tags-search')
    mocker.patch.object(demisto, 'args', return_value={'unit42': 'True', 'class': 'Actor', 'retry_on_rate_limit': 'true'})
    mocker.patch.object(demisto, 'demistoVersion', return_value={'version': '6.9.0', 'buildNumber': '12345'})
    response = ResMocker(bucket_info, 503)
    mocker.patch.object(autofocusv2_client, '_http_request', return_value=response)
    mocker.patch('AutofocusV2.Client', return_value=autofocusv2_client)

    return_results_mock = mocker.patch('AutofocusV2.return_results')
    AutofocusV2.EXECUTION_METRICS = ExecutionMetrics()

    AutofocusV2.main()

    autofocusv2_client._http_request.assert_called_with(
        method='POST',
        headers={'Content-Type': 'application/json'},
        data=json.dumps({
            "query": {"operator": "all", "children": [{"field": "sample.tag_class", "operator": "is", "value": "actor"}]},
            "scope": None, "tagScopes": ["unit42"], "apiKey": "1234"
        }),
        url_suffix='/top-tags/search/',
        ok_codes=(200, 409, 503),
        resp_type='response',
        retries=3,
        params={}
    )
    assert return_results_mock.call_args_list[0][0][0].readable_output == 'API Rate limit exceeded, rerunning command.'
    assert return_results_mock.call_args_list[0][0][0].scheduled_command._args == {
        'unit42': 'True', 'class': 'Actor', 'retry_on_rate_limit': 'false',
    }
    assert return_results_mock.call_args_list[0][0][0].scheduled_command._next_run == '40'
    assert return_results_mock.call_args_list[1][0][0].execution_metrics == [{'APICallsCount': 1, 'Type': 'QuotaError'}]
    assert return_results_mock.call_args_list[2][0][0].readable_output == '''### Autofocus API Points
|Daily allotment started|Daily points used|Minute allotment started|Minute points used|
|---|---|---|---|
| 2015-09-01 17:08:40 | 4578/30000 | 2015-09-02 10:55:33 | 0/200 |
'''
