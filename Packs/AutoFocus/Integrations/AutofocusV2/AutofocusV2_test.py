import json
import pytest
import requests
import requests_mock
import sys
import io
import demistomock as demisto

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
    params = {
        'api_key': '1234'
    }
    mocker.patch.object(demisto, 'params', return_value=params)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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


def test_connection_error(mocker):
    import AutofocusV2

    RETURN_ERROR_TARGET = 'AutofocusV2.return_error'
    BASE_URL = 'https://autofocus.paloaltonetworks.com/api/v1.0'

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=sys.exit)

    with requests_mock.Mocker() as m:
        m.get(f'{BASE_URL}/tic', exc=requests.exceptions.ConnectionError)

        with pytest.raises(SystemExit):
            AutofocusV2.search_indicator('ip', '8.8.8.8')
        assert 'Error connecting to server. Check your URL/Proxy/Certificate settings' \
               in return_error_mock.call_args[0][0]


def test_tag_details(mocker):
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
    AutofocusV2.tag_details_command()
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


def test_reliability(mocker):
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
    AutofocusV2.search_ip_command('1.1.1.1', DBotScoreReliability.B, False)
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
    expected_entity_b_types = ['STIX Threat Actor', 'Campaign', 'STIX Malware', 'STIX Attack Pattern']
    expected_name = 'indicator-of'
    expected_name_entity_b = ['Upatre1', 'Upatre2', 'Upatre3', 'Upatre5']

    relationships = create_relationships_list(entity_a='Test', entity_a_type='IP',
                                              tags=RAW_TAGS, reliability='B - Usually reliable')
    relation_entry = [relation.to_entry() for relation in relationships]

    for relation, i in zip(relation_entry, range(len(relation_entry))):
        assert relation.get('name') == expected_name
        assert relation.get('entityA') == 'Test'
        assert relation.get('entityB') == expected_name_entity_b[i]
        assert relation.get('entityBType') == expected_entity_b_types[i]
