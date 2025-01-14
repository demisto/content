import pytest

import DBotSuggestClassifierMapping
from DBotSuggestClassifierMapping import *
from freezegun import freeze_time

all_incident_fields = []


@pytest.fixture(autouse=True)
def setup(mocker):
    global all_incident_fields
    DBotSuggestClassifierMapping.ALIASING_MAP, DBotSuggestClassifierMapping.ALIASING_TERMS_MAP = get_aliasing(
        DBotSuggestClassifierMapping.SIEM_FIELDS)
    for siem_field in SIEM_FIELDS:
        machine_name = siem_field.replace(" ", "").lower()
        all_incident_fields.append({INCIDENT_FIELD_NAME: siem_field,
                                    INCIDENT_FIELD_MACHINE_NAME: machine_name,
                                    INCIDENT_FIELD_SYSTEM: True})
    init()


@freeze_time('2022-05-01 12:52:29')
def test_date_validator():
    date_validator = DateValidator()

    assert date_validator.is_unix_timestamp("1582816207")
    assert date_validator.is_unix_timestamp("1582816207921")
    assert date_validator.has_valid_date("2020-05-14T12:58:31Z")
    assert date_validator.has_valid_date("2020-05-14T12:58:31+0000")
    assert date_validator.has_valid_date("2020/05/14 12:58:31")
    assert date_validator.has_valid_date("2020.05.14 12:58:31")


@freeze_time('2022-05-01 12:52:29')
def test_validator():
    validator = Validator()

    assert validator.validate_ip("", "1.2.3.4")
    assert validator.validate_ip("", "292.17.120.107") is False

    assert validator.validate_email("", "someemail@domain.com")
    assert validator.validate_email("", "erezdcom") is False
    assert validator.validate_email("", "erez@demisto") is False

    assert validator.validate_not_count("message_count", "aa")
    assert validator.validate_not_count("message_ount", "123")

    assert validator.validate_sha256("", "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069")
    assert validator.validate_sha256("", "affa687a87f8abe90d9b9eba09bdbacb") is False
    assert validator.validate_sha256("", "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b26d9069") is False
    assert validator.validate_md5("", "affa687a87f8abe90d9b9eba09bdbacb")
    assert validator.validate_md5("", "affa687a87f8abe90d9b9eba09b") is False
    assert validator.validate_hash("", "affa687a87f8abe90d9b9eba09bdbacb")

    assert validator.validate_mac("", "00-11-22-33-44-22")
    assert validator.validate_mac("", "AA:BB:CC:DD:EE:FF")
    assert validator.validate_mac("", "AA:BB:CC:DD:EE:FF".lower())
    assert validator.validate_mac("", "AA:BB:CC:DD:EE:") is False

    assert validator.validate_alphanumeric_with_common_punct("", "erez harkush -is_ok sda '\"sd' ")
    assert validator.validate_alphanumeric_with_common_punct("", "erez!!") is False

    assert validator.validate_hostname("", "hostName-Erez")
    assert validator.validate_hostname("", "hostName- Erez") is False

    assert validator.validate_file_full_path("", "/path/to/file.php")
    assert validator.validate_file_full_path("", "C:\\Users\\Bob\\.luxshop\\jeans\\diesel-qd\\images\\Livier_11.png")
    assert validator.validate_file_full_path("", "\\Users\\Bob\\.luxshop\\jeans\\diesel-qd\\images\\Livier_11.png")
    assert validator.validate_file_full_path("", "Livier_11.png") is False

    assert validator.validate_date("", "1582816207921")
    assert validator.validate_date("", "1582816207")
    assert validator.validate_date("", "2020-05-14T12:58:31Z")

    assert validator.validate_url("", "http://google.com")
    assert validator.validate_url("", "https://google.com")
    assert validator.validate_url("", "hxxp://google.com")
    assert validator.validate_url("", "https://paloaltonetworks.zoom.us/j/12345?pwd=1234&status=success")
    assert not validator.validate_url("", "word")
    assert not validator.validate_url("", "https:// google.com")


def test_list_utils():
    assert is_sublist_of_list([1, 2], [1, 1, 2, 3, 4])
    assert is_sublist_of_list([1, 2, 3], [1, 2, 3])
    assert is_sublist_of_list([1, 2], [1, 1, 3, 2]) is False
    assert is_sublist_of_list([1, 2, 3], [1, 2]) is False

    assert remove_dups([1, 2, 3, 4, 1, 2]) == [1, 2, 3, 4]
    assert remove_dups([1, 2, 3]) == [1, 2, 3]


def test_string_utils():
    assert split_by_non_alpha_numeric("This_is-a.test123.45") == ['This', 'is', 'a', 'test123', '45']
    assert split_by_non_alpha_numeric("JustOneWord") == ['JustOneWord']

    assert camel_case_split("thisIsCamelCase") == ['this', 'Is', 'Camel', 'Case']
    assert camel_case_split("justoneword") == ['justoneword']
    assert camel_case_split("Justoneword") == ['Justoneword']

    assert jaccard_similarity_for_string_terms("word1 word2 word1", "word1") == 0.5
    assert jaccard_similarity_for_string_terms("word1 word2 word1", "word2  word1") == 1


def test_flatten_json():
    map1 = {
        'innerMap': {
            'value1': 'value2',
            'listvalue': ['value3', 'value4']
        }
    }
    flat_map1, values_with_more_than_one_element = flatten_json(map1)
    assert flat_map1 == {'innerMap.listvalue.[1]': 'value4', 'innerMap.listvalue.[0]': 'value3',
                         'innerMap.value1': 'value2'}
    assert values_with_more_than_one_element == ['innerMap.listvalue']

    map1 = {
        'innerMap': {
            'value1': 'value2',
        }
    }
    flat_map2, values_with_more_than_one_element = flatten_json(map1)
    assert flat_map2 == {
        'innerMap.value1': 'value2'
    }
    assert values_with_more_than_one_element == []


def test_suggest_field():
    assert 'src ip' in DBotSuggestClassifierMapping.ALIASING_MAP
    assert 'source ip' in DBotSuggestClassifierMapping.ALIASING_MAP
    assert 'source address' in DBotSuggestClassifierMapping.ALIASING_MAP
    assert get_candidates("src ip") == ['src ip']
    assert suggest_field_with_alias("src ip", "1.2.3.4") == ('Source IP', 'src ip')


def test_normilize():
    DBotSuggestClassifierMapping.ALL_POSSIBLE_TERMS = ['address', 'network']
    DBotSuggestClassifierMapping.ALL_POSSIBLE_TERMS_SET = set(DBotSuggestClassifierMapping.ALL_POSSIBLE_TERMS)
    assert normilize("Source IP") == ["source", "ip"]
    assert normilize("Dest IP") == ["dest", "ip"]
    assert normilize("Dest Addresses") == ["dest", "address"]
    assert normilize("Dest Networks") == ["dest", "network"]


def test_filter_by_dict_by_keys():
    d = {'a': 1, 'b': 2, 'c': 3}
    assert filter_by_dict_by_keys(d, []) == {}
    assert filter_by_dict_by_keys(d, d.keys()) == d
    assert filter_by_dict_by_keys(d, ['a']) == {'a': 1}


def test_combine_mappers():
    original = {'a': 1, 'b': 2, 'c': 3}
    new = {'a': 11}
    combine_mappers(original, new, []) == original
    new['d'] = 4
    combine_mappers(original, new, []) == {'a': 1, 'b': 2, 'c': 3, 'd': 4}


def test_get_most_relevant_match_for_field():
    cnt = Counter({'value 1': 2, 'value 2': 2, "value 3": 3})

    get_most_relevant_match_for_field("value 3", cnt) == "value 3"
    get_most_relevant_match_for_field("2 value", cnt) == "value 2"
    get_most_relevant_match_for_field("value", cnt) == "value 3"


@freeze_time('2022-05-01 12:52:29')
def test_main_qradar(mocker):
    incidents = json.load(open('TestData/qradar.json'))

    args = {
        'incidentSamples': incidents
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mapper = main()

    assert 'source_address_ids.[0]' == get_complex_value_key(mapper['Source IP']['complex'])
    assert 'local_destination_address_ids.[0]' == get_complex_value_key(mapper['Destination IP']['complex'])
    assert 'start_time' == get_complex_value_key(mapper['occurred']['complex'])
    assert 'severity' == get_complex_value_key(mapper['severity']['complex'])
    assert 'destination_networks.[0]' == get_complex_value_key(mapper['Destination Network']['complex'])
    assert 'source_network' == get_complex_value_key(mapper['Source Network']['complex'])


def test_main_arcsight(mocker):
    incidents = json.load(open('./TestData/arcsight.json'))
    args = {
        'incidentSamples': incidents
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mapper = main()

    assert 'Event-Severity' == get_complex_value_key(mapper['severity']['complex'])
    assert 'Name' == get_complex_value_key(mapper['name']['complex'])
    assert 'Event-File Path' == get_complex_value_key(mapper['File Path']['complex'])
    assert 'Event-File Name' == get_complex_value_key(mapper['File Name']['complex'])
    assert 'Event-File Type' == get_complex_value_key(mapper['File Type']['complex'])
    assert 'Event-Destination Address' == get_complex_value_key(mapper['Destination IP']['complex'])
    assert 'Event-Source Address' == get_complex_value_key(mapper['Source IP']['complex'])
    assert 'Event-Source Geo Country Code' == get_complex_value_key(mapper['Country']['complex'])
    assert 'Event-Source Host Name' == get_complex_value_key(mapper['Source Hostname']['complex'])
    assert 'Event-Start Time' == get_complex_value_key(mapper['occurred']['complex'])
    assert 'Event-Agent ID' == get_complex_value_key(mapper['Agent ID']['complex'])


def test_main_splunk(mocker):
    incidents = json.load(open('./TestData/splunk.json'))
    args = {
        'incidentSamples': incidents
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mapper = main()

    assert 'Name' == get_complex_value_key(mapper['name']['complex'])
    assert 'severity' == get_complex_value_key(mapper['severity']['complex'])
    assert 'rule_description' == get_complex_value_key(mapper['details']['complex'])


def test_main_outgoing(mocker):
    incidents = json.load(open('TestData/outgoing.json'))

    args = {
        'incidentSamples': incidents,
        'incidentSamplesType': 'outgoingSamples',
        'incidentFields': all_incident_fields,
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mapper = main()
    assert 'severity' == get_complex_value_key(mapper.get('user_priority', {})) \
           or 'severity' == get_complex_value_key(mapper.get('src_priority', {}))
    assert 'category' == get_complex_value_key(mapper['category'])


def test_main_splunk_schemes(mocker, capfd):
    incidents = json.load(open('TestData/splunk_scheme.json'))

    args = {
        'incidentSamples': incidents,
        'incidentSamplesType': 'scheme',
        'incidentFields': all_incident_fields,
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mapper = main()
    assert 'protocol' == get_complex_value_key(mapper['Protocol']['complex'])
    assert 'severity' == get_complex_value_key(mapper['severity']['complex'])
    assert 'body' == get_complex_value_key(mapper['Email Body']['complex'])
    assert 'subject_email' in get_complex_value_key(mapper['Email Subject']['complex'])
    assert 'country' == get_complex_value_key(mapper['Country']['complex'])
    assert 'vendor_product' == get_complex_value_key(mapper['Vendor Product']['complex'])
    assert 'signature' == get_complex_value_key(mapper['Signature']['complex'])
    assert 'os' == get_complex_value_key(mapper['OS']['complex'])
    assert 'app' == get_complex_value_key(mapper['App']['complex'])


def test_custom_field(mocker, capfd):
    incidents = json.load(open('TestData/splunk_scheme.json'))
    fields = [{INCIDENT_FIELD_SYSTEM: False,
               INCIDENT_FIELD_MACHINE_NAME: 'payloadtype',
               INCIDENT_FIELD_NAME: 'Payload Type'}]
    args = {
        'incidentSamples': incidents,
        'incidentSamplesType': 'scheme',
        'incidentFields': fields,
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mapper = main()
    assert len(mapper) == 1
    assert 'payload_type' == get_complex_value_key(mapper['Payload Type']['complex'])


def test_unmapped_field(mocker):
    incidents = json.load(open('TestData/splunk_scheme.json'))
    fields = [{INCIDENT_FIELD_SYSTEM: False,
               INCIDENT_FIELD_MACHINE_NAME: 'payloadtype',
               INCIDENT_FIELD_NAME: 'Payload Type'},
              {INCIDENT_FIELD_SYSTEM: False,
               INCIDENT_FIELD_MACHINE_NAME: 'action',
               INCIDENT_FIELD_NAME: 'Action',
               INCIDENT_FIELD_UNMAPPED: True}
              ]
    args = {
        'incidentSamples': incidents,
        'incidentSamplesType': 'scheme',
        'incidentFields': fields,
    }
    mocker.patch.object(demisto, 'args', return_value=args)
    mapper = main()
    assert len(mapper) == 1
    assert 'Action' not in mapper
