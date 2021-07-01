import pytest

from CommonServerPython import DemistoException

TAG_IDS_LISTS = [([1, 2, 3], [2, 3, 4, 5], [1, 2, 3], [4, 5]),
                 ([1, 2, 3], [4, 5], [1, 2, 3], [4, 5])]


def mock_misp(mocker):
    from pymisp import ExpandedPyMISP
    mocker.patch.object(ExpandedPyMISP, '__init__', return_value=None)


def test_convert_timestamp(mocker):
    mock_misp(mocker)
    from MISPV3 import convert_timestamp
    assert convert_timestamp(1546713469) == "2019-01-05 18:37:49"


def test_build_list_from_dict(mocker):
    mock_misp(mocker)
    from MISPV3 import build_list_from_dict
    lst = build_list_from_dict({'ip': '8.8.8.8', 'domain': 'google.com'})
    assert lst == [{'ip': '8.8.8.8'}, {'domain': 'google.com'}]


def test_extract_error(mocker):
    mock_misp(mocker)
    from MISPV3 import extract_error
    error_response = [
        (
            403,
            {
                'name': 'Could not add object',
                'message': 'Could not add object',
                'url': '/objects/add/156/',
                'errors': 'Could not save object as at least one attribute has failed validation (ip). \
                        {"value":["IP address has an invalid format."]}'
            }
        )
    ]
    expected_response = [
        {
            'code': 403,
            'message': 'Could not add object',
            'errors': 'Could not save object as at least one attribute has failed validation (ip).      '
                      '                   {"value":["IP address has an invalid format."]}'
        }
    ]
    err = extract_error(error_response)
    assert err == expected_response

    error_response = [(404, {'name': 'Invalid event.', 'message': 'Invalid event.', 'url': '/objects/add/1546'})]
    expected_response = [{'code': 404, 'message': 'Invalid event.', 'errors': None}]
    err = extract_error(error_response)
    assert err == expected_response

    # Empty error
    err = extract_error([])
    assert err == []


def test_build_misp_complex_filter(mocker):
    mock_misp(mocker)
    from MISPV3 import build_misp_complex_filter

    old_query = "tag1"
    old_query_with_ampersand = "tag1&&tag2"
    old_query_with_not = "!tag1"

    actual = build_misp_complex_filter(old_query)
    assert actual == old_query

    actual = build_misp_complex_filter(old_query_with_ampersand)
    assert actual == old_query_with_ampersand

    actual = build_misp_complex_filter(old_query_with_not)
    assert actual == old_query_with_not

    complex_query_AND_single = "AND:tag1"
    expected = {'AND': ['tag1']}
    actual = build_misp_complex_filter(complex_query_AND_single)
    assert actual == expected

    complex_query_OR_single = "OR:tag1"
    expected = {'OR': ['tag1']}
    actual = build_misp_complex_filter(complex_query_OR_single)
    assert actual == expected

    complex_query_NOT_single = "NOT:tag1"
    expected = {'NOT': ['tag1']}
    actual = build_misp_complex_filter(complex_query_NOT_single)
    assert actual == expected

    complex_query_AND = "AND:tag1,tag2"
    expected = {'AND': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_AND)
    assert actual == expected

    complex_query_OR = "OR:tag1,tag2"
    expected = {'OR': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_OR)
    assert actual == expected

    complex_query_NOT = "NOT:tag1,tag2"
    expected = {'NOT': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_NOT)
    assert actual == expected

    complex_query_AND_OR = "AND:tag1,tag2;OR:tag3,tag4"
    expected = {'AND': ['tag1', 'tag2'], 'OR': ['tag3', 'tag4']}
    actual = build_misp_complex_filter(complex_query_AND_OR)
    assert actual == expected

    complex_query_OR_AND = "OR:tag3,tag4;AND:tag1,tag2"
    expected = {'OR': ['tag3', 'tag4'], 'AND': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_OR_AND)
    assert actual == expected

    complex_query_AND_NOT = "AND:tag1,tag2;NOT:tag3,tag4"
    expected = {'AND': ['tag1', 'tag2'], 'NOT': ['tag3', 'tag4']}
    actual = build_misp_complex_filter(complex_query_AND_NOT)
    assert actual == expected

    complex_query_NOT_AND = "NOT:tag3,tag4;AND:tag1,tag2"
    expected = {'NOT': ['tag3', 'tag4'], 'AND': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_NOT_AND)
    assert actual == expected

    complex_query_OR_NOT = "OR:tag1,tag2;NOT:tag3,tag4"
    expected = {'OR': ['tag1', 'tag2'], 'NOT': ['tag3', 'tag4']}
    actual = build_misp_complex_filter(complex_query_OR_NOT)
    assert actual == expected

    complex_query_NOT_OR = "NOT:tag3,tag4;OR:tag1,tag2"
    expected = {'NOT': ['tag3', 'tag4'], 'OR': ['tag1', 'tag2']}
    actual = build_misp_complex_filter(complex_query_NOT_OR)
    assert actual == expected

    complex_query_AND_OR_NOT = "AND:tag1,tag2;OR:tag3,tag4;NOT:tag5"
    expected = {'AND': ['tag1', 'tag2'], 'OR': ['tag3', 'tag4'], 'NOT': ['tag5']}
    actual = build_misp_complex_filter(complex_query_AND_OR_NOT)
    assert actual == expected


def test_is_tag_list_valid(mocker):
    mock_misp(mocker)
    from MISPV3 import is_tag_list_valid
    is_tag_list_valid(["200", 100])
    assert True


def test_is_tag_list_invalid(mocker):
    mock_misp(mocker)
    from MISPV3 import is_tag_list_valid
    with pytest.raises(DemistoException) as e:
        is_tag_list_valid(["abc", 100, "200"])
        if not e:
            assert False


@pytest.mark.parametrize('malicious_tag_ids, suspicious_tag_ids, return_malicious_tag_ids, return_suspicious_tag_ids',
                         TAG_IDS_LISTS)
def test_handle_tag_duplication_ids(mocker, malicious_tag_ids, suspicious_tag_ids, return_malicious_tag_ids,
                                    return_suspicious_tag_ids):
    mock_misp(mocker)
    from MISPV3 import handle_tag_duplication_ids
    assert return_malicious_tag_ids, return_suspicious_tag_ids == handle_tag_duplication_ids(malicious_tag_ids,
                                                                                             suspicious_tag_ids)


def test_convert_arg_to_misp_args(mocker):
    mock_misp(mocker)
    from MISPV3 import convert_arg_to_misp_args
    args = {'dst_port': 8001, 'src_port': 8002, 'name': 'test'}
    args_names = ['dst_port', 'src_port', 'name']
    assert convert_arg_to_misp_args(args, args_names) == [{'dst-port': 8001}, {'src-port': 8002}, {'name': 'test'}]


def test_pagination_args_valid(mocker):
    mock_misp(mocker)
    from MISPV3 import pagination_args_validation
    pagination_args_validation("5", 50)
    assert True


def test_pagination_args_invalid(mocker):
    mock_misp(mocker)
    from MISPV3 import pagination_args_validation
    with pytest.raises(DemistoException) as e:
        pagination_args_validation("page", "3")
        if not e:
            assert False
