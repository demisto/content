def mock_misp(mocker):
    from pymisp import ExpandedPyMISP
    mocker.patch.object(ExpandedPyMISP, '__init__', return_value=None)


def test_get_misp_threat_level(mocker):
    mock_misp(mocker)
    from MISP_V2 import get_misp_threat_level
    assert get_misp_threat_level('1') == 'HIGH'
    assert get_misp_threat_level('2') == 'MEDIUM'
    assert get_misp_threat_level('3') == 'LOW'
    assert get_misp_threat_level('4') == 'UNDEFINED'


def test_get_dbot_level(mocker):
    mock_misp(mocker)
    from MISP_V2 import get_dbot_level
    assert get_dbot_level('1') == 3
    assert get_dbot_level('2') == 3
    assert get_dbot_level('3') == 2
    assert get_dbot_level('4') == 0
    assert get_dbot_level('random') == 0


def test_convert_timestamp(mocker):
    mock_misp(mocker)
    from MISP_V2 import convert_timestamp
    assert convert_timestamp(1546713469) == "2019-01-05 18:37:49"


def test_build_list_from_dict(mocker):
    mock_misp(mocker)
    from MISP_V2 import build_list_from_dict
    lst = build_list_from_dict({'ip': '8.8.8.8', 'domain': 'google.com'})
    assert lst == [{'ip': '8.8.8.8'}, {'domain': 'google.com'}]


def test_extract_error(mocker):
    mock_misp(mocker)
    from MISP_V2 import extract_error
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

    # TODO check errors
