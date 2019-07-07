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

