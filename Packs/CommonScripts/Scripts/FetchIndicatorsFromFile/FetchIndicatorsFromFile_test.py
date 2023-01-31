import pytest

CSV_TEST_RESULTS_1 = [
    {'type': 'File', 'value': '4f79697b40d0932e91105bd496908f8e02c130a0e36f6d3434d6243e79ef82e0'},
    {'type': 'File', 'value': '794cf7644115198db451431bca7c89ff9a97550482b1e3f7f13eb7aca6120a11'},
    {'type': 'File', 'value': 'ec2faa62b6ab93f84e2e8c00f81bc751c0ea559b7a01f6aa08afdb1d93f0f391'},
    {'type': 'File', 'value': 'e315c28cad7be368718b99522740610fe6e1590452ddbb9f2bc83fd773a51879'}
]

CSV_TEST_RESULTS_2 = [
    {'type': 'Domain', 'value': '794cf7644115198db451431bca7c89ff9a97550482b1e3f7f13eb7aca6120a11'},
    {'type': 'Domain', 'value': 'ec2faa62b6ab93f84e2e8c00f81bc751c0ea559b7a01f6aa08afdb1d93f0f391'},
]

XLS_TEST_RESULTS_1 = [
    {'type': 'URL', 'value': 'www.demisto.com/path'},
    {'type': 'Domain', 'value': 'demisto.com'}
]

XLS_TEST_RESULTS_2 = [
    {'type': 'Domain', 'value': 'demisto.com'}
]

TEXT_TEST_RESULT_1 = [
    {'type': 'IP', 'value': '8.8.8.8'},
    {'type': 'IP', 'value': '1.2.3.4'},
    {'type': 'Domain', 'value': 'google.com'},
    {'type': 'URL', 'value': 'www.google.com/path'},
    {'type': 'IPv6', 'value': '2001:db8:85a3:8d3:1319:8a2e:370:7348'}
]

TEXT_TEST_RESULT_2 = [
    {'type': 'File', 'value': 'google.com'},
    {'type': 'File', 'value': 'www.google.com/path'},
]

TEST_INDICATOR_TYPE = [
    ("", True, "default", "text",  # args
     None,  # indicator_type
     None  # result
     ),
    ("", True, None, "csv",  # args
     None,  # indicator_type
     None  # result
     ),
    ("", True, "default", "csv",  # args
     None,  # indicator_type
     "default"  # result
     ),
    ("", True, None, "csv",  # args
     None,  # indicator_type
     None  # result
     ),
    ("", True, None, "csv",  # args
     'file',  # indicator_type
     'file'  # result
     )
]


def test_csv_file_to_indicator_list_1():
    from FetchIndicatorsFromFile import csv_file_to_indicator_list
    result = csv_file_to_indicator_list(file_path='test_data/Hashes_list.csv',
                                        col_num=0, starting_row=0, auto_detect=True, default_type=None, type_col=None,
                                        limit=None, offset=0)
    assert CSV_TEST_RESULTS_1 == result


def test_csv_file_to_indicator_list_2():
    from FetchIndicatorsFromFile import csv_file_to_indicator_list
    result = csv_file_to_indicator_list(file_path='test_data/Hashes_list.csv',
                                        col_num=0, starting_row=1, auto_detect=False, default_type='Domain',
                                        type_col=None, limit=2, offset=0)
    assert CSV_TEST_RESULTS_2 == result


def test_xls_file_to_indicator_list_1():
    from FetchIndicatorsFromFile import xls_file_to_indicator_list
    result = xls_file_to_indicator_list(file_path='test_data/IndicatorsXls.xlsx', sheet_name=None,
                                        col_num=1, starting_row=1, auto_detect=True, default_type=None, type_col=None,
                                        limit=None, offset=0)
    assert result == XLS_TEST_RESULTS_1


def test_xls_file_to_indicator_list_2():
    from FetchIndicatorsFromFile import xls_file_to_indicator_list
    result = xls_file_to_indicator_list(file_path='test_data/IndicatorsXls.xlsx', sheet_name=None,
                                        col_num=1, starting_row=1, auto_detect=False, default_type=None, type_col=4,
                                        limit=3, offset=0)
    assert result == XLS_TEST_RESULTS_1


def test_xls_file_to_indicator_list_3():
    from FetchIndicatorsFromFile import xls_file_to_indicator_list
    result = xls_file_to_indicator_list(file_path='test_data/IndicatorsXls.xlsx', sheet_name=None,
                                        col_num=1, starting_row=1, auto_detect=False, default_type=None, type_col=4,
                                        limit=3, offset=1)
    assert result == XLS_TEST_RESULTS_2


def test_xls_file_to_indicator_list_4():
    from FetchIndicatorsFromFile import xls_file_to_indicator_list
    result = xls_file_to_indicator_list(file_path='test_data/IndicatorsXls.xlsx', sheet_name=None,
                                        col_num=1, starting_row=0, auto_detect=True, default_type=None, type_col=None,
                                        limit=None, offset=0)
    assert result == XLS_TEST_RESULTS_1


def test_txt_file_to_indicator_list_1():
    from FetchIndicatorsFromFile import txt_file_to_indicator_list
    result = txt_file_to_indicator_list(file_path='test_data/IndicatorsList.txt',
                                        auto_detect=True, default_type=None, limit=None, offset=0)

    assert result == TEXT_TEST_RESULT_1


def test_txt_file_to_indicator_list_2():
    from FetchIndicatorsFromFile import txt_file_to_indicator_list
    result = txt_file_to_indicator_list(file_path='test_data/IndicatorsList.txt',
                                        auto_detect=False, default_type="File", limit=2, offset=2)

    assert result == TEXT_TEST_RESULT_2


def test_detect_type():
    from FetchIndicatorsFromFile import detect_type
    assert 'File' == detect_type('4f79697b40d0932e91105bd496908f8e02c130a0e36f6d3434d6243e79ef82e0')
    assert 'Domain' == detect_type('demisto.com')
    assert 'IP' == detect_type('8.8.8.8')
    assert 'IPv6' == detect_type('2001:db8:85a3:8d3:1319:8a2e:370:7348')
    assert 'URL' == detect_type('www.demisto.com/path')
    assert 'CIDR' == detect_type('8.8.8.8/12')
    assert 'Email' == detect_type('some@mail.com')
    assert 'DomainGlob' == detect_type('*.demisto.com')
    assert 'IPv6CIDR' == detect_type('2001:db8:85a3:8d3:1319:8a2e:370:7348/32')
    assert None is detect_type('not_an_indicator')


@pytest.mark.parametrize('indicator_value, auto_detect, default_type, file_type,indicator_type, expected_result',
                         TEST_INDICATOR_TYPE)
def test_get_indicator_type(mocker, indicator_value, auto_detect, default_type, file_type, indicator_type, expected_result):
    """
    Given:
        - indicator_value, auto_detect, default_type, file_type
    When:
        - get_indicator_type function is executed
    Then:
        - Return indicator_type
    """
    from FetchIndicatorsFromFile import get_indicator_type
    mocker.patch('FetchIndicatorsFromFile.detect_type', return_value=indicator_type)
    result = get_indicator_type(indicator_value, auto_detect, default_type, file_type)
    assert expected_result == result


def test_main(mocker):
    """
    Given:
        - All return values from helper functions are valid
    When:
        - main function is executed
    Then:
        - Return results to War-Room
    """
    from FetchIndicatorsFromFile import main
    import demistomock as demisto
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch('FetchIndicatorsFromFile.fetch_indicators_from_file', return_value=("", {}, []))
    main()
