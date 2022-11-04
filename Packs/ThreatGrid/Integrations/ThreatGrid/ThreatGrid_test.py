import os
import pytest
import demistomock as demisto  # noqa: F401

os.environ["HTTP_PROXY"] = "test"
os.environ["HTTPS_PROXY"] = "test"
os.environ["http_proxy"] = "test"
os.environ["https_proxy"] = "test"
PARAMS = {
    'server': 'test',
    'proxy': True,
    'disregard_quota': True,
}

LIST_MOCK = [
    {
        'Country': 'IL',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip',
        'location': '32.0123, 34.7705'
    },
    {
        'Country': 'BE',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip',
        'location': '50.8847, 4.5049'
    }]


def test_get_with_limit_list(mocker):
    """
    Given:
        demisto context
    When:
        Executing get_with_limit function
    Then
        ensure limit was made
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import get_with_limit

    mocker.patch.object(demisto, 'get', return_value=LIST_MOCK)

    res = get_with_limit('mock_obj', 'mock_path', 1)
    assert len(res) == 1


DICT_MOCK = {
    'Country': 'IL',
    'event_timestamp': '2022-03-02T10: 06: 09Z',
    'identity_display_name': 'paanalyticstest',
    'ip': 'ip',
    'location': '32.0123, 34.7705'
}


def test_get_with_limit_dict(mocker):
    """
    Given:
        demisto context
    When:
        Executing get_with_limit function
    Then
        ensure limit was made
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import get_with_limit

    mocker.patch.object(demisto, 'get', return_value=DICT_MOCK)

    res = get_with_limit('mock_obj', 'mock_path', 1)
    assert len(res) == 1
    assert len(res.get('Country'))


def test_get_with_limit_fail(mocker):
    """
    Given:
        demisto context
    When:
        Executing get_with_limit function
    Then
        ensure limit was made
    """
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import get_with_limit

    mocker.patch.object(demisto, 'get', return_value="Some string")

    res = get_with_limit('mock_obj', 'mock_path', 1)
    assert res == 'Some string'


@pytest.mark.parametrize('test_dict, expected_result', [
    (
        {'Sample': {'File': [],
                    'Domain': {},
                    'Regitry Keys Created': ['test'],
                    'Sample': {'test': 'test'}},
         'File': 'test',
         'Artifact': 'test'},
        {'Sample': {'File': []}, 'File': 'test', 'Artifact': 'test'}
    )
])
def test_create_analysis_json_human_readable(mocker, test_dict, expected_result):

    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    from ThreatGrid import create_analysis_json_human_readable
    mocker.patch('ThreatGrid.tableToMarkdown', return_value='test')
    create_analysis_json_human_readable(test_dict)
    assert test_dict == expected_result
