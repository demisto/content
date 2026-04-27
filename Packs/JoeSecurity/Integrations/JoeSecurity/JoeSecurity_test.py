import os

import demistomock as demisto
import pytest


def mock_http_post(suffix_url, data=None, files=None, parse_json=True):
    return {'data': {'webids': [files]}}


def mock_info_request(web_id):
    return {'data': web_id}


def mock_analysis_to_entry(title, info):
    return info


def test_analyse_sample_file_request(mocker):
    """
    Given:
        A file with a backslash in it's name
    When:
        joe-analysis-submit-sample is running
    Then:
        Make sure that the file name changed with a regular slash ('abc\def.txt' => 'abc/def.txt')
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'www.example.com'})
    mocker.patch('JoeSecurity.http_post', side_effect=mock_http_post)
    mocker.patch('JoeSecurity.info_request', side_effect=mock_info_request)
    mocker.patch('JoeSecurity.analysis_to_entry', side_effect=mock_analysis_to_entry)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'README.md', 'name': 'abc\def.txt'})

    from JoeSecurity import analyse_sample_file_request
    result = analyse_sample_file_request(123456, False, True, comments='', systems='')

    assert result.get('sample')[0] == 'abc/def.txt'


@pytest.mark.parametrize(
    "input_name, expected_basename",
    [
        ("/tmp/evil/../../../etc/passwd", "passwd"),
        ("report.pdf", "report.pdf"),
    ],
)
def test_analyse_sample_file_uses_basename(mocker, input_name, expected_basename):
    """
    Given:
        - A file entry with a name that may contain directory components or path-traversal sequences,
          or a standard filename with no directory components.
    When:
        - Calling joe-analysis-submit-sample.
    Then:
        - Verify that only the basename of the file name is used.
    """
    mocker.patch.object(demisto, 'params', return_value={'url': 'www.example.com'})
    mocker.patch('JoeSecurity.http_post', side_effect=mock_http_post)
    mocker.patch('JoeSecurity.info_request', side_effect=mock_info_request)
    mocker.patch('JoeSecurity.analysis_to_entry', side_effect=mock_analysis_to_entry)
    mocker.patch.object(
        demisto, 'getFilePath',
        return_value={'path': 'README.md', 'name': input_name},
    )

    from JoeSecurity import analyse_sample_file_request
    result = analyse_sample_file_request(123456, False, True, comments='', systems='')

    # Verify the file name used is the basename only
    file_name_used = result.get('sample')[0]
    assert file_name_used == expected_basename
    assert os.path.basename(file_name_used) == file_name_used
