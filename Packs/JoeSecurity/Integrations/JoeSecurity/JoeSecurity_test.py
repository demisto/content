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
    import demistomock as demisto
    mocker.patch.object(demisto, 'params', return_value={'url': 'www.example.com'})
    mocker.patch('JoeSecurity.http_post', side_effect=mock_http_post)
    mocker.patch('JoeSecurity.info_request', side_effect=mock_info_request)
    mocker.patch('JoeSecurity.analysis_to_entry', side_effect=mock_analysis_to_entry)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'README.md', 'name': 'abc\def.txt'})

    from JoeSecurity import analyse_sample_file_request
    result = analyse_sample_file_request(123456, False, True, comments='', systems='')

    assert result.get('sample')[0] == 'abc/def.txt'
