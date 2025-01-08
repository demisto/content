from CommonServerPython import *
import pytest
import tempfile

BASE_URL = "http://localhost:8008/metascan_rest/"
SCAN_RESULTS_RES_1: dict = {}
SCAN_RESULTS_RES_2: dict = {'file_info': {'file_type_description': 'type_desc', 'display_name': 'display_name',
                                          'md5': 'some_md5_hash'},
                            'process_info': {'progress_percentage': 50},
                            'scan_results': {'total_avs': 100, 'scan_all_result_a': 'scan_all_result_a', 'scan_all_result_i': 100,
                                             'scan_details': {'key': {'def_time': '1/1/2023', 'threat_found': 'threat'}}}}
HASH_INFO_RES_1: dict = {}
HASH_INFO_RES_2: dict = {'file_info': {'display_name': 'display_name', 'file_type_description': 'type_desc'},
                         'scan_results': {'scan_all_result_a': 'scan_all_result_a', 'total_detected_avs': 100, 'total_avs': 100,
                                          'scan_details': {'key': {'def_time': '1/1/2023', 'threat_found': 'threat'}}}}


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


# This method will be used by the mock to replace requests.post
def mocked_requests_post(*args, **kwargs):
    file_name = kwargs.get('headers', {}).get('filename', '')
    try:
        if type(file_name) is str:
            file_name.encode('latin-1')
        else:
            file_name.decode('latin-1')
        return MockResponse({"data_id": "mock_id"}, 200)
    except Exception as e:
        return MockResponse(str(e), 404)


@pytest.mark.parametrize(
    "file_name, data, expected_md_results",
    [
        (
            "2022年年年年年.docx",
            "年年年年年",
            "# OPSWAT-Metadefender\nThe file has been successfully submitted to scan.\nScan id: mock_id\n",
        )
    ],
)
def test_scan_file_command(mocker, file_name, data, expected_md_results):
    """
    Given:
    - File_name and content to mock file_entry.
    - case 1: a docx file with chinese letters in the name and content
    When:
    - Calling scan_file_command.
    Then:
    - Ensures the String type was parsed correctly and that the entry was generated correctly.
    - case 1: Ensures the request didn't fail due to letters parsing issue and that the entry was generated correctly.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = f'{temp_dir}/{file_name}'
        with open(file_path, 'w') as f:
            f.write(data)
        mocker.patch.object(demisto, 'getFilePath', return_value={"path": file_path, "name": file_name})
        mocker.patch.object(demisto, 'params', return_value={'url': BASE_URL})
        mocker.patch.object(requests, 'post', side_effect=mocked_requests_post)
        mocker.patch.object(demisto, 'args', return_value={'fileId': '1191@302', 'scanRule': 'Test'})
        mocker.patch.object(demisto, 'results')

        from OPSWATMetadefenderV2 import scan_file_command
        scan_file_command()

    entry = demisto.results.call_args[0][0]
    ec_results = entry.get('EntryContext', {}).get('OPSWAT', {})
    assert entry.get('HumanReadable') == expected_md_results
    assert ec_results.get('ScanId') == 'mock_id'
    assert ec_results.get('FileName') == file_name


# This method will be used by the mock to replace requests.get
def mocked_requests_get(*args, **kwargs):
    url = args[0]
    data = {}
    if 'file' in url:
        id = url[-1]
        if id == '1':
            data = SCAN_RESULTS_RES_1
        elif id == '2':
            data = SCAN_RESULTS_RES_2
    elif 'hash' in url:
        hash = url[-32:]
        if hash == '9d59494ca97bac09a2fb22188b03961f':
            data = HASH_INFO_RES_1
        elif hash == '9d59494ca97bac09a2fb22188b03961s':
            data = HASH_INFO_RES_2
    return MockResponse(data, 200)


@pytest.mark.parametrize('id, expected_md_results', [
    ('1', '# OPSWAT-Metadefender\n### Results for scan id 1\nNo results for this id\n'),
    ('2', "# OPSWAT-Metadefender\n### Results for scan id 2\n### The scan proccess is in progrees (done: 50%) \nFile "
        "name: display_name\nScan result:scan_all_result_a\nDetected AV: 100/100\nAV Name|Def Time|Threat Name Found\n"
        "---|---|---\nkey|1/1/2023|threat\n")
])
def test_get_scan_result_command(mocker, id, expected_md_results):
    """
    Given:
    - a file id.
    - case 1: an id that return empty response
    - case 2: an id that return a non empty response
    When:
    - Running get_scan_result_command.
    Then:
    - Ensures the HumanReadable in the result entry was generated correctly.
    - case 1: Ensures the human readable contains a no results message.
    - case 2: Ensures the table in the human readable was generated correctly.
    """
    mocker.patch.object(demisto, 'params', return_value={'url': BASE_URL})
    mocker.patch.object(requests, 'get', side_effect=mocked_requests_get)
    mocker.patch.object(demisto, 'args', return_value={'id': id})
    mocker.patch.object(demisto, 'results')

    from OPSWATMetadefenderV2 import get_scan_result_command
    get_scan_result_command()
    entry = demisto.results.call_args[0][0]
    assert entry.get('HumanReadable') == expected_md_results


@pytest.mark.parametrize('hash, expected_md_results', [
    ('9d59494ca97bac09a2fb22188b03961f', '# OPSWAT-Metadefender\nNo results for hash 9d59494ca97bac09a2fb22188b03961f\n'),
    ('9d59494ca97bac09a2fb22188b03961s', "# OPSWAT-Metadefender\nFile name: display_name\nFile description: type_desc\n"
     "Scan result: scan_all_result_a\nDetected AV: 100/100\nAV Name|Def Time|Threat Name Found\n"
     "---|---|---\nkey|1/1/2023|threat\n")
])
def test_get_hash_info_command(mocker, hash, expected_md_results):
    """
    Given:
    - a file hash.
    - case 1: a hash that return empty response
    - case 2: a hash that return a non empty response
    When:
    - Running get_hash_info_command.
    Then:
    - Ensures the HumanReadable in the result entry was generated correctly.
    - case 1: Ensures the human readable contains a no results message.
    - case 2: Ensures the table in the human readable was generated correctly.
    """
    mocker.patch.object(demisto, 'params', return_value={'url': BASE_URL})
    mocker.patch.object(requests, 'get', side_effect=mocked_requests_get)
    mocker.patch.object(demisto, 'args', return_value={'hash': hash})
    mocker.patch.object(demisto, 'results')

    from OPSWATMetadefenderV2 import get_hash_info_command
    get_hash_info_command()
    entry = demisto.results.call_args[0][0]
    assert entry.get('HumanReadable') == expected_md_results


def test_get_sanitized_file_command(mocker):
    """
    Given:
    - a file id.
    When:
    - Running get_sanitized_file_command.
    Then:
    - Ensures that sanitized file was created.
    """
    mocker.patch.object(demisto, 'args', return_value={'id': '1'})
    mocker.patch.object(demisto, 'params', return_value={'url': BASE_URL})
    mocker.patch('OPSWATMetadefenderV2.get_scan_result',
                 return_value={'process_info': {'post_processing':
                                                {'converted_destination': 'sanitized.pdf', 'actions_ran': 'Sanitized'}}})
    mocker.patch('OPSWATMetadefenderV2.get_sanitized_file',
                 return_value=b'sanitized file content')
    mocker.patch.object(demisto, 'results')
    from OPSWATMetadefenderV2 import get_sanitized_file_command
    get_sanitized_file_command()
    entry = demisto.results.call_args[0][0]
    assert entry.get('File') == 'sanitized.pdf'


def test_get_sanitized_file_fail_command(mocker):
    """
    Given:
    - a file id.
    When:
    - Running get_sanitized_file_command.
    Then:
    - Ensures that sanitized file wasn't created and warning was created.
    """
    mocker.patch.object(demisto, 'args', return_value={'id': '1'})
    mocker.patch.object(demisto, 'params', return_value={'url': BASE_URL})
    mocker.patch('OPSWATMetadefenderV2.get_scan_result', return_value={'process_info': {}})
    mocker.patch('OPSWATMetadefenderV2.get_sanitized_file',
                 return_value=b'sanitized file content')
    mocker.patch.object(demisto, 'results')
    from OPSWATMetadefenderV2 import get_sanitized_file_command
    get_sanitized_file_command()
    entry = demisto.results.call_args[0][0]
    assert entry == {'Type': 11, 'ContentsFormat': 'text', 'Contents': 'No sanitized file.'}
