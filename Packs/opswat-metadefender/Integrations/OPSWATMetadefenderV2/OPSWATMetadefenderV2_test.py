from CommonServerPython import *
import pytest
import tempfile

BASE_URL = "http://localhost:8008/metascan_rest/"
RES_1: dict = {}
RES_2: dict = {'file_info': {'file_type_description': 'type_desc', 'display_name': 'display_name', 'md5': 'some_md5_hash'},
               'process_info': {'progress_percentage': 50},
               'scan_results': {'total_avs': 100, 'scan_all_result_a': 'scan_all_result_a', 'scan_all_result_i': 100,
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
        if type(file_name) == str:
            file_name.encode('latin-1')
        else:
            file_name.decode('latin-1')
        return MockResponse({"data_id": "mock_id"}, 200)
    except Exception as e:
        return MockResponse(str(e), 404)


@pytest.mark.parametrize('file_name, file_type, data', [
    ('2022年年年年年', 'docx', '年年年年年')
])
def test_file_scan_command(mocker, file_name, file_type, data):
    """
    Given:
    - a file_path and file_name to mock file_entry.
    When:
    - Running scan_file function.
    Then:
    - Ensures the String type was parsed correctly.
    """
    try:
        _, file_path = tempfile.mkstemp(prefix=file_name, suffix=file_type)
        with open(file_path, 'w') as temp_file:
            temp_file.write(data)
        mocker.patch.object(demisto, 'getFilePath', return_value={"path": file_path, "name": file_name})
        mocker.patch.object(demisto, 'params', return_value={'url': BASE_URL})
        mocker.patch.object(requests, 'post', side_effect=mocked_requests_post)

        from OPSWATMetadefenderV2 import scan_file
        res, extracted_file_name = scan_file('1191@302')
    finally:
        os.remove(file_path)
    assert res.get('data_id') == 'mock_id'
    assert file_name == extracted_file_name


# This method will be used by the mock to replace requests.get
def mocked_requests_get(*args, **kwargs):
    id = args[0][-1]
    data = {}
    if id == '1':
        data = RES_1
    elif id == '2':
        data = RES_2
    return MockResponse(data, 200)


@pytest.mark.parametrize('id, md', [
    ('1', '# OPSWAT-Metadefender\n### Results for scan id 1\nNo results for this id\n'),
    ('2', "# OPSWAT-Metadefender\n### Results for scan id 2\n### The scan proccess is in progrees (done: 50%) \nFile "
        "name: display_name\nScan result:scan_all_result_a\nDetected AV: 100/100\nAV Name|Def Time|Threat Name Found\n"
        "---|---|---\nkey|1/1/2023|threat\n")
])
def test_get_scan_result_command(mocker, id, md):
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
    assert entry.get('HumanReadable') == md
