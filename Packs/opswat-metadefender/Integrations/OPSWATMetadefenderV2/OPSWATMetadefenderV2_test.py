from CommonServerPython import *
import pytest
import tempfile

BASE_URL = "http://localhost:8008/metascan_rest/"


# This method will be used by the mock to replace requests.post
def mocked_requests_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

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
    - The String type was parsed correctly.
    """
    _, file_path = tempfile.mkstemp(prefix=file_name, suffix=file_type)
    with open(file_path, 'w') as temp_file:
        temp_file.write(data)
    mocker.patch.object(demisto, 'getFilePath', return_value={"path": file_path, "name": file_name})
    mocker.patch.object(demisto, 'params', return_value={'url': BASE_URL})
    mocker.patch.object(requests, 'post', side_effect=mocked_requests_post)

    from OPSWATMetadefenderV2 import scan_file
    res, extracted_file_name = scan_file('1191@302')

    assert res.get('data_id') == 'mock_id'
    assert file_name == extracted_file_name
