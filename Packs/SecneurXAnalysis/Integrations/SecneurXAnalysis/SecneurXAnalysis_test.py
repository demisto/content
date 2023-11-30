import json
import demistomock as demisto


API_KEY = "1234"
DATA_KEY = "data"
SERVER_URL = "http://test.com/api/v1"
HEADERS = {'api-key': API_KEY}


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_verdict_command(requests_mock):
    from SecneurXAnalysis import Client, get_verdict_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['verdict_response']
    requests_mock.get(f'{SERVER_URL}/get_verdict', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'task_uuid': '13bd267ca3d7af495f8cd8f72daf3ea997312671eafe9992a88768e4f3ecc601-2022-06-07-14-40-46'}
    res = get_verdict_cmd(client, args)
    assert res.raw_response == mock_response[DATA_KEY]


def test_get_verdict_failure(requests_mock):
    from SecneurXAnalysis import Client, get_verdict_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['error_response']
    requests_mock.get(f'{SERVER_URL}/get_verdict', json=mock_response['invalid_error_res'])
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'task_uuid': '13bd267ca3d7af495f8cd8f72daf3ea997312671eafe9992a88768e4f3ecc601-2022-06-07-14-40-46'}
    res = get_verdict_cmd(client, args)
    assert res.raw_response == mock_response['invalid_error_res']


def test_get_completed_command(requests_mock):
    from SecneurXAnalysis import Client, get_completed_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['completed_response']
    requests_mock.get(f'{SERVER_URL}/get_completed', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'last_count': 2}
    res = get_completed_cmd(client, args)
    assert len(res.raw_response) == 2
    assert res.raw_response == mock_response[DATA_KEY]


def test_get_completed_failure(requests_mock):
    from SecneurXAnalysis import Client, get_completed_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['error_response']
    requests_mock.get(f'{SERVER_URL}/get_completed', json=mock_response['empty_error_res'])
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'last_hours': 1}
    res = get_completed_cmd(client, args)
    assert res.raw_response == mock_response['completed_cmd_res']

    requests_mock.get(f'{SERVER_URL}/get_completed', json=mock_response['metadata_error_res'])
    res = get_completed_cmd(client, {'last_hour': '1'})
    assert res.outputs == mock_response['metadata_error_res']


def test_get_pending_command(requests_mock):
    from SecneurXAnalysis import Client, get_pending_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['pending_response']
    requests_mock.get(f'{SERVER_URL}/get_processing', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'last_count': 2}
    res = get_pending_cmd(client, args)
    assert len(res.raw_response) == 2
    assert res.raw_response[0]['task_uuid'] == mock_response[DATA_KEY][0]['task_uuid']


def test_get_pending_failure(requests_mock):
    from SecneurXAnalysis import Client, get_pending_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['error_response']
    requests_mock.get(f'{SERVER_URL}/get_processing', json=mock_response['empty_error_res'])
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'last_hours': 1}
    res = get_pending_cmd(client, args)
    assert res.raw_response == mock_response['pending_cmd_res']

    requests_mock.get(f'{SERVER_URL}/get_processing', json=mock_response['metadata_error_res'])
    res = get_pending_cmd(client, {'last_hour': '1'})
    assert res.outputs == mock_response['metadata_error_res']


def test_get_sample_status_command(requests_mock):
    from SecneurXAnalysis import Client, get_status_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['status_response']
    requests_mock.get(f'{SERVER_URL}/get_status', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'last_count': 2}
    res = get_status_cmd(client, args)
    assert len(res.raw_response) == 2
    assert res.raw_response[0]['task_uuid'] == mock_response[DATA_KEY][0]['task_uuid']


def test_get_sample_status_failure(requests_mock):
    from SecneurXAnalysis import Client, get_status_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['error_response']
    requests_mock.get(f'{SERVER_URL}/get_status', json=mock_response['empty_error_res'])
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'last_hours': 1}
    res = get_status_cmd(client, args)
    assert res.raw_response == mock_response['status_cmd_res']

    requests_mock.get(f'{SERVER_URL}/get_status', json=mock_response['metadata_error_res'])
    res = get_status_cmd(client, {'last_hour': '1'})
    assert res.outputs == mock_response['metadata_error_res']


def test_get_report_command(requests_mock, mocker):
    from SecneurXAnalysis import Client, get_report_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['report_response']
    requests_mock.get(f'{SERVER_URL}/get_report', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {
        'task_uuid': 'd0cde86d47219e9c56b717f55dcdb01b0566344c13aa671613598cab427345b9-2022-07-06-07-42-33',
        'report_format': 'json'
    }
    res = get_report_cmd(client, args)
    assert res.outputs['Verdict'] == 'Malware'


def test_get_report_command_failure(requests_mock):
    from SecneurXAnalysis import Client, get_report_cmd

    response = util_load_json('test_data/get_response_example.json')
    mock_response = response['error_response']
    requests_mock.get(f'{SERVER_URL}/get_report', json=mock_response['metadata_error_res'])
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'task_uuid': '13bd267ca3d7af495f8cd8f72daf3ea997312671eafe9992a88768e4f3ecc601-2022-06-07-14-40-46'}
    res = get_report_cmd(client, args)
    assert res.raw_response == mock_response['metadata_error_res']

    response = util_load_json('test_data/get_response_example.json')
    mock_response = response['pending_response']
    requests_mock.get(f'{SERVER_URL}/get_report', json={'success': 1, 'data': mock_response[DATA_KEY][0]})
    args = {'task_uuid': 'e94e76882b30f4050d456d126ec76713b8e997a193ac80269f090f394290086b-2022-07-05-06-59-01'}
    res = get_report_cmd(client, args)
    assert res.raw_response[DATA_KEY] == mock_response[DATA_KEY][0]


def test_post_url_command(requests_mock):
    from SecneurXAnalysis import Client, post_submit_url

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['submit_url_response']
    requests_mock.post(f'{SERVER_URL}/analyze_url', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'URL': 'https://google.com'}
    res = post_submit_url(client, args)
    assert res.raw_response == mock_response[DATA_KEY]


def test_post_url_command_failure(requests_mock):
    from SecneurXAnalysis import Client, post_submit_url

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['error_response']
    requests_mock.post(f'{SERVER_URL}/analyze_url', json=mock_response['submit_failed_res'], status_code=200)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'URL': 'https://google.com'}
    res = post_submit_url(client, args)
    assert res.raw_response == mock_response['submit_failed_res']


def test_post_sample_command(requests_mock, mocker):
    from SecneurXAnalysis import Client, post_submit_file

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['submit_file_response']
    requests_mock.post(f'{SERVER_URL}/submit_file', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    args = {'EntryID': 1, 'platform': 'windows'}
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'test_data/dummy_file.txt', 'name': 'dummy_file.txt'})
    res = post_submit_file(client, args)
    assert res.raw_response == mock_response[DATA_KEY]


def test_requests_params_dict():
    from SecneurXAnalysis import create_request_json

    paramsDict = {
        'task_uuid': '1234',
        'last_count': 10,
        'last_hours': 2,
        'Platform': 'windows',
        'Priority': 'high',
        'Extension': 'exe',
        'Duration': '120',
        'File Password': 'password',
        'Reboot': True,
        'report_format': 'html'
    }
    reqDict = create_request_json(paramsDict)
    assert len(reqDict.keys()) == 10


def test_module_connection(requests_mock):
    from SecneurXAnalysis import Client, SNXErrorMsg, test_module

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['status_response']
    requests_mock.get(f'{SERVER_URL}/get_status', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    msg = test_module(client)
    assert msg == SNXErrorMsg.SUCCESS_MSG


def test_module_connection_failure(requests_mock):
    from SecneurXAnalysis import Client, SNXErrorMsg, test_module

    requests_mock.get(f'{SERVER_URL}/get_status', json=None)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    try:
        test_module(client)
    except Exception as e:
        assert e.message == SNXErrorMsg.CONFIG_ERR


def test_connection_response(requests_mock):
    from SecneurXAnalysis import SNXErrorMsg, error_response

    requests_mock.get(f'{SERVER_URL}/get_status', json=None, status_code=403)
    try:
        error_response(None)
    except Exception as e:
        assert e == SNXErrorMsg.INVALID_ERR


def test_quoto_cmd(requests_mock):
    from SecneurXAnalysis import Client, get_quota_cmd

    res = util_load_json('test_data/get_response_example.json')
    mock_response = res['quota_response']
    requests_mock.get(f'{SERVER_URL}/get_quota', json=mock_response)
    client = Client(
        base_url=SERVER_URL,
        verify=False,
        headers=HEADERS,
        proxy=False
    )
    res = get_quota_cmd(client)
    assert res.outputs == mock_response[DATA_KEY]
