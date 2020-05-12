from FalconX import Client, test_module,\
    upload_file_command, send_uploaded_file_to_sendbox_analysis_command, send_url_to_sandbox_analysis_command,\
    get_full_report_command, get_report_summary_command, get_analysis_status_command, download_ioc_command, \
    check_quota_status_command, find_sandbox_reports_command, find_submission_id_command


def test_say_hello():
    client = Client(base_url='https://test.com', verify=False, auth=('test', 'test'))
    args = {
        'name': 'Dbot'
    }
    _, outputs, _ = say_hello_command(client, args)

    assert outputs['hello'] == 'Hello Dbot'


def test_say_hello_over_http(requests_mock):
    mock_response = {'result': 'Hello Dbot'}
    requests_mock.get('https://test.com/hello/Dbot', json=mock_response)

    client = Client(base_url='https://test.com', verify=False, auth=('test', 'test'))
    args = {
        'name': 'Dbot'
    }
    _, outputs, _ = say_hello_over_http_command(client, args)

    assert outputs['hello'] == 'Hello Dbot'
