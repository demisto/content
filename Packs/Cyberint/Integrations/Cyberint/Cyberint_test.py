import json
from datetime import datetime, timedelta

from CommonServerPython import EntryType

BASE_URL = 'https://test.cyberint.io/alert'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def load_mock_response(file_name: str) -> str:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


def test_cyberint_alerts_fetch_command(requests_mock):
    """
    Scenario: List alerts
    Given:
     - User has provided valid credentials.
    When:
     - cyberint_alert_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from Cyberint import Client, cyberint_alerts_fetch_command
    mock_response = load_mock_response('csv_example.csv')
    requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-3/attachments/X', json=mock_response)
    mock_response = json.loads(load_mock_response('list_alerts.json'))
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    result = cyberint_alerts_fetch_command(client, {})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == 'Cyberint.Alert'
    assert result.outputs[0].get('ref_id') == 'ARG-3'


def test_cyberint_alerts_status_update_command(requests_mock):
    """
    Scenario: Update alert statuses.
    Given:
     - User has provided valid credentials.
    When:
     - cyberint_alert_update is called.
     - Fetch incidents - for each incident
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from Cyberint import Client, cyberint_alerts_status_update
    mock_response = {}
    requests_mock.put(f'{BASE_URL}/api/v1/alerts/status', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    result = cyberint_alerts_status_update(client, {'alert_ref_ids': 'alert1',
                                                    'status': 'acknowledged'})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'Cyberint.Alert'
    assert result.outputs[0].get('ref_id') == 'alert1'
    result = cyberint_alerts_status_update(client, {'alert_ref_ids': 'alert1,alert2',
                                                    'status': 'acknowledged'})
    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'Cyberint.Alert'
    assert result.outputs[1].get('ref_id') == 'alert2'


def test_fetch_incidents(requests_mock) -> None:
    """
    Scenario: Fetch incidents.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - Every time fetch_incident is called (either timed or by command).
    Then:
     - Ensure number of incidents is correct.
     - Ensure last_fetch is correctly configured according to mock response.
    """
    from Cyberint import Client, fetch_incidents
    mock_response = load_mock_response('csv_example.csv')
    requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-3/attachments/X', json=mock_response)
    requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-4/attachments/X', json=mock_response)

    with open('test_data/expert_analysis_mock.pdf', 'rb') as pdf_content_mock:
        requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-4/analysis_report', content=pdf_content_mock.read())

    mock_response = json.loads(load_mock_response('list_alerts.json'))
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    last_fetch, incidents = fetch_incidents(client, {'last_fetch': 100000000}, '3 days', [], [],
                                            [], [], 50)
    wanted_time = datetime.timestamp(datetime.strptime('2020-12-30T00:00:57Z', DATE_FORMAT))
    assert last_fetch.get('last_fetch') == wanted_time * 1000
    assert len(incidents) == 3
    assert incidents[0].get('name') == 'Cyberint alert ARG-3: Company Customer Credentials Exposed'


def test_fetch_incidents_no_last_fetch(requests_mock):
    """
    Scenario: Fetch incidents for the first time, so there is no last_fetch available.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
     - First time running fetch incidents.
    When:
     - Every time fetch_incident is called (either timed or by command).
    Then:
     - Ensure number of incidents is correct.
     - Ensure last_fetch is correctly configured according to mock response.
    """
    from Cyberint import Client, fetch_incidents
    mock_response = load_mock_response('csv_example.csv')
    requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-3/attachments/X', json=mock_response)

    with open('test_data/expert_analysis_mock.pdf', 'rb') as pdf_content_mock:
        requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-4/analysis_report', content=pdf_content_mock.read())
    requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-4/attachments/X', json=mock_response)

    mock_response = json.loads(load_mock_response('list_alerts.json'))
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    last_fetch, incidents = fetch_incidents(client, {'last_fetch': 100000000}, '3 days', [], [],
                                            [], [], 50)
    wanted_time = datetime.timestamp(datetime.strptime('2020-12-30T00:00:57Z', DATE_FORMAT))
    assert last_fetch.get('last_fetch') == wanted_time * 1000
    assert len(incidents) == 3
    assert incidents[0].get('name') == 'Cyberint alert ARG-3: Company Customer Credentials Exposed'


def test_fetch_incidents_empty_response(requests_mock):
    """
        Scenario: Fetch incidents but there are no incidents to return.
        Given:
         - User has provided valid credentials.
         - Headers and JWT token have been set.
        When:
         - Every time fetch_incident is called (either timed or by command).
         - There are no incidents to return.
        Then:
         - Ensure number of incidents is correct (None).
         - Ensure last_fetch is correctly configured according to mock response.
        """
    from Cyberint import Client, fetch_incidents
    mock_response = json.loads(load_mock_response('empty.json'))
    requests_mock.post(f'{BASE_URL}/api/v1/alerts', json=mock_response)
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    last_fetch, incidents = fetch_incidents(client, {'last_fetch': 100000000}, '3 days', [], [],
                                            [], [], 50)
    assert last_fetch.get('last_fetch') == 100001000
    assert len(incidents) == 0


def test_set_date_pair():
    """
        Scenario: Set date_start and date_end for both creation and modification.
        Given:
         - User has provided valid credentials.
        When:
         - Every time cyberint_list_alerts is called.
        Then:
         - Ensure dates return match what is needed (correct format)
    """
    from Cyberint import set_date_pair
    start_time = '2020-12-01T00:00:00Z'
    end_time = '2020-12-05T00:00:00Z'
    assert set_date_pair(start_time, end_time, None) == (start_time, end_time)
    new_range = '3 Days'
    three_days_ago = datetime.strftime(datetime.now() - timedelta(days=3), DATE_FORMAT)
    current_time = datetime.strftime(datetime.now(), DATE_FORMAT)
    assert set_date_pair(start_time, end_time, new_range) == (three_days_ago, current_time)

    assert set_date_pair(start_time, None, None) == (start_time, datetime.strftime(datetime.now(),
                                                                                   DATE_FORMAT))
    assert set_date_pair(None, end_time, None) == (datetime.strftime(datetime.
                                                                     fromisocalendar(2020, 2, 1),
                                                                     DATE_FORMAT), end_time)


def test_extract_data_from_csv_stream(requests_mock):
    """
        Scenario: Extract data out of a downloaded csv file.
        Given:
         - User has provided valid credentials.
        When:
         - A fetch command is called and there is a CSV file reference in the response.
        Then:
         - Ensure all fields in the CSV are returned.
         - Ensure the wanted fields are found when downloaded.
         - Ensure a sample value matches what is in the sample CSV.
    """
    from Cyberint import Client, extract_data_from_csv_stream, CSV_FIELDS_TO_EXTRACT
    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    mock_response = load_mock_response('csv_no_username.csv')
    requests_mock.get(f'{BASE_URL}/api/v1/alerts/alert_id/attachments/123', json=mock_response)
    result = extract_data_from_csv_stream(client, 'alert_id', '123')
    assert len(result) == 0
    mock_response = load_mock_response('csv_example.csv')
    requests_mock.get(f'{BASE_URL}/api/v1/alerts/alert_id/attachments/123', json=mock_response)
    result = extract_data_from_csv_stream(client, 'alert_id', '123', delimiter=b'\\n')
    assert len(result) == 6
    assert list(result[0].keys()) == [value.lower() for value in CSV_FIELDS_TO_EXTRACT]
    assert result[0]['username'] == 'l1'


def test_cyberint_alerts_analysis_report_command(requests_mock):
    """
        Scenario: Retrieve expert analysis report.
        Given:
         - User has provided valid credentials and arguments.
        When:
         - A alerts-analysis-report is called and there analysis report reference in the response.
        Then:
         - Ensure that the return ContentsFormat of the file is 'text'.
         - Ensure that the return Type is file.
         - Ensure the name of the file.
    """
    from Cyberint import Client, cyberint_alerts_get_analysis_report_command

    with open('test_data/expert_analysis_mock.pdf', 'rb') as pdf_content_mock:
        requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-4/analysis_report', content=pdf_content_mock.read())

    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    result = cyberint_alerts_get_analysis_report_command(client, "ARG-4", "expert_analysis_mock.pdf")
    assert result['ContentsFormat'] == 'text'
    assert result['Type'] == EntryType.FILE
    assert result['File'] == "expert_analysis_mock.pdf"


def test_cyberint_alerts_get_attachment_command(requests_mock):
    """
         Scenario: Retrieve alert attachment.
         Given:
          - User has provided valid credentials and arguments.
         When:
          - A alerts-get-attachment called and there attachments reference in the response.
         Then:
          - Ensure that the return ContentsFormat of the file is 'text'.
          - Ensure that the return Type is file.
          - Ensure the name of the file.
     """
    from Cyberint import Client, cyberint_alerts_get_attachment_command

    with open('test_data/attachment_file_mock.png', 'rb') as png_content_mock:
        requests_mock.get(f'{BASE_URL}/api/v1/alerts/ARG-3/attachments/X', content=png_content_mock.read())

    client = Client(base_url=BASE_URL, verify_ssl=False, access_token='xxx', proxy=False)
    result = cyberint_alerts_get_attachment_command(client, "ARG-3", "X", "attachment_file_mock.png")
    assert result['ContentsFormat'] == 'text'
    assert result['Type'] == EntryType.FILE
    assert result['File'] == "attachment_file_mock.png"
