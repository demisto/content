import json
import pytest
from freezegun import freeze_time

"""Helper functions and fixrtures"""


def load_params_from_json(json_path, type=''):
    with open(json_path) as f:
        file = json.load(f)
    if type == "incidents":
        for incident in file:
            incident['rawJSON'] = json.dumps(incident.get('rawJSON', {}))
    return file


@pytest.fixture(scope='module')
def client():
    from PhishLabsIOC_DRP import Client
    return Client(base_url='https://caseapi.phishlabs.com/v1/data')


"""Function tests"""


class TestHelperFunctions:
    def test_raw_response_to_context(self):
        from PhishLabsIOC_DRP import raw_response_to_context
        input_raw = load_params_from_json(r'./test_data/helper_functions/raw_response_to_context_input.json')
        expected_ec = load_params_from_json(r'./test_data/helper_functions/raw_response_to_context_output.json')
        tested_ec = raw_response_to_context(cases=input_raw)

        assert tested_ec == expected_ec


@freeze_time("2019-12-1 18:43:02")
class TestCommandsFunctions:
    def test_fetch_incidents(self, requests_mock, client):
        from PhishLabsIOC_DRP import fetch_incidents_command
        # Test no incidents
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_3.json'))
        expected_incidents = load_params_from_json(r'./test_data/commands/fetch_incidents/output_1.json', type='incidents')
        expected_last_run = '2019-11-10T02:30:37Z'
        tested_incidents_response, tested_last_run_response = fetch_incidents_command(client,
                                                                                      fetch_time='1 days',
                                                                                      last_run='2019-11-10T02:30:37Z',
                                                                                      max_records=20)
        assert expected_incidents == tested_incidents_response, 'Failed - Test no incidents, incidents criteria'
        assert expected_last_run == tested_last_run_response, 'Failed - Test no incidents, last run criteria'

        # Test last run - should return 2 incidents and new last run
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        expected_incidents = load_params_from_json(r'./test_data/commands/fetch_incidents/output_2.json', type='incidents')
        expected_last_run = '2019-12-01T01:40:36Z'
        tested_incidents_response, tested_last_run_response = fetch_incidents_command(client,
                                                                                      fetch_time='1 days',
                                                                                      last_run='2019-11-30T18:42:02Z',
                                                                                      max_records=20)
        assert expected_incidents == tested_incidents_response, 'Failed - Test 2 incidents should return, incidents criteria'
        assert expected_last_run == tested_last_run_response, 'Failed -  Test 2 incidents should return, last run criteria'

        # Test no last run - should return 2 incidents and new last run
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        expected_incidents = load_params_from_json(r'./test_data/commands/fetch_incidents/output_2.json', type='incidents')
        expected_last_run = '2019-12-01T01:40:36Z'
        tested_incidents_response, tested_last_run_response = fetch_incidents_command(client,
                                                                                      fetch_time='1 days',
                                                                                      max_records=20)
        assert expected_incidents == tested_incidents_response, 'Failed - Test no last run - should return 2 incidents and new last run, incidents criteria'
        assert expected_last_run == tested_last_run_response, 'Failed -  Test no last run - should return 2 incidents and new last run, last run criteria'


@freeze_time("2019-11-30")
class TestClientMethods:
    def test_get_cases_limit_filter(self, requests_mock, client):
        # Test less than exsits - get cases should query once and return 3 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?maxRecords=3',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        expected_response = load_params_from_json(r'./test_data/client_methods/get_cases/limit_filter/output_1.json')
        tested_response = client.get_cases(max_records=3)
        assert tested_response == expected_response, 'Failed - Test less than exsits - get cases should query once ' \
                                                     'and return 3 cases'

        # Test exact results - get cases should query twice and return 7 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=7',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=7',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        expected_response = load_params_from_json(r'./test_data/client_methods/get_cases/limit_filter/output_2.json')
        tested_response = client.get_cases(max_records=7)
        assert tested_response == expected_response, 'Failed - Test exact results - get cases should query twice' \
                                                     ' and return 7 cases'

        # Test Overflow - get cases should query three times and return 7 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=10',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=10',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=7&maxRecords=10',
                          json=load_params_from_json(r'./test_data/raw_response_3.json'))
        expected_response = load_params_from_json(r'./test_data/client_methods/get_cases/limit_filter/output_2.json')
        tested_response = client.get_cases(max_records=10)
        assert tested_response == expected_response, 'Failed - Test Overflow - get cases should query three times and' \
                                                     ' return 7 cases'

    def test_get_cases_begin_date_filter(self, requests_mock, client):
        # Test - begin date in first request - get cases should query one time and return 1 case
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        expected_response = load_params_from_json(
            r'./test_data/client_methods/get_cases/begin_date_filter/output_1.json')
        tested_response = client.get_cases(begin_date="2019-12-01T01:34:48Z")
        assert tested_response == expected_response, 'Failed - begin date in first request - get cases should query one ' \
                                                     'time and return 1 case'

        # Test begin date in second request - get cases should query twice and return 3 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        expected_response = load_params_from_json(
            r'./test_data/client_methods/get_cases/begin_date_filter/output_2.json')
        tested_response = client.get_cases(begin_date="2019-11-10T02:09:17Z")
        assert tested_response == expected_response, 'Failed - begin date in second request - get cases should query twice' \
                                                     ' and return 6 cases'

        # Test begin date is more then exsits - get cases should query three-times and return 7 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=7&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_3.json'))
        expected_response = load_params_from_json(
            r'./test_data/client_methods/get_cases/begin_date_filter/output_3.json')
        tested_response = client.get_cases(begin_date="2018-11-10T02:30:37Z")
        assert tested_response == expected_response, 'Failed - begin date is more then exsits - get cases should query ' \
                                                     'three-times and return 7 cases'

    def test_get_cases_end_date_filter(self, requests_mock, client):
        # Test end date is more than exsits - get cases should query three times and return 0 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=7&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_3.json'))
        expected_response = load_params_from_json(r'./test_data/client_methods/get_cases/end_date_filter/output_1.json')
        tested_response = client.get_cases(end_date="2018-11-10T02:30:37Z")
        assert tested_response == expected_response, 'Failed - end date is more than exsits - get cases should ' \
                                                     'query three times and return 0 cases'

        # Test end date in second request - get cases should query three times and return 2 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=7&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_3.json'))
        expected_response = load_params_from_json(r'./test_data/client_methods/get_cases/end_date_filter/output_2.json')
        tested_response = client.get_cases(end_date="2019-11-10T02:30:37Z")
        assert tested_response == expected_response, 'Failed - end date in second request - get cases should query three' \
                                                     ' times and return 2 cases'

        # Test end date in first request - get cases should query three-times and return 7 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=7&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_3.json'))
        expected_response = load_params_from_json(r'./test_data/client_methods/get_cases/end_date_filter/output_3.json')
        tested_response = client.get_cases(end_date="2019-12-01T01:40:36Z")
        assert tested_response == expected_response, 'Failed - end date in first request - get cases should query ' \
                                                     'three-times and return 7 cases'

    def test_get_cases_combined_filters(self, requests_mock, client):
        # Test end date and begin date in first request - get cases should query twice and return 5 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        expected_response = load_params_from_json(
            r'./test_data/client_methods/get_cases/combined_filters/output_1.json')
        tested_response = client.get_cases(end_date="2019-12-01T01:40:36Z",
                                           begin_date="2019-11-29T02:34:00Z")
        assert tested_response == expected_response, 'Failed - end date and begin date in first request - get cases' \
                                                     ' should query twice and return 5 cases'

        # Test end date in first request and begin date in second request - get cases should query twice and return 2 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=20',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        expected_response = load_params_from_json(
            r'./test_data/client_methods/get_cases/combined_filters/output_2.json')
        tested_response = client.get_cases(end_date="2019-11-29T02:34:00Z",
                                           begin_date="2019-11-10T02:09:17Z")
        assert tested_response == expected_response, 'Failed - end date in first request and begin date in second ' \
                                                     'request - get cases should query twice and return 3 case'

        # Test - end date in second request and begin date in not exsits - get cases should three times and return 1 case
        # Test end date in first request and begin date in second request - get cases should query twice and return 2 cases
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=0&maxRecords=1',
                          json=load_params_from_json(r'./test_data/raw_response_1.json'))
        requests_mock.get('https://caseapi.phishlabs.com/v1/data/cases?offset=5&maxRecords=1',
                          json=load_params_from_json(r'./test_data/raw_response_2.json'))
        expected_response = load_params_from_json(
            r'./test_data/client_methods/get_cases/combined_filters/output_3.json')
        tested_response = client.get_cases(end_date="2019-11-29T02:34:00Z",
                                           begin_date="2019-11-10T02:09:17Z",
                                           max_records=1)
        assert tested_response == expected_response, 'Failed - end date in first request and begin date in second ' \
                                                     'request - get cases should query twice and return 3 case'
