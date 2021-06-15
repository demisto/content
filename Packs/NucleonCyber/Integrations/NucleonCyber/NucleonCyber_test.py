"""HelloWorld Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the HelloWorld Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/HelloWorld

Coverage
--------

There should be at least one unit test per command function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

Unit tests should be self contained and should not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the HelloWorld API. This way we
can have full control of the API behavior and focus only on testing the logic
inside the integration code.

We recommend to use outputs from the API calls and use them to compare the
results when possible. See the ``test_data`` directory that contains the data
we use for comparison, in order to reduce the complexity of the unit tests and
avoding to manually mock all the fields.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_say_hello():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from HelloWorld import Client, say_hello_command

    client = Client(base_url='https://test.com/api/v1', verify=False, auth=('test', 'test'))
    args = {
        'name': 'Dbot'
    }
    response = say_hello_command(client, args)

    assert response.outputs == 'Hello Dbot'


def test_start_scan(requests_mock):
    """Tests helloworld-scan-start command function.

    Configures requests_mock instance to generate the appropriate start_scan
    API response when the correct start_scan API request is performed. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, scan_start_command

    mock_response = {
        'scan_id': '7a161a3f-8d53-42de-80cd-92fb017c5a12',
        'status': 'RUNNING'
    }
    requests_mock.get('https://test.com/api/v1/start_scan?hostname=example.com', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'hostname': 'example.com'
    }

    response = scan_start_command(client, args)

    assert response.outputs_prefix == 'HelloWorld.Scan'
    assert response.outputs_key_field == 'scan_id'
    assert response.outputs == {
        'scan_id': '7a161a3f-8d53-42de-80cd-92fb017c5a12',
        'status': 'RUNNING',
        'hostname': 'example.com'
    }


def test_status_scan(requests_mock):
    """Tests helloworld-scan-status command function.

    Configures requests_mock instance to generate the appropriate check_scan
    API responses based on the scan ID provided. For scan_id 100, 300 status
    should be COMPLETE while for scan ID 200 is RUNNING. Checks the output of
    the command function with the expected output.
    """
    from HelloWorld import Client, scan_status_command

    mock_response = {
        'scan_id': '100',
        'status': 'COMPLETE'
    }
    requests_mock.get('https://test.com/api/v1/check_scan?scan_id=100', json=mock_response)

    mock_response = {
        'scan_id': '200',
        'status': 'RUNNING'
    }
    requests_mock.get('https://test.com/api/v1/check_scan?scan_id=200', json=mock_response)

    mock_response = {
        'scan_id': '300',
        'status': 'COMPLETE'
    }
    requests_mock.get('https://test.com/api/v1/check_scan?scan_id=300', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'scan_id': ['100', '200', '300']
    }

    response = scan_status_command(client, args)

    assert response.outputs_prefix == 'HelloWorld.Scan'
    assert response.outputs_key_field == 'scan_id'
    assert response.outputs == [
        {
            'scan_id': '100',
            'status': 'COMPLETE'
        },
        {
            'scan_id': '200',
            'status': 'RUNNING'
        },
        {
            'scan_id': '300',
            'status': 'COMPLETE'
        }
    ]


def test_scan_results(mocker, requests_mock):
    """Tests helloworld-scan-results command function.

    Configures requests_mock instance to generate the appropriate
    get_scan_results API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, scan_results_command
    from CommonServerPython import Common

    mock_response = util_load_json('test_data/scan_results.json')
    requests_mock.get('https://test.com/api/v1/get_scan_results?scan_id=100', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'scan_id': '100',
        'format': 'json'
    }

    response = scan_results_command(client, args)

    assert response[0].outputs == mock_response
    assert response[0].outputs_prefix == 'HelloWorld.Scan'
    assert response[0].outputs_key_field == 'scan_id'

    # This command also returns Common.CVE data
    assert isinstance(response, list)
    assert len(response) > 1
    for i in range(1, len(response)):
        assert isinstance(response[i].indicator, Common.CVE)


def test_search_alerts(requests_mock):
    """Tests helloworld-search-alerts command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, search_alerts_command

    mock_response = util_load_json('test_data/search_alerts.json')
    requests_mock.get(
        'https://test.com/api/v1/get_alerts?alert_status=ACTIVE&severity=Critical&max_results=2&start_time=1581982463',
        json=mock_response['alerts'])

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'severity': 'Critical',
        'start_time': 1581982463,
        'max_results': 2,
        'status': 'ACTIVE'
    }

    response = search_alerts_command(client, args)

    # We modify the timestamp from the raw mock_response of the API, because the
    # integration changes the format from timestamp to ISO8601.
    mock_response['alerts'][0]['created'] = '2020-02-17T23:34:23.000Z'
    mock_response['alerts'][1]['created'] = '2020-02-17T23:34:23.000Z'

    assert response.outputs_prefix == 'HelloWorld.Alert'
    assert response.outputs_key_field == 'alert_id'
    assert response.outputs == mock_response['alerts']


def test_get_alert(requests_mock):
    """Tests helloworld-get-alert command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, get_alert_command

    mock_response = util_load_json('test_data/get_alert.json')
    requests_mock.get('https://test.com/api/v1/get_alert_details?alert_id=695b3238-05d6-4934-86f5-9fff3201aeb0',
                      json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'alert_id': '695b3238-05d6-4934-86f5-9fff3201aeb0',
    }

    response = get_alert_command(client, args)

    # We modify the timestamp from the raw mock_response of the API, because the
    # integration changes the format from timestamp to ISO8601.
    mock_response['created'] = '2020-04-17T14:43:59.000Z'

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'HelloWorld.Alert'
    assert response.outputs_key_field == 'alert_id'


def test_update_alert_status(requests_mock):
    """Tests helloworld-update-alert-status command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, update_alert_status_command

    mock_response = util_load_json('test_data/update_alert_status.json')
    requests_mock.get(
        'https://test.com/api/v1/change_alert_status?alert_id=695b3238-05d6-4934-86f5-9fff3201aeb0&alert_status=CLOSED',
        json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'alert_id': '695b3238-05d6-4934-86f5-9fff3201aeb0',
        'status': 'CLOSED'
    }

    response = update_alert_status_command(client, args)

    # We modify the timestamp from the raw mock_response of the API, because the
    # integration changes the format from timestamp to ISO8601.
    mock_response['updated'] = '2020-04-17T14:45:12.000Z'

    assert response.outputs == mock_response
    assert response.outputs_prefix == 'HelloWorld.Alert'
    assert response.outputs_key_field == 'alert_id'


def test_ip(requests_mock):
    """Tests the ip reputation command function.

    Configures requests_mock instance to generate the appropriate
    ip reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, ip_reputation_command
    from CommonServerPython import Common

    ip_to_check = '151.1.1.1'
    mock_response = util_load_json('test_data/ip_reputation.json')
    requests_mock.get(f'http://test.com/api/v1/ip?ip={ip_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com/api/v1',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    args = {
        'ip': ip_to_check,
        'threshold': 65,
    }

    response = ip_reputation_command(client, args, 65)

    assert response[0].outputs == mock_response
    assert response[0].outputs_prefix == 'HelloWorld.IP'
    assert response[0].outputs_key_field == 'ip'

    # This command also returns Common.IP data
    assert isinstance(response, list)
    assert isinstance(response[0].indicator, Common.IP)
    assert response[0].indicator.ip == ip_to_check


def test_domain(requests_mock):
    """Tests the domain reputation command function.

    Configures requests_mock instance to generate the appropriate
    domain reputation API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, domain_reputation_command
    from CommonServerPython import Common

    domain_to_check = 'google.com'
    mock_response = util_load_json('test_data/domain_reputation.json')
    requests_mock.get(f'http://test.com/api/v1/domain?domain={domain_to_check}',
                      json=mock_response)

    client = Client(
        base_url='http://test.com/api/v1',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    args = {
        'domain': domain_to_check,
        'threshold': 65,
    }

    response = domain_reputation_command(client, args, 65)

    # We modify the timestamps from the raw mock_response of the API, because the
    # integration changes the format from timestamp to ISO8601.
    mock_response['expiration_date'] = '2028-09-14T04:00:00.000Z'
    mock_response['creation_date'] = '1997-09-15T04:00:00.000Z'
    mock_response['updated_date'] = '2019-09-09T15:39:04.000Z'

    assert response[0].outputs == mock_response
    assert response[0].outputs_prefix == 'HelloWorld.Domain'
    assert response[0].outputs_key_field == 'domain'

    # This command also returns Common.Domain data
    assert isinstance(response, list)
    assert isinstance(response[0].indicator, Common.Domain)
    assert response[0].indicator.domain == domain_to_check


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, fetch_incidents

    mock_response = util_load_json('test_data/search_alerts.json')
    requests_mock.get(
        'https://test.com/api/v1/get_alerts?alert_status=ACTIVE'
        '&severity=Low%2CMedium%2CHigh%2CCritical&max_results=2'
        '&start_time=1581944401', json=mock_response['alerts'])

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    last_run = {
        'last_fetch': 1581944401  # Mon Feb 17 2020
    }

    _, new_incidents = fetch_incidents(
        client=client,
        max_results=2,
        last_run=last_run,
        alert_status='ACTIVE',
        min_severity='Low',
        alert_type=None,
        first_fetch_time='3 days',
    )

    assert new_incidents == [
        {
            'name': 'Hello World Alert 100',
            'occurred': '2020-02-17T23:34:23.000Z',
            'rawJSON': json.dumps(mock_response['alerts'][0]),
            'severity': 4,  # critical, this is XSOAR severity (already converted)
        },
        {
            'name': 'Hello World Alert 200',
            'occurred': '2020-02-17T23:34:23.000Z',
            'rawJSON': json.dumps(mock_response['alerts'][1]),
            'severity': 2,  # medium, this is XSOAR severity (already converted)
        }
    ]
