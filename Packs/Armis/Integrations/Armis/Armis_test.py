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


def test_untag_device(requests_mock):
    pass


def test_tag_device(requests_mock):
    pass


def test_update_alert_status(requests_mock):
    pass


def test_search_alerts(requests_mock):
    pass


def test_search_alerts_by_aql(requests_mock):
    pass


def test_search_devices(requests_mock):
    pass


def test_search_devices_by_aql(requests_mock):
    pass


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
