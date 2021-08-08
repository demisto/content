"""Cyren Inbox Security Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the Cyren Inbox Security Integration
based
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
demisto-sdk lint -i Packs/CyrenInboxSecurity/Integrations/CyrenInboxSecurity

Coverage
--------

There is at least one unit test per command function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

Unit tests are self contained and do not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the CyrenInboxSecurity API.
This way we can have full control of the API behavior and focus only on
testing the logic inside the integration code.

See the ``test_data`` directory that contains the data
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
import datetime


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_simulate_fetch():
    from CyrenInboxSecurity import simulate_fetch

    # fetch
    incidents = simulate_fetch()

    assert incidents[0]["name"] ==\
           'Cyren Inbox Security Sample - phishing (System)'


def test_test_module(requests_mock):
    """Tests the test function."""

    from CyrenInboxSecurity import Client, test_module

    requests_mock.post(
        'https://test.com/v1/token',
        json="ok"
    )

    client = Client(
        base_url='https://test.com/',
        verify=False
    )

    # test
    results = test_module(
        client=client,
        client_id="sample",
        client_secret="sample",
    )

    assert results == 'ok'


def test_resolve_and_remediate_command(requests_mock):
    """Tests the cyren-resolve-and-remediate command function.
    """
    from CyrenInboxSecurity import Client, resolve_and_remediate_command

    requests_mock.patch(
        'https://test.com/v1/cases',
        json={"data": {"status": "ok"}}
    )

    requests_mock.post(
        'https://test.com/v1/token',
        json={"data": {"access_token": "sample"}}
    )

    client = Client(
        base_url='https://test.com/',
        verify=False
    )

    # resolve and remediate
    cmd_results = resolve_and_remediate_command(
        client=client,
        args={
            "case_id": '123',
            "resolution": 'phishing',
            "resolution_reason_text": '',
            "actions": [],
        },
        client_id="sample",
        client_secret="sample",
    )

    attrs = vars(cmd_results)
    assert attrs["raw_response"]["data"]["status"] == 'ok'


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from CyrenInboxSecurity import Client, fetch_incidents

    mock_response = util_load_json('test_data/sample-incidents.json')

    requests_mock.get(
        'https://test.com/v1/incidents',
        json=mock_response
    )

    requests_mock.post(
        'https://test.com/v1/token',
        json={"data": {"access_token": "sample"}}
    )

    client = Client(
        base_url='https://test.com/',
        verify=False
    )

    last_run = {
    }

    # fetch
    incidents = fetch_incidents(
        client=client,
        client_id="sample",
        client_secret="sample",
        last_run=last_run,
        first_fetch_time=datetime.datetime.now(),
        max_fetch=10,
    )

    assert incidents[0]["name"] ==\
           'Cyren Inbox Security - phishing (System)'
