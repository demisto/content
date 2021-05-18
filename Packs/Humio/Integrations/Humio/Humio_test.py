"""Humio Integration for Cortex XSOAR - Unit Tests file

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
demisto-sdk lint -d Packs/HelloWorld/Integrations/HelloWorld

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
import os


def util_load_json(path):
    path = os.path.join(os.path.dirname(__file__), path)
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


headers = {}
headers["Content-Type"] = "application/json"
headers["Authorization"] = "Bearer APIKEY"


def test_humio_query(requests_mock):
    """Tests that a humio query can be issued"""
    from Humio import Client, humio_query

    mock_response = util_load_json("test_data/query_results.json")
    requests_mock.post(
        "https://test.com/api/v1/repositories/sandbox/query", json=mock_response
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {
        "queryString": "test",
        "start": "24h",
        "end": "now",
        "isLive": "False",
        "timeZoneOffsetMinutes": 60,
        "repository": "sandbox",
    }

    _, outputs, _ = humio_query(client, args, headers)
    assert outputs == {"Humio.Query": [mock_response]}


def test_humio_query_job(requests_mock):
    """Tests that a humio queryjob can be issued"""
    from Humio import Client, humio_query_job

    mock_response = json.loads(
        """{"id": "1-xK13lC_jjtOYqPR1onSdlLm8","queryOnView": "<R:tail(limit=1.0)>"}"""
    )
    requests_mock.post(
        "https://test.com/api/v1/repositories/sandbox/queryjobs", json=mock_response
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {
        "queryString": "tail(1)",
        "start": "24h",
        "end": "now",
        "isLive": "False",
        "timeZoneOffsetMinutes": 60,
        "repository": "sandbox",
    }

    _, outputs, _ = humio_query_job(client, args, headers)
    assert outputs["Humio.Job"]["id"] == mock_response["id"]


def test_humio_poll(requests_mock):
    """Tests that a humio queryjob can be polled"""
    from Humio import Client, humio_poll

    mock_response = util_load_json("test_data/poll_results.json")
    requests_mock.get(
        "https://test.com/api/v1/repositories/sandbox/queryjobs/testid",
        json=mock_response,
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {"id": "testid", "repository": "sandbox"}

    _, outputs, _ = humio_poll(client, args, headers)
    assert (
        outputs["Humio.Result(val.job_id == obj.job_id)"]["events"]
        == mock_response["events"]
    )


def test_humio_list_alerts(requests_mock):
    """Tests that a humio alerts can be listed"""
    from Humio import Client, humio_list_alerts

    mock_response = util_load_json("test_data/list_alerts_results.json")
    requests_mock.get(
        "https://test.com/api/v1/repositories/sandbox/alerts", json=mock_response
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {"repository": "sandbox"}

    _, outputs, _ = humio_list_alerts(client, args, headers)
    assert outputs["Humio.Alert(val.id == obj.id)"] == mock_response


def test_humio_get_alert_by_id(requests_mock):
    """Tests that a humio alert can be fetched based on its id"""
    from Humio import Client, humio_get_alert_by_id

    mock_response = util_load_json("test_data/get_alert_by_id_results.json")
    requests_mock.get(
        "https://test.com/api/v1/repositories/sandbox/alerts/zNVae7vz-DH7GpeQUPfx1KXMGXGg7bf7",
        json=mock_response,
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {"repository": "sandbox", "id": "zNVae7vz-DH7GpeQUPfx1KXMGXGg7bf7"}

    _, outputs, _ = humio_get_alert_by_id(client, args, headers)
    assert outputs["Humio.Alert(val.id == obj.id)"] == mock_response


def test_humio_create_alert(requests_mock):
    """Tests that a humio alert can be fetched based on its id"""
    from Humio import Client, humio_create_alert

    mock_response = util_load_json("test_data/create_alert_results.json")
    requests_mock.post(
        "https://test.com/api/v1/repositories/sandbox/alerts",
        json=mock_response,
        status_code=201,
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {
        "queryString": "alert=true",
        "start": "24h",
        "name": "TestingAlert",
        "description": "Description of TestingAlert",
        "throttleTimeMillis": "3000000",
        "repository": "sandbox",
        "silenced": "false",
        "notifiers": "BTkuj8QArhIFMh_L39FoN0tnyTUEXplc",
        "labels": "",
    }

    _, outputs, _ = humio_create_alert(client, args, headers)
    assert outputs["Humio.Alert(val.id == obj.id)"] == mock_response


def test_humio_list_notifiers(requests_mock):
    """Tests that a humio alerts can be listed"""
    from Humio import Client, humio_list_notifiers

    mock_response = util_load_json("test_data/list_notifiers_results.json")
    requests_mock.get(
        "https://test.com/api/v1/repositories/sandbox/alertnotifiers",
        json=mock_response,
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {"repository": "sandbox"}

    _, outputs, _ = humio_list_notifiers(client, args, headers)
    assert outputs["Humio.Notifier(val.id == obj.id)"] == mock_response


def test_humio_get_notifier_by_id(requests_mock):
    """Tests that a humio alerts can be listed"""
    from Humio import Client, humio_get_notifier_by_id

    mock_response = util_load_json("test_data/notifier_by_id_results.json")
    requests_mock.get(
        "https://test.com/api/v1/repositories/sandbox/alertnotifiers/BTkuj8QArhIFMh_L39FoN0tnyTUEXplc",
        json=mock_response,
    )

    client = Client(base_url="https://test.com", verify=False, proxies=None)
    args = {"repository": "sandbox", "id": "BTkuj8QArhIFMh_L39FoN0tnyTUEXplc"}

    _, outputs, _ = humio_get_notifier_by_id(client, args, headers)
    assert outputs["Humio.Notifier(val.id == obj.id)"] == mock_response
