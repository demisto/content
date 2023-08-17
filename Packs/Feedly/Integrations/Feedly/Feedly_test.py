"""HelloWorld Feed Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the HelloWorld Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration, as well as a feed integration, should have a proper set of unit
tests to automatically verify that the integration is behaving as expected
during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your feed integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/FeedHelloWorld

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
before each test to simulate the API calls to the FeedHelloWorld API (which is
OpenPhish). This way we can have full control of the API behavior and focus only
on testing the logic inside the integration code.

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

from Feedly import Client


URL = "https://api.feedly.com/v3/enterprise/ioc?streamId=tag%2FenterpriseName%2Fcategory%2Fuuid&count=20&newerThan=0&client=feedly.demisto.client"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_build_iterator(requests_mock):
    """

    Given:
        - Output of the feed API
    When:
        - When calling fetch_indicators or get_indicators
    Then:
        - Returns a list of the indicators parsed from the API's response

    """
    with open("test_data/FeedHelloWorld_mock.txt") as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_ip = "1.2.3.4"
    client = Client(base_url=URL, verify=False, proxy=False,)
    indicators = client.fetch_indicators_from_stream("tag/enterpriseName/category/uuid", 0)
    ip_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "IP"}
    assert {expected_ip} == ip_indicators
    report = next(indicator for indicator in indicators if indicator["type"] == "Report")
    assert report["fields"]["description"] == "This is a report."
