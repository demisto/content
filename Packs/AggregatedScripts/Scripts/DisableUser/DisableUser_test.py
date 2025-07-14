"""HelloWorld Script for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the HelloWorld Script based
on pytest. Cortex XSOAR contribution requirements mandate that every
script should have a proper set of unit tests to automatically
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
demisto-sdk lint -d Packs/HelloWorld/Scripts/HelloWorldScript

Coverage
--------

There should be at least one unit test per  function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

Also please check the HelloWorld Integration Unit Tests file.

"""

from HelloWorldScript import say_hello, say_hello_command


def test_say_hello():
    result = say_hello("Dbot")

    assert result == "Hello Dbot"


def test_say_hello_command():
    args = {"name": "Dbot"}

    readable_output, outputs, raw_response = say_hello_command(args)

    assert readable_output == "## Hello Dbot"
    assert outputs["HelloWorld"]["hello"] == "Hello Dbot"
    assert raw_response == "Hello Dbot"
