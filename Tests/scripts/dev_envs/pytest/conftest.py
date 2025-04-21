import pytest
import logging
import os
from uuid import uuid4


# File is copied to each package dir when running tests.
# More info about conftest.py at:
#   https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins  # disable-secrets-detection


@pytest.fixture(autouse=True)
def check_logging(caplog):
    '''
    Fixture validates that the python logger doesn't contain any warnings (or up) messages

    If your test fails and it is ok to have such messages then you can clear the log at the end of your test
    By callign: caplog.clear()

    For example:

    def test_foo(caplog):
        logging.getLogger().warning('this is ok')
        caplog.clear()
    '''
    yield
    messages = [
        "{}: {}".format(x.levelname, x.message) for x in caplog.get_records('call') if x.levelno >= logging.WARNING
    ]
    if messages:
        pytest.fail(
            "warning messages encountered during testing: {}".format(messages)
        )


@pytest.fixture(autouse=True)
def check_std_out_err(capfd):
    '''
    Fixture validates that there is no output to stdout or stderr.

    If your test fails and it is ok to have output in stdout/stderr, you can disable the capture use "with capfd.disabled()"

    For example:

    def test_boo(capfd):
        with capfd.disabled():
            print("this is ok")
    '''
    yield
    (out, err) = capfd.readouterr()
    if out:
        pytest.fail("Found output in stdout: [{}]".format(out.strip()))
    if err:
        pytest.fail("Found output in stderr: [{}]".format(err.strip()))


def pytest_sessionfinish(session, exitstatus):
    """
    This function runs after all tests are run.

    If the exit code is 5 (no tests were collected),
    it will change the exit code to 0 (success) as this is the current behavior in content.
    """
    if exitstatus == 5:
        session.exitstatus = 0


def pytest_configure(config):
    """
    This functions runs before any tests are run, in pre-commit
    It configures the junit xml report to include the docker image name which the test is run
    """
    junit_xml = config.option.xmlpath
    if junit_xml and ".pre-commit" in junit_xml:
        image = os.getenv("DOCKER_IMAGE")
        if image:
            config.option.xmlpath = junit_xml.replace(".xml", "-{}.xml".format(image.replace("/", "_")))
        else:
            config.option.xmlpath = junit_xml.replace(".xml", "-{}.xml".format(str(uuid4())))


def pytest_addoption(parser):
    parser.addoption(
        "--client_conf",
        action="store",
        default=None,
        help="Client configuration in the format: key1=value1,key2=value2",
    )
