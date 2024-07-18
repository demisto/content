import pytest
import logging


# File is coppied to each package dir when running tests.
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
    Fixture validates that there is no ouput to stdout or stderr.

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
