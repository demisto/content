import subprocess
import pytest
import logging
import os
import shutil
import tempfile
from uuid import uuid4
# More info about conftest.py at:
#   https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins  # disable-secrets-detection
NO_TESTS_COLLECTED = 5
SUCCESS = 0


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
@pytest.fixture(autouse=True)
def chdir(monkeypatch):
    temp_dir = tempfile.mkdtemp()
    monkeypatch.chdir(temp_dir)
    yield
    shutil.rmtree(temp_dir)
    
def pytest_sessionfinish(session, exitstatus):
    if exitstatus == NO_TESTS_COLLECTED:
        session.exitstatus = SUCCESS
    if os.getenv("CI"):
        subprocess.run(["git", "clean", "-fdx"], check=True)


def pytest_configure(config):
    junit_xml = config.option.xmlpath
    if junit_xml:
        image = os.getenv("DOCKER_IMAGE")
        if image:
            config.option.xmlpath = junit_xml.replace(".xml", "-{}.xml".format(image.replace("/", "_")))
        else:
            config.option.xmlpath = junit_xml.replace(".xml", "-{}.xml".format(str(uuid4())))
