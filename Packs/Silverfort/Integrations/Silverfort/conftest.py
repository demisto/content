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


@pytest.fixture
def upn():
    return 'xxxx@xx.xxxxx.silverfort.io'


@pytest.fixture
def base_url():
    return 'https://test.com'


@pytest.fixture
def email():
    return 'xxxx@silverfort.com'


@pytest.fixture
def domain():
    return 'silverfort.io'


@pytest.fixture
def api_key():
    return 'XXXXXXXXXXXXXXXXXXXXX'


@pytest.fixture
def risk():
    return {'risk_name': 'activity_risk', 'severity': 'medium', 'valid_for': 1, 'description': 'Suspicious activity'}


@pytest.fixture
def resource_name():
    return 'XX-XXX-DCNN-Y'


@pytest.fixture
def bad_response():
    return 'No valid response'


@pytest.fixture
def valid_update_response():
    return {"result": "updated successfully!"}


@pytest.fixture
def valid_get_risk_response():
    return {"risk": "Low", "reasons": ["Password never expires", "Suspicious activity"]}


@pytest.fixture
def valid_get_upn_response(upn):
    return {"upn": upn}


@pytest.fixture
def sam_account():
    return 'xxxx'


@pytest.fixture
def client(base_url):
    from Packs.Silverfort.Integrations.Silverfort.Silverfort import Client
    return Client(base_url=base_url, verify=False)


@pytest.fixture
def risk_args(risk):
    return {'risk_name': 'activity_risk', 'severity': 'medium', 'valid_for': 1, 'description': 'Suspicious activity'}
