import pytest
from unittest.mock import patch

demisto_params = {
    "host": "https://some-triage-host/",
    "token": "api_token",
    "user": "user",
}
with patch("demistomock.params", lambda: demisto_params):
    from .. import CofenseTriage


@pytest.fixture
def fixture_from_file():
    def _fixture_from_file(fname):
        with open(f"test/fixtures/{fname}", "r") as file:
            return file.read()
    return _fixture_from_file


DEMISTO_ARGS = {}


@pytest.fixture
def set_demisto_arg():
    def _set_demisto_arg(name, value):
        DEMISTO_ARGS[name] = value
    return _set_demisto_arg


def get_demisto_arg(name):
    if name in DEMISTO_ARGS:
        return DEMISTO_ARGS[name]
    raise Exception(
        f'Test setup did not specify a Demisto argument named {name}. Use `set_demisto_arg("{name}", "value")`.'
    )


def demisto_handle_error(message, error="", outputs=None):
    raise Exception(
        f"Reported error to Demisto: {message} (error={error}) (outputs={outputs})"
    )


@pytest.fixture(autouse=True)
def stub_demisto_setup(mocker):
    mocker.patch("demistomock.getArg", get_demisto_arg)
    mocker.patch("demistomock.getParam", get_demisto_arg)  # args ≡ params in tests
    mocker.patch("demistomock.results")
    mocker.patch("demistomock.incidents")
