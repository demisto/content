import datetime
from pathlib import Path

import pytest
from unittest.mock import patch

demisto_params = {
    "host": "https://some-triage-host/",
    "token": "api_token",
    "user": "user",
}
with patch("demistomock.params", lambda: demisto_params):
    from CofenseTriagev2 import TriageInstance  # noqa: 401 - this is used in other test files


@pytest.fixture
def fixture_from_file():
    def _fixture_from_file(fname):
        with (Path(__file__).parent / 'test' / 'fixtures' / fname).open() as file:
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


@pytest.fixture(autouse=True)
def stub_demisto_setup(mocker):
    mocker.patch("demistomock.getArg", get_demisto_arg)
    mocker.patch("demistomock.getParam", get_demisto_arg)  # args ≡ params in tests
    mocker.patch("demistomock.results")
    mocker.patch("demistomock.incidents")


@pytest.fixture
def triage_instance():
    return TriageInstance(
        host="https://some-triage-host",
        token="top-secret-token-value",
        user="triage-user",
        disable_tls_verification=False,
        demisto_params={
            "start_date": datetime.datetime.fromisoformat("2000-10-30"),
            "max_fetch": 10,
            "category_id": 5,
            "match_priority": 2,
            "tags": "",
        },
    )
