import json
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from Hackuity import (
    Client,
    format_date,
    get_first_value,
    hackuity_dashboard_data_command,
    hackuity_dashboard_widgets_command,
    hackuity_search_findings_command,
    hackuity_search_vulnerabilities_command,
    none_or_apply,
)
from Hackuity import (
    test_module as try_module_command,
)  # avoid pytest thinking it is a test

""" HELPER FUNCTIONS """


@pytest.mark.parametrize(
    "item, expected",
    [
        (None, None),
        ({}, None),
        ({"foo": "bar"}, "bar"),
    ],
)
def test_get_first_value(item, expected):
    assert get_first_value(item) == expected


@pytest.mark.parametrize(
    "item, expected",
    [
        (None, None),
        ("2022-01-03T01:23:45.678Z", "2022-01-03T01:23:45Z"),
    ],
)
def test_format_date(item, expected):
    assert format_date(item) == expected


@pytest.mark.parametrize(
    "item, expected",
    [
        (None, None),
        ("42", 42),
    ],
)
def test_none_or_apply(item, expected):
    assert none_or_apply(item, int) == expected


""" COMMAND FUNCTIONS """


TEST_DATA_PATH = Path("test_data")


def util_get_json(directory, filename):
    with (TEST_DATA_PATH / directory / filename).with_suffix(".json").open(
        mode="rb"
    ) as f:
        return json.loads(f.read())


@pytest.fixture
def mocked_client(mocker):
    client = Client("https://xxx.api.hackuity.io", "N012345654321", "foo", "bar")

    def mocked_http_request(url_suffix: str = "", **_: Any):
        return util_get_json("api", "_".join(url_suffix.split("/")[-2:]))

    mocker.patch.object(client, "http_request", side_effect=mocked_http_request)

    return client


def test_command_test_module(mocked_client):
    result = try_module_command(mocked_client)
    assert result == "ok"


@pytest.mark.parametrize(
    "command, args, expected_filename",
    [
        pytest.param(
            hackuity_search_findings_command,
            {"limit": 2},
            "search_findings",
            id="search_findings",
        ),
        pytest.param(
            partial(hackuity_search_vulnerabilities_command, hy_global_only=False),
            {"limit": 2},
            "search_vulnerabilities",
            id="search_provider_vulnerabilities",
        ),
        pytest.param(
            partial(hackuity_search_vulnerabilities_command, hy_global_only=True),
            {"limit": 2},
            "search_vulnerabilities",
            id="search_vulndb_vulnerabilities",
        ),
        pytest.param(
            hackuity_dashboard_widgets_command,
            {},
            "dashboard_widgets",
            id="dashboard_widgets",
        ),
        pytest.param(
            hackuity_dashboard_data_command,
            {"widget_id": "789"},
            "dashboard_data",
            id="dashboard_data",
        ),
    ],
)
def test_commands(command, args, expected_filename, mocked_client):
    expected_result = util_get_json("expected", expected_filename)
    result = command(mocked_client, args)
    assert result.outputs == expected_result
