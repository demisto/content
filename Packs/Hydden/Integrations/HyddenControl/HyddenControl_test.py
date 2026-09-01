import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest


def _install_cortex_test_stubs() -> None:
    """Provide minimal Cortex modules when testing outside the content repo."""
    if "demistomock" not in sys.modules:
        sys.modules["demistomock"] = MagicMock()

    try:
        __import__("CommonServerPython")
    except ModuleNotFoundError:
        common = ModuleType("CommonServerPython")

        class BaseClient:
            pass

        class DemistoException(Exception):
            pass

        class CommandResults:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        common.BaseClient = BaseClient
        common.DemistoException = DemistoException
        common.CommandResults = CommandResults
        common.tableToMarkdown = lambda _title, data: str(data)
        common.return_results = lambda result: result
        common.return_error = lambda message: message
        sys.modules["CommonServerPython"] = common


_install_cortex_test_stubs()

from HyddenControl import (
    Client,
    DemistoException,
    _get_account_id,
    hydden_blast_radius_command,
    hydden_deprovision_account_command,
    _as_blast_radius_string,
)


ACCOUNT_ID = "00000000-0000-0000-0000-000000000000"


def test_get_blast_radius_sends_account_id_query_param() -> None:
    client = Client.__new__(Client)
    client._http_request = MagicMock(return_value={})

    client.get_blast_radius(ACCOUNT_ID)

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="blast-radius",
        params={"account_id": ACCOUNT_ID},
    )


def test_hydden_blast_radius_command() -> None:
    client = MagicMock()
    client.get_blast_radius.return_value = {"blast_radius": "high privilege across 7 resources"}

    result = hydden_blast_radius_command(client, {"account_id": ACCOUNT_ID})

    client.get_blast_radius.assert_called_once_with(ACCOUNT_ID)
    assert result.outputs == {"blast_radius": "high privilege across 7 resources"}


def test_hydden_blast_radius_command_stringifies_non_string_value() -> None:
    client = MagicMock()
    client.get_blast_radius.return_value = {"blast_radius": 42}

    result = hydden_blast_radius_command(client, {"account_id": ACCOUNT_ID})

    assert result.outputs == {"blast_radius": "42"}


def test_as_blast_radius_string_requires_field() -> None:
    with pytest.raises(DemistoException, match="did not include blast_radius"):
        _as_blast_radius_string({"id": ACCOUNT_ID})


def test_deprovision_account_posts_account_actions_path() -> None:
    client = Client.__new__(Client)
    client._http_request = MagicMock(return_value="")

    client.deprovision_account(ACCOUNT_ID)

    client._http_request.assert_called_once_with(
        method="POST",
        url_suffix="account-actions/deprovision",
        params={"account_id": ACCOUNT_ID},
        resp_type="text",
    )


def test_hydden_deprovision_account_command() -> None:
    client = MagicMock()
    client.deprovision_account.return_value = ""

    result = hydden_deprovision_account_command(client, {"account_id": ACCOUNT_ID})

    client.deprovision_account.assert_called_once_with(ACCOUNT_ID)
    assert result.outputs == {"deprovisioned": True}


def test_get_account_id_rejects_empty_value() -> None:
    with pytest.raises(DemistoException, match="Please provide account_id"):
        _get_account_id({"account_id": " "})
