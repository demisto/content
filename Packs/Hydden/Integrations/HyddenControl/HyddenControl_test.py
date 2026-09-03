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
            def __init__(self, **kwargs):
                self._headers = kwargs.get("headers") or {}
                self._verify = kwargs.get("verify", True)
                self._proxy = kwargs.get("proxy", False)
                self._base_url = kwargs.get("base_url")

        class ContentClient(BaseClient):
            pass

        class DemistoException(Exception):
            pass

        class CommandResults:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        common.BaseClient = BaseClient
        common.ContentClient = ContentClient
        common.DemistoException = DemistoException
        common.CommandResults = CommandResults
        common.tableToMarkdown = lambda _title, data: str(data)
        common.return_results = lambda result: result
        common.return_error = lambda message: message
        common.arg_to_number = lambda value: int(value) if value not in (None, "") else None
        sys.modules["CommonServerPython"] = common

    if "ContentClientApiModule" not in sys.modules:
        content_client_mod = ModuleType("ContentClientApiModule")
        csp = sys.modules["CommonServerPython"]
        content_client_mod.ContentClient = getattr(csp, "ContentClient", getattr(csp, "BaseClient"))
        sys.modules["ContentClientApiModule"] = content_client_mod


_install_cortex_test_stubs()

from HyddenControl import (
    Client,
    DemistoException,
    _get_account_id,
    hydden_blast_radius_command,
    hydden_deprovision_account_command,
    _as_blast_radius_string,
    test_module as run_test_module,
)

ACCOUNT_ID = "00000000-0000-0000-0000-000000000000"
TOKEN = "issued-bearer-token"


def _client_with_mocked_transport(return_value=None):
    """A Client with __init__ bypassed so no real HTTP setup is needed."""
    client = Client.__new__(Client)
    client._headers = {"accept": "application/json", "content-type": "application/json"}
    client._client_id = "client-id"
    client._client_secret = "client-secret"
    client._token = None
    client._token_expires_at = 0.0
    client._http_request = MagicMock(return_value=return_value)
    return client


def test_get_bearer_token_posts_client_credentials_form() -> None:
    client = _client_with_mocked_transport({"access_token": TOKEN, "expires_in": 300})

    assert client.get_bearer_token() == TOKEN

    client._http_request.assert_called_once_with(
        method="POST",
        url_suffix="oauth/token",
        headers={
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "client_credentials",
            "client_id": "client-id",
            "client_secret": "client-secret",
        },
    )


def test_get_bearer_token_caches_until_near_expiry() -> None:
    client = _client_with_mocked_transport({"access_token": TOKEN, "expires_in": 300})

    assert client.get_bearer_token() == TOKEN
    assert client.get_bearer_token() == TOKEN

    assert client._http_request.call_count == 1


def test_get_bearer_token_reissues_once_the_cached_token_expires() -> None:
    client = _client_with_mocked_transport({"access_token": TOKEN, "expires_in": 300})

    client.get_bearer_token()
    client._token_expires_at = 0.0
    client.get_bearer_token()

    assert client._http_request.call_count == 2


def test_get_bearer_token_requires_access_token() -> None:
    client = _client_with_mocked_transport({"token_type": "Bearer"})

    with pytest.raises(DemistoException, match="did not include access_token"):
        client.get_bearer_token()


def test_get_blast_radius_sends_the_account_id_as_the_ref_query_param() -> None:
    client = _client_with_mocked_transport({})

    client.get_blast_radius(ACCOUNT_ID, TOKEN)

    client._http_request.assert_called_once_with(
        method="GET",
        url_suffix="blast-radius",
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
        params={"ref": ACCOUNT_ID, "type": "account"},
    )


def test_get_blast_radius_passes_through_a_group_subject_type() -> None:
    client = _client_with_mocked_transport({})

    client.get_blast_radius(ACCOUNT_ID, TOKEN, "group")

    assert client._http_request.call_args.kwargs["params"] == {
        "ref": ACCOUNT_ID,
        "type": "group",
    }


# The shape the live endpoint answers, verified against qa1 on 2026-09-02.
LIVE_RESPONSE = {
    "subject_type": "account",
    "subject_ref": ACCOUNT_ID,
    "account_ref": ACCOUNT_ID,
    "score": 0,
    "raw_severity": 0,
    "reachable_resources": 0,
    "tenant_resources": 0,
    "share_of_tenant": 0,
    "denied_resources": 0,
    "by_sensitivity": {},
    "by_assignment_type": {},
    "top_contributors": [],
    "grants_considered": 0,
    "truncated": False,
    "score_version": "2",
    "computed_at": "2026-09-02T19:57:36.707308521Z",
}


def test_hydden_blast_radius_command_reads_the_score_field() -> None:
    client = MagicMock()
    client.get_bearer_token.return_value = TOKEN
    client.get_blast_radius.return_value = {**LIVE_RESPONSE, "score": 73, "reachable_resources": 7}

    result = hydden_blast_radius_command(client, {"account_id": ACCOUNT_ID})

    client.get_bearer_token.assert_called_once_with()
    client.get_blast_radius.assert_called_once_with(ACCOUNT_ID, TOKEN, "account")
    assert result.outputs["blast_radius"] == "73"
    assert result.outputs["reachable_resources"] == 7
    assert result.outputs["subject_ref"] == ACCOUNT_ID


def test_hydden_blast_radius_command_keeps_a_zero_score() -> None:
    """A score of 0 is a real answer, not a missing field."""
    client = MagicMock()
    client.get_bearer_token.return_value = TOKEN
    client.get_blast_radius.return_value = LIVE_RESPONSE

    result = hydden_blast_radius_command(client, {"account_id": ACCOUNT_ID})

    assert result.outputs["blast_radius"] == "0"


def test_as_blast_radius_string_falls_back_to_a_flat_blast_radius_field() -> None:
    assert _as_blast_radius_string({"blast_radius": "high privilege across 7 resources"}) == (
        "high privilege across 7 resources"
    )


def test_as_blast_radius_string_requires_a_score_field() -> None:
    with pytest.raises(DemistoException, match="did not include a blast radius score"):
        _as_blast_radius_string({"id": ACCOUNT_ID})


def test_as_blast_radius_string_error_names_the_fields_that_did_come_back() -> None:
    with pytest.raises(DemistoException, match="Fields returned: id, name"):
        _as_blast_radius_string({"name": "phead", "id": ACCOUNT_ID})


def test_deprovision_account_posts_account_actions_path_with_bearer_token() -> None:
    client = _client_with_mocked_transport("")

    client.deprovision_account(ACCOUNT_ID, TOKEN)

    client._http_request.assert_called_once_with(
        method="POST",
        url_suffix="account-actions/deprovision",
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
        params={"ref": ACCOUNT_ID},
        resp_type="text",
    )


def test_hydden_deprovision_account_command() -> None:
    client = MagicMock()
    client.get_bearer_token.return_value = TOKEN
    client.deprovision_account.return_value = ""

    result = hydden_deprovision_account_command(client, {"account_id": ACCOUNT_ID})

    client.get_bearer_token.assert_called_once_with()
    client.deprovision_account.assert_called_once_with(ACCOUNT_ID, TOKEN)
    assert result.outputs == {"deprovisioned": True}


def test_get_account_id_rejects_empty_value() -> None:
    with pytest.raises(DemistoException, match="Please provide account_id"):
        _get_account_id({"account_id": " "})


def test_hydden_blast_radius_command_passes_group_type() -> None:
    client = MagicMock()
    client.get_bearer_token.return_value = TOKEN
    client.get_blast_radius.return_value = {**LIVE_RESPONSE, "score": 1}

    hydden_blast_radius_command(client, {"account_id": ACCOUNT_ID, "type": "group"})

    client.get_blast_radius.assert_called_once_with(ACCOUNT_ID, TOKEN, "group")


def test_test_module_treats_not_found_as_ok() -> None:
    client = MagicMock()
    client.get_bearer_token.return_value = TOKEN
    client.get_blast_radius.side_effect = DemistoException("404 Not Found")

    assert run_test_module(client) == "ok"


def test_test_module_raises_on_authorization_failure() -> None:
    client = MagicMock()
    client.get_bearer_token.side_effect = DemistoException("401 Unauthorized")

    with pytest.raises(DemistoException, match="Authorization failed"):
        run_test_module(client)


def test_client_inherits_from_content_client() -> None:
    from ContentClientApiModule import ContentClient

    assert issubclass(Client, ContentClient)


def test_client_forwards_verify_and_proxy_to_content_client(monkeypatch) -> None:
    """YAML insecure/proxy (type 8) must reach ContentClient as verify/proxy."""
    from ContentClientApiModule import ContentClient

    seen: dict = {}

    def capture_init(self, **kwargs):
        seen.update(kwargs)
        self._headers = kwargs.get("headers") or {}
        self._verify = kwargs.get("verify", True)
        self._proxy = kwargs.get("proxy", False)

    monkeypatch.setattr(ContentClient, "__init__", capture_init)
    Client(
        client_id="client-id",
        client_secret="client-secret",
        base_url="https://control.hydden.ai/api/public/v1/",
        verify=False,
        proxy=True,
        headers={"accept": "application/json"},
    )

    assert seen["verify"] is False
    assert seen["proxy"] is True
