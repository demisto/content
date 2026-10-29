import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
import SoChain
from CommonServerPython import Common, DBotScoreReliability, DemistoException
from SoChain import (
    Client,
    address_counterparties_command,
    address_poisoning_command,
    address_summary_command,
    crypto_reputation_command,
    split_scheme,
    transaction_command,
)

BASE_URL = "https://sochain.com/api/v3"
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
TXID = "597bafa25fcbb081467bdeb030a42bf441dbfcc054bdcfad31a829d7db5d931f"
VALID = {"status": "success", "data": {"is_valid": True}}
INVALID = {"status": "success", "data": {"is_valid": False}}
NO_CHECK = {"status": "fail", "data": {"error_message": "No address poisoning check on this network."}}


def util_load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker):
    """ContentClient calls support_multithreading(), which needs the real demisto object."""
    mocker.patch("ContentClientApiModule.support_multithreading")


@pytest.fixture
def respx_mock():
    """Mocks every httpx request; a request to an unmocked URL fails the test."""
    with respx.mock(assert_all_called=False) as mock:
        yield mock


def mock_get(respx_mock, path: str, json: dict, status_code: int = 200, headers: dict | None = None) -> respx.Route:
    """Answers GET {BASE_URL}/{path} (any query string) with the given JSON."""
    return respx_mock.get(f"{BASE_URL}/{path}").mock(return_value=httpx.Response(status_code, json=json, headers=headers))


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, verify=True, proxy=False)


def test_api_key_header():
    """The key is sent as API-KEY, and no header is sent without one."""
    assert Client(base_url=BASE_URL, verify=True, proxy=False, api_key="k1")._headers["API-KEY"] == "k1"
    assert "API-KEY" not in Client(base_url=BASE_URL, verify=True, proxy=False)._headers


@pytest.mark.parametrize(
    "value, expected",
    [
        (GENESIS, (GENESIS, None)),
        (f"bitcoin:{GENESIS}", (GENESIS, "BTC")),
        (f"BITCOIN:{GENESIS}?amount=1", (GENESIS, "BTC")),
        ("dogecoin:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L", ("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L", "DOGE")),
        (f"  {GENESIS} ", (GENESIS, None)),
    ],
)
def test_split_scheme(value, expected):
    assert split_scheme(value) == expected


def test_test_module(client, respx_mock):
    mock_get(respx_mock, f"is_valid_address/BTC/{GENESIS}", json=VALID)
    assert SoChain.test_module(client) == "ok"


def test_bad_api_key(respx_mock):
    """A 401 names the key as the problem."""
    mock_get(
        respx_mock,
        f"is_valid_address/BTC/{GENESIS}",
        status_code=401,
        json={"status": "fail", "data": {"error_message": "Invalid API key."}},
    )
    with pytest.raises(DemistoException, match="rejected the API key"):
        SoChain.test_module(Client(base_url=BASE_URL, verify=True, proxy=False, api_key="bad"))


def test_rate_limited(client, respx_mock):
    """A 429 passes on Retry-After and where to get a key, at once: it is not retried."""
    route = mock_get(
        respx_mock,
        f"address_summary/BTC/{GENESIS}",
        status_code=429,
        headers={"Retry-After": "120"},
        json={"status": "fail", "data": {"error_message": "Too many requests"}},
    )
    with pytest.raises(DemistoException, match="Retry after 120 seconds.*sochain.com/dashboard"):
        address_summary_command(client, {"address": GENESIS, "network": "BTC"})
    assert route.call_count == 1


def test_server_error_retried(client, respx_mock, mocker):
    """A 5xx is retried (3 attempts in all), then reported with SoChain's message."""
    mocker.patch("ContentClientApiModule.anyio.sleep", new=AsyncMock())
    route = mock_get(
        respx_mock,
        f"address_summary/BTC/{GENESIS}",
        status_code=503,
        json={"status": "fail", "data": {"error_message": "Try again soon"}},
    )
    with pytest.raises(DemistoException, match=r"SoChain API error \(503\): Try again soon"):
        address_summary_command(client, {"address": GENESIS, "network": "BTC"})
    assert route.call_count == 3


def test_address_summary_detects_network(client, respx_mock):
    """Without a network, the first network where is_valid_address says yes is used."""
    mock_get(respx_mock, f"is_valid_address/BTC/{GENESIS}", json=VALID)
    mock_get(respx_mock, f"address_summary/BTC/{GENESIS}", json=util_load_json("test_data/address_summary.json"))

    result = address_summary_command(client, {"address": GENESIS})

    assert result.outputs_prefix == "SoChain.Address"
    assert result.outputs["Network"] == "BTC"
    assert result.outputs["Address"] == GENESIS
    assert result.outputs["TxsTotal"] == 67159
    assert result.outputs["ConfirmedBalance"] == "57.69048146"
    assert result.outputs["FirstActiveHeight"] == 123723
    assert result.outputs["FirstActiveTime"] == "2011-05-13T21:04:05Z"


def test_address_detection_order(client, respx_mock):
    """An address valid on DOGE only is checked against BTC and LTC first."""
    address = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
    mock_get(respx_mock, f"is_valid_address/BTC/{address}", json=INVALID)
    mock_get(respx_mock, f"is_valid_address/LTC/{address}", json=INVALID)
    mock_get(respx_mock, f"is_valid_address/DOGE/{address}", json=VALID)
    mock_get(respx_mock, f"address_summary/DOGE/{address}", json=util_load_json("test_data/address_summary.json"))

    result = address_summary_command(client, {"address": address})

    assert result.outputs["Network"] == "DOGE"
    assert [call.request.url.path.split("/")[-2] for call in respx_mock.calls[:3]] == ["BTC", "LTC", "DOGE"]


def test_address_not_valid_anywhere(client, respx_mock):
    for network in ("BTC", "LTC", "DOGE", "ZEC"):
        mock_get(respx_mock, f"is_valid_address/{network}/nope", json=INVALID)
    with pytest.raises(DemistoException, match="not a valid address on BTC, LTC, DOGE, ZEC"):
        address_summary_command(client, {"address": "nope"})


def test_unsupported_network(client):
    with pytest.raises(DemistoException, match="Unsupported network"):
        address_summary_command(client, {"address": GENESIS, "network": "ETH"})


def test_crypto_no_lookalikes(client, respx_mock):
    """An active address without findings: Unknown score, and the message says no look-alikes were found."""
    mock_get(respx_mock, f"address_summary/BTC/{GENESIS}", json=util_load_json("test_data/address_summary.json"))
    mock_get(respx_mock, f"address_poisoning/BTC/{GENESIS}", json=util_load_json("test_data/address_poisoning_none.json"))

    results = crypto_reputation_command(client, {"crypto": f"bitcoin:{GENESIS}"}, DBotScoreReliability.C)

    assert len(results) == 1
    indicator = results[0].indicator
    assert indicator.address == f"bitcoin:{GENESIS}"
    assert indicator.address_type == "bitcoin"
    assert indicator.dbot_score.indicator == f"bitcoin:{GENESIS}"
    assert indicator.dbot_score.score == Common.DBotScore.NONE
    assert indicator.dbot_score.message == "No address poisoning look-alikes found."
    assert results[0].outputs["Poisoning"]["LookalikesFound"] is False
    # The network came from the scheme, so is_valid_address was not called.
    assert not any("is_valid_address" in str(call.request.url) for call in respx_mock.calls)


def test_crypto_lookalikes_found_is_not_bad(client, respx_mock):
    """Look-alikes make the address a target, not a bad actor: the score stays Unknown."""
    address = "bc1qtestvictimaddress0000000000000000000000"
    mock_get(respx_mock, f"address_summary/BTC/{address}", json=util_load_json("test_data/address_summary.json"))
    mock_get(respx_mock, f"address_poisoning/BTC/{address}", json=util_load_json("test_data/address_poisoning_findings.json"))

    result = crypto_reputation_command(client, {"crypto": address, "network": "BTC"}, DBotScoreReliability.C)[0]

    assert result.indicator.dbot_score.score == Common.DBotScore.NONE
    assert result.indicator.dbot_score.message == "Targeted by address poisoning: 1 look-alike address(es) sent it dust."
    assert result.outputs["Poisoning"]["LookalikesFound"] is True
    assert result.outputs["Poisoning"]["Findings"][0]["Imitates"] == "bc1qrealpartner00000000000000000000000realaddress"
    context = result.to_context()["EntryContext"]
    crypto_context = next(v for k, v in context.items() if k.startswith("Cryptocurrency("))
    assert "Malicious" not in crypto_context
    assert "Look-alike addresses" in result.readable_output


def test_crypto_network_without_check(client, respx_mock):
    """A 404 from the poisoning check (a network without it) still enriches the address."""
    address = "tmTestAddress0000000000000000000000"
    mock_get(respx_mock, f"address_summary/ZECTEST/{address}", json=util_load_json("test_data/address_summary.json"))
    mock_get(respx_mock, f"address_poisoning/ZECTEST/{address}", status_code=404, json=NO_CHECK)

    result = crypto_reputation_command(client, {"crypto": address, "network": "ZECTEST"}, DBotScoreReliability.C)[0]

    assert result.outputs["Poisoning"] is None
    assert result.indicator.address_type == "zcash"
    assert result.indicator.dbot_score.message == "The address poisoning check is not available for this network."


def test_crypto_unused_address(client, respx_mock):
    """A valid address with no transactions gets 'No results found.'"""
    summary = {
        "status": "success",
        "data": {
            "txs_sent": 0,
            "txs_received": 0,
            "txs_total": 0,
            "confirmed_balance": "0.00000000",
            "unconfirmed_balance": "0.00000000",
            "confirmed_received": "0.00000000",
            "first_active": None,
            "last_active": None,
        },
    }
    mock_get(respx_mock, "address_summary/LTC/Lunused", json=summary)
    mock_get(respx_mock, "address_poisoning/LTC/Lunused", json=util_load_json("test_data/address_poisoning_none.json"))

    result = crypto_reputation_command(client, {"crypto": "litecoin:Lunused"}, DBotScoreReliability.C)[0]

    assert result.indicator.dbot_score.score == Common.DBotScore.NONE
    assert result.indicator.dbot_score.message == "No results found."
    assert result.outputs["FirstActiveTime"] is None


def test_crypto_invalid_address(client, respx_mock):
    """A string that isn't an address on any network gets an Unknown score and no SoChain context."""
    for network in ("BTC", "LTC", "DOGE", "ZEC"):
        mock_get(respx_mock, f"is_valid_address/{network}/nope", json=INVALID)
    mock_get(
        respx_mock,
        "address_summary/BTC/notbtc",
        status_code=404,
        json={"status": "fail", "data": {"error_message": "Unable to fetch address summary. Invalid address?"}},
    )

    results = crypto_reputation_command(client, {"crypto": "nope,bitcoin:notbtc"}, DBotScoreReliability.C)

    assert [r.indicator.dbot_score.score for r in results] == [Common.DBotScore.NONE, Common.DBotScore.NONE]
    assert [r.indicator.dbot_score.message for r in results] == ["No results found.", "No results found."]
    assert all(r.outputs is None for r in results)


def test_transaction(client, respx_mock):
    mock_get(respx_mock, f"transaction/BTC/{TXID}", json=util_load_json("test_data/transaction.json"))

    result = transaction_command(client, {"txid": TXID, "network": "btc"})

    assert result.outputs_prefix == "SoChain.Transaction"
    assert result.outputs["Hash"] == TXID
    assert result.outputs["Fee"] == "0.00090000"
    assert result.outputs["Time"] == "2022-12-31T22:23:07Z"
    assert result.outputs["Inputs"][0]["Address"] == "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
    assert [o["Spent"] for o in result.outputs["Outputs"]] == [True, True]
    assert "39KPyDkWXeEE9UXkSNPXkv5tbgqZfxHhqv" in result.readable_output


def test_transaction_needs_network(client):
    with pytest.raises(DemistoException, match="required"):
        transaction_command(client, {"txid": TXID})


def test_address_counterparties(client, respx_mock):
    mock_get(respx_mock, f"address_counterparties/BTC/{GENESIS}", json=util_load_json("test_data/address_counterparties.json"))

    result = address_counterparties_command(client, {"address": GENESIS, "network": "BTC", "limit": "3"})

    assert dict(respx_mock.calls.last.request.url.params) == {"limit": "3"}
    assert result.outputs["WindowBlocks"] == 4320
    assert result.outputs["Counterparties"][0] == {
        "Address": "bc1qdux37a0pzr44lrhc8vm44uellvplgyh7g73epq",
        "Direction": "received",
        "Amount": "0.06774527",
        "Txid": "f1363d1f8ceb5753aa5f9f5fee1a9c605545be2d167ae89c44103c04d2b80731",
        "Height": 971286,
    }


def test_limit_out_of_range(client):
    with pytest.raises(DemistoException, match="between 1 and 100"):
        address_counterparties_command(client, {"address": GENESIS, "network": "BTC", "limit": "500"})


def test_address_poisoning(client, respx_mock):
    address = "bc1qtestvictimaddress0000000000000000000000"
    mock_get(respx_mock, f"address_poisoning/BTC/{address}", json=util_load_json("test_data/address_poisoning_findings.json"))

    result = address_poisoning_command(client, {"address": address, "network": "BTC"})

    assert dict(respx_mock.calls.last.request.url.params) == {"limit": "50"}
    assert result.outputs_prefix == "SoChain.AddressPoisoning"
    assert result.outputs["LookalikesFound"] is True
    assert result.outputs["Findings"][0]["Sender"] == "bc1qrealpartner00000000000000000000000lookalike"
    assert result.outputs["Findings"][0]["SenderKind"] == "dust_bot"
    assert "Targeted by address poisoning" in result.readable_output
