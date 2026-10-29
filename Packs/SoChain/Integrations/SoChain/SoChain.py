import traceback
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from ContentClientApiModule import *  # noqa: F401

""" CONSTANTS """

INTEGRATION_NAME = "SoChain"
DEFAULT_BASE_URL = "https://sochain.com/api/v3"
KEY_URL = "https://sochain.com/dashboard"

# Networks tried, in order, when a command gets an address without a network.
DETECTION_NETWORKS = ["BTC", "LTC", "DOGE", "ZEC"]
NETWORKS = DETECTION_NETWORKS + ["BTCTEST", "LTCTEST", "DOGETEST", "ZECTEST"]

# URI schemes an address may carry (CryptoCurrenciesFormat stores Bitcoin indicators as "bitcoin:<address>").
SCHEME_NETWORKS = {
    "bitcoin": "BTC",
    "litecoin": "LTC",
    "dogecoin": "DOGE",
    "zcash": "ZEC",
}
NETWORK_ADDRESS_TYPES = {
    "BTC": "bitcoin",
    "LTC": "litecoin",
    "DOGE": "dogecoin",
    "ZEC": "zcash",
    "BTCTEST": "bitcoin",
    "LTCTEST": "litecoin",
    "DOGETEST": "dogecoin",
    "ZECTEST": "zcash",
}
DEFAULT_LIMIT = 50
MAX_LIMIT = 100

""" CLIENT CLASS """


class Client(ContentClient):
    """Client for the SoChain API v3. Every lookup works without a key; a key raises the request limits."""

    def __init__(self, base_url: str, verify: bool, proxy: bool, api_key: str | None = None):
        headers = {"Accept": "application/json"}
        if api_key:
            headers["API-KEY"] = api_key
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
            client_name=INTEGRATION_NAME,
            # Retry only server errors. A 429 is a daily or monthly limit, so waiting on its Retry-After
            # (up to a day) would hang the command; it is reported at once instead.
            retry_policy=RetryPolicy(max_attempts=3, retryable_status_codes=(500, 502, 503, 504)),  # type: ignore[call-arg]
            diagnostic_mode=is_debug_mode(),
        )

    def _get(self, url_suffix: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = self._http_request(method="GET", url_suffix=url_suffix, params=params)
        except ContentClientError as e:
            # ContentClient raises on any non-2xx answer; turn it into a message that says what to do.
            if e.response is not None:
                self._error_handler(e.response)
            raise
        return response.get("data") or {}

    @staticmethod
    def _error_handler(res: httpx.Response) -> None:
        try:
            message = res.json().get("data", {}).get("error_message") or res.text
        except ValueError:
            message = res.text
        if res.status_code == 401:
            raise DemistoException(f"SoChain rejected the API key (401): {message}", res=res)
        if res.status_code == 429:
            retry_after = res.headers.get("Retry-After")
            wait = f" Retry after {retry_after} seconds." if retry_after else ""
            raise DemistoException(
                f"SoChain rate limit reached (429): {message}.{wait} An API key from {KEY_URL} raises the limit.",
                res=res,
            )
        raise DemistoException(f"SoChain API error ({res.status_code}): {message}", res=res)

    def is_valid_address(self, network: str, address: str) -> bool:
        return bool(self._get(f"/is_valid_address/{network}/{address}").get("is_valid"))

    def address_summary(self, network: str, address: str) -> dict[str, Any]:
        return self._get(f"/address_summary/{network}/{address}")

    def transaction(self, network: str, txid: str) -> dict[str, Any]:
        return self._get(f"/transaction/{network}/{txid}")

    def address_counterparties(self, network: str, address: str, limit: int) -> dict[str, Any]:
        return self._get(f"/address_counterparties/{network}/{address}", params={"limit": limit})

    def address_poisoning(self, network: str, address: str, limit: int) -> dict[str, Any]:
        return self._get(f"/address_poisoning/{network}/{address}", params={"limit": limit})


""" HELPER FUNCTIONS """


def split_scheme(value: str) -> tuple[str, str | None]:
    """Strips a "bitcoin:"-style scheme (and any "?query") from an address.

    Returns the bare address and the network the scheme names, if any.
    """
    value = value.strip()
    network = None
    if ":" in value:
        scheme, _, rest = value.partition(":")
        if scheme.lower() in SCHEME_NETWORKS:
            network = SCHEME_NETWORKS[scheme.lower()]
            value = rest
    return value.split("?", 1)[0], network


def normalize_network(network: str | None) -> str | None:
    if not network:
        return None
    network = network.strip().upper()
    if network not in NETWORKS:
        raise DemistoException(f"Unsupported network '{network}'. Use one of: {', '.join(NETWORKS)}.")
    return network


def detect_network(client: Client, address: str) -> str | None:
    """Returns the first network (BTC, LTC, DOGE, ZEC) on which the address is valid, or None."""
    for network in DETECTION_NETWORKS:
        if client.is_valid_address(network, address):
            return network
    return None


def resolve_address(client: Client, value: str, network_arg: str | None) -> tuple[str, str]:
    """Returns (address, network) for a command argument, detecting the network when it isn't given."""
    address, scheme_network = split_scheme(value)
    if not address:
        raise DemistoException("No address given.")
    network = normalize_network(network_arg) or scheme_network or detect_network(client, address)
    if not network:
        raise DemistoException(f"{address} is not a valid address on {', '.join(DETECTION_NETWORKS)}.")
    return address, network


def get_limit(args: dict[str, Any]) -> int:
    limit = arg_to_number(args.get("limit"), arg_name="limit") or DEFAULT_LIMIT
    if not 1 <= limit <= MAX_LIMIT:
        raise DemistoException(f"limit must be between 1 and {MAX_LIMIT}.")
    return limit


def unix_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    return timestamp_to_datestring(int(value) * 1000, date_format="%Y-%m-%dT%H:%M:%SZ", is_utc=True)


def summary_to_context(address: str, network: str, summary: dict[str, Any]) -> dict[str, Any]:
    first_active = summary.get("first_active") or {}
    last_active = summary.get("last_active") or {}
    return {
        "Address": address,
        "Network": network,
        "TxsSent": summary.get("txs_sent"),
        "TxsReceived": summary.get("txs_received"),
        "TxsTotal": summary.get("txs_total"),
        "ConfirmedBalance": summary.get("confirmed_balance"),
        "UnconfirmedBalance": summary.get("unconfirmed_balance"),
        "ConfirmedReceived": summary.get("confirmed_received"),
        "FirstActiveHeight": first_active.get("height"),
        "FirstActiveTime": unix_to_iso(first_active.get("time")),
        "LastActiveHeight": last_active.get("height"),
        "LastActiveTime": unix_to_iso(last_active.get("time")),
    }


def poisoning_to_context(address: str, network: str, data: dict[str, Any]) -> dict[str, Any]:
    findings = [
        {
            "DustTxid": finding.get("dust_txid"),
            "Amount": finding.get("amount"),
            "Sender": finding.get("sender"),
            "Imitates": finding.get("imitates"),
            "RealTxid": finding.get("real_txid"),
            "RealHeight": finding.get("real_height"),
            "RealAmount": finding.get("real_amount"),
            "ReceiverPaid": finding.get("receiver_paid"),
            "SharedPrefix": finding.get("shared_prefix"),
            "SharedSuffix": finding.get("shared_suffix"),
            "SenderKind": finding.get("sender_kind"),
            "SenderTxs": finding.get("sender_txs"),
            "Height": finding.get("height"),
            "Confirmed": finding.get("confirmed"),
        }
        for finding in data.get("findings") or []
    ]
    return {
        "Address": address,
        "Network": network,
        "Building": data.get("building"),
        "LookalikesFound": bool(findings),
        "Findings": findings,
    }


def poisoning_message(poisoning: dict[str, Any] | None) -> str:
    if poisoning is None:
        return "The address poisoning check is not available for this network."
    count = len(poisoning["Findings"])
    if count:
        return f"Targeted by address poisoning: {count} look-alike address(es) sent it dust."
    if poisoning.get("Building"):
        return "No address poisoning look-alikes found so far (the check is still catching up)."
    return "No address poisoning look-alikes found."


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    client.is_valid_address("BTC", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    return "ok"


def is_not_found(error: DemistoException) -> bool:
    return error.res is not None and getattr(error.res, "status_code", None) == 404


def get_poisoning_or_none(client: Client, address: str, network: str) -> dict[str, Any] | None:
    """The poisoning check, or None on a network without it (the API answers 404)."""
    try:
        data = client.address_poisoning(network, address, DEFAULT_LIMIT)
    except DemistoException as e:
        if is_not_found(e):
            demisto.debug(f"No address poisoning check for {address} on {network}: {e}")
            return None
        raise
    return poisoning_to_context(address, network, data)


def crypto_dbot_score(value: str, reliability: DBotScoreReliability | str, message: str) -> Common.DBotScore:
    """SoChain gives on-chain facts, not verdicts, so the score is always Unknown (0); the message says what was found."""
    return Common.DBotScore(
        indicator=value,
        indicator_type=DBotScoreType.CRYPTOCURRENCY,
        integration_name=INTEGRATION_NAME,
        score=Common.DBotScore.NONE,
        reliability=reliability,
        message=message,
    )


def crypto_not_found(value: str, reason: str, reliability: DBotScoreReliability | str) -> CommandResults:
    dbot_score = crypto_dbot_score(value, reliability, "No results found.")
    return CommandResults(
        readable_output=f"SoChain: {reason}",
        indicator=Common.Cryptocurrency(address=value, address_type="", dbot_score=dbot_score),
    )


def crypto_reputation_for(
    client: Client, value: str, network_arg: str | None, reliability: DBotScoreReliability | str
) -> CommandResults:
    """Enriches one Cryptocurrency indicator with its activity and the address poisoning check."""
    address, scheme_network = split_scheme(value)
    network = normalize_network(network_arg) or scheme_network or detect_network(client, address)
    if not network:
        return crypto_not_found(value, f"{address} is not a valid address on {', '.join(DETECTION_NETWORKS)}.", reliability)
    try:
        summary = client.address_summary(network, address)
    except DemistoException as e:
        if not is_not_found(e):
            raise
        return crypto_not_found(value, f"{address} is not a valid {network} address.", reliability)

    context = summary_to_context(address, network, summary)
    poisoning = get_poisoning_or_none(client, address, network)
    context["Poisoning"] = poisoning

    message = poisoning_message(poisoning) if context.get("TxsTotal") else "No results found."
    dbot_score = crypto_dbot_score(value, reliability, message)
    indicator = Common.Cryptocurrency(address=value, address_type=NETWORK_ADDRESS_TYPES[network], dbot_score=dbot_score)

    table = {key: val for key, val in context.items() if key != "Poisoning"}
    table["AddressPoisoning"] = message
    readable = tableToMarkdown(f"SoChain: {address} ({network})", table, headers=list(table.keys()), removeNull=True)
    if poisoning and poisoning["Findings"]:
        readable += tableToMarkdown(
            "Look-alike addresses",
            poisoning["Findings"],
            headers=["Sender", "Imitates", "Amount", "DustTxid", "Confirmed"],
        )

    return CommandResults(
        outputs_prefix="SoChain.Address",
        outputs_key_field=["Address", "Network"],
        outputs=context,
        readable_output=readable,
        indicator=indicator,
        raw_response=context,
    )


def crypto_reputation_command(
    client: Client, args: dict[str, Any], reliability: DBotScoreReliability | str
) -> list[CommandResults]:
    values = argToList(args.get("crypto"))
    if not values:
        raise DemistoException("No cryptocurrency address given.")
    return [crypto_reputation_for(client, value, args.get("network"), reliability) for value in values]


def address_summary_command(client: Client, args: dict[str, Any]) -> CommandResults:
    address, network = resolve_address(client, args.get("address", ""), args.get("network"))
    summary = client.address_summary(network, address)
    context = summary_to_context(address, network, summary)
    return CommandResults(
        outputs_prefix="SoChain.Address",
        outputs_key_field=["Address", "Network"],
        outputs=context,
        readable_output=tableToMarkdown(
            f"SoChain address summary: {address} ({network})", context, headers=list(context.keys()), removeNull=True
        ),
        raw_response=summary,
    )


def transaction_to_context(network: str, tx: dict[str, Any]) -> dict[str, Any]:
    return {
        "Hash": tx.get("hash"),
        "Network": network,
        "Confirmations": tx.get("confirmations"),
        "BlockHash": tx.get("block_hash"),
        "BlockHeight": tx.get("block_height"),
        "Time": unix_to_iso(tx.get("time")),
        "Size": tx.get("size"),
        "Vsize": tx.get("vsize"),
        "Fee": tx.get("fee"),
        "InputsCount": tx.get("inputs_n"),
        "OutputsCount": tx.get("outputs_n"),
        "InputsValue": tx.get("inputs_value"),
        "OutputsValue": tx.get("outputs_value"),
        "Inputs": [
            {"Index": tx_in.get("index"), "Address": tx_in.get("address"), "Value": tx_in.get("value")}
            for tx_in in tx.get("inputs") or []
        ],
        "Outputs": [
            {
                "Index": tx_out.get("index"),
                "Address": tx_out.get("address"),
                "Value": tx_out.get("value"),
                "Type": tx_out.get("type"),
                "Spent": tx_out.get("spent") is not None,
            }
            for tx_out in tx.get("outputs") or []
        ],
    }


def transaction_command(client: Client, args: dict[str, Any]) -> CommandResults:
    txid = (args.get("txid") or "").strip()
    network = normalize_network(args.get("network"))
    if not txid or not network:
        raise DemistoException("txid and network are required.")
    tx = client.transaction(network, txid)
    context = transaction_to_context(network, tx)
    summary = {key: val for key, val in context.items() if key not in ("Inputs", "Outputs")}
    readable = tableToMarkdown(f"SoChain transaction {txid} ({network})", summary, headers=list(summary.keys()), removeNull=True)
    readable += tableToMarkdown("Inputs", context["Inputs"], headers=["Index", "Address", "Value"])
    readable += tableToMarkdown("Outputs", context["Outputs"], headers=["Index", "Address", "Value", "Type", "Spent"])
    return CommandResults(
        outputs_prefix="SoChain.Transaction",
        outputs_key_field=["Hash", "Network"],
        outputs=context,
        readable_output=readable,
        raw_response=tx,
    )


def address_counterparties_command(client: Client, args: dict[str, Any]) -> CommandResults:
    address, network = resolve_address(client, args.get("address", ""), args.get("network"))
    data = client.address_counterparties(network, address, get_limit(args))
    counterparties = [
        {
            "Address": row.get("address"),
            "Direction": row.get("direction"),
            "Amount": row.get("amount"),
            "Txid": row.get("txid"),
            "Height": row.get("height"),
        }
        for row in data.get("counterparties") or []
    ]
    context = {
        "Address": address,
        "Network": network,
        "WindowBlocks": data.get("window_blocks"),
        "FromHeight": data.get("from_height"),
        "Building": data.get("building"),
        "Counterparties": counterparties,
    }
    return CommandResults(
        outputs_prefix="SoChain.Counterparties",
        outputs_key_field=["Address", "Network"],
        outputs=context,
        readable_output=tableToMarkdown(
            f"SoChain counterparties of {address} ({network}), from block {data.get('from_height')}",
            counterparties,
            headers=["Address", "Direction", "Amount", "Txid", "Height"],
        ),
        raw_response=data,
    )


def address_poisoning_command(client: Client, args: dict[str, Any]) -> CommandResults:
    address, network = resolve_address(client, args.get("address", ""), args.get("network"))
    data = client.address_poisoning(network, address, get_limit(args))
    context = poisoning_to_context(address, network, data)
    readable = f"### SoChain address poisoning check: {address} ({network})\n{poisoning_message(context)}\n"
    if context["Findings"]:
        readable += tableToMarkdown(
            "Look-alike addresses",
            context["Findings"],
            headers=["Sender", "Imitates", "Amount", "DustTxid", "SharedPrefix", "SharedSuffix", "ReceiverPaid", "Confirmed"],
        )
    return CommandResults(
        outputs_prefix="SoChain.AddressPoisoning",
        outputs_key_field=["Address", "Network"],
        outputs=context,
        readable_output=readable,
        raw_response=data,
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    api_key = (params.get("credentials") or {}).get("password") or None
    base_url = (params.get("url") or DEFAULT_BASE_URL).rstrip("/")
    reliability = params.get("integrationReliability") or DBotScoreReliability.C

    try:
        client = Client(
            base_url=base_url,
            verify=not argToBoolean(params.get("insecure", False)),
            proxy=argToBoolean(params.get("proxy", False)),
            api_key=api_key,
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command == "crypto":
            return_results(crypto_reputation_command(client, args, reliability))
        elif command == "sochain-address-summary":
            return_results(address_summary_command(client, args))
        elif command == "sochain-transaction":
            return_results(transaction_command(client, args))
        elif command == "sochain-address-counterparties":
            return_results(address_counterparties_command(client, args))
        elif command == "sochain-address-poisoning":
            return_results(address_poisoning_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        demisto.debug(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}", error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
