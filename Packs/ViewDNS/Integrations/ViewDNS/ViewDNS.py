import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import html
import re
import traceback
from collections.abc import Callable
from typing import Any

""" CONSTANTS """

INTEGRATION_NAME = "ViewDNS"
DEFAULT_BASE_URL = "https://api.viewdns.info"
DEFAULT_LIMIT = 50
# Maximum number of list items (IP history records, co-hosted domains) kept by the reputation commands.
REPUTATION_MAX_ITEMS = 50
RETRIES = 3
BACKOFF_FACTOR = 2
STATUS_LIST_TO_RETRY = [500, 502, 503, 504]
# ViewDNS reports errors with these HTTP status codes and a JSON body, so they are parsed rather than raised by requests.
HANDLED_STATUS_CODES = (200, 400, 401, 403, 429)
# Free API keys receive a canned demonstration payload from the Reverse WHOIS API instead of an error.
DEMO_QUERY_MARKER = "demonstration---tool-for-paid-users-only"
# IP History reports "nothing known about this domain" as an error string in a successful response.
NO_RECORDS_MARKER = "do not have any records"
REPUTATION_DISABLED_MESSAGE = (
    "ViewDNS reputation commands are disabled. To enrich indicators with the !{command} command, select "
    '"Enable reputation commands" in the ViewDNS integration instance settings. '
    "Note that every enriched indicator consumes ViewDNS API queries."
)

""" CLIENT CLASS """


class Client(BaseClient):
    """Client for the ViewDNS.info API (https://viewdns.info/api/documentation/)."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self._api_key = api_key

    def _api_request(self, url_suffix: str, params: dict[str, Any], empty_markers: tuple[str, ...] = ()) -> dict[str, Any]:
        """Sends a GET request and returns the parsed body.

        Args:
            url_suffix: The API path, for example ``/reverseip/``.
            params: The query parameters (without the API key and output format).
            empty_markers: Substrings of in-body error messages which mean "no data" rather than a failure.

        Returns:
            The full parsed JSON body. The ``response`` key is always a dict.
        """
        query = assign_params(**params)
        query.update({"apikey": self._api_key, "output": "json"})
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=query,
            resp_type="response",
            ok_codes=HANDLED_STATUS_CODES,
            retries=RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
        )
        if response.status_code != 200:
            raise DemistoException(build_error_message(response.status_code, extract_error_message(response)), res=response)
        try:
            body = response.json()
        except ValueError:
            raise DemistoException(f"{INTEGRATION_NAME}: the API returned a response which is not valid JSON.", res=response)
        if not isinstance(body, dict):
            raise DemistoException(f"{INTEGRATION_NAME}: the API returned an unexpected response.", res=response)

        result = body.get("response")
        if not isinstance(result, dict):
            result = {}
        body["response"] = result
        error = result.get("error")
        if error:
            if any(marker in str(error) for marker in empty_markers):
                body["response"] = {}
            else:
                raise DemistoException(f"{INTEGRATION_NAME}: {error}")
        return body

    def account_balance(self) -> dict[str, Any]:
        return self._api_request("/account/", {"action": "balance"})

    def reverse_ip(self, host: str, page: int | None = None) -> dict[str, Any]:
        return self._api_request("/reverseip/", {"host": host, "page": page})

    def reverse_whois(self, query: str, page: int | None = None) -> dict[str, Any]:
        body = self._api_request("/reversewhois/", {"q": query, "page": page})
        if (body.get("query") or {}).get("query") == DEMO_QUERY_MARKER:
            raise DemistoException(
                f"{INTEGRATION_NAME}: the Reverse WHOIS API is available to paid API keys only. "
                "The API returned demonstration data, which was discarded."
            )
        return body

    def reverse_ns(self, nameserver: str, page: int | None = None) -> dict[str, Any]:
        return self._api_request("/reversens/", {"ns": nameserver, "page": page})

    def reverse_mx(self, mail_server: str, page: int | None = None) -> dict[str, Any]:
        return self._api_request("/reversemx/", {"mx": mail_server, "page": page})

    def ip_history(self, domain: str) -> dict[str, Any]:
        return self._api_request("/iphistory/", {"domain": domain}, empty_markers=(NO_RECORDS_MARKER,))

    def dns_record(self, domain: str, record_type: str) -> dict[str, Any]:
        return self._api_request("/dnsrecord/", {"domain": domain, "recordtype": record_type})

    def whois(self, domain: str) -> dict[str, Any]:
        return self._api_request("/whois/v2/", {"domain": domain})

    def port_scan(self, host: str) -> dict[str, Any]:
        return self._api_request("/portscan/", {"host": host})

    def ping(self, host: str) -> dict[str, Any]:
        return self._api_request("/ping/v2/", {"host": host})

    def traceroute(self, host: str) -> dict[str, Any]:
        return self._api_request("/traceroute/", {"domain": host})


""" HELPER FUNCTIONS """


def extract_error_message(response: Any) -> str:
    """Extracts the error message from a ViewDNS error response."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or "")
    return str(error or "")


def build_error_message(status_code: int, api_message: str) -> str:
    """Maps a ViewDNS HTTP error status to a clear, actionable message."""
    details = f" ViewDNS message: {api_message}" if api_message else ""
    if status_code == 401:
        return f"{INTEGRATION_NAME}: authorization error - the API key is invalid.{details}"
    if status_code == 403:
        return f"{INTEGRATION_NAME}: the API key does not have access to this tool (a paid plan may be required).{details}"
    if status_code == 429:
        return (
            f"{INTEGRATION_NAME}: the query limit was reached - the monthly quota is used up and "
            f"no prepaid queries remain.{details}"
        )
    if status_code == 400:
        return f"{INTEGRATION_NAME}: invalid input.{details}"
    return f"{INTEGRATION_NAME}: the API returned an error (HTTP {status_code}).{details}"


def to_int(value: Any) -> int | None:
    """Converts the numeric strings returned by the API to integers, returning None when not numeric."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def to_float(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def get_positive_int_arg(args: dict[str, Any], name: str, default: int) -> int:
    value = arg_to_number(args.get(name), arg_name=name)
    if value is None:
        return default
    if value < 1:
        raise DemistoException(f"The '{name}' argument must be a positive number.")
    return value


def get_required_arg(args: dict[str, Any], name: str) -> str:
    value = str(args.get(name) or "").strip()
    if not value:
        raise DemistoException(f"The '{name}' argument is required.")
    return value


def remove_blank_values(data: dict[str, Any]) -> dict[str, Any]:
    """Drops the keys whose value is None, an empty string or an empty collection.

    The API returns both nulls and empty strings for missing WHOIS fields.
    """
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def no_results(description: str) -> str:
    return f"### {INTEGRATION_NAME}\nNo results found for {description}."


def paged_title(name: str, shown: int, total: int | None, page: int) -> str:
    total_text = f" of {total}" if total is not None else ""
    return f"{INTEGRATION_NAME} {name} (showing {shown}{total_text}, page {page})"


def parse_contact(contact: Any) -> dict[str, Any]:
    """Converts a WHOIS contact block to context format, dropping empty values."""
    if not isinstance(contact, dict):
        return {}
    return remove_blank_values(
        {
            "Name": contact.get("name"),
            "Organization": contact.get("organization"),
            "Street": contact.get("street1"),
            "City": contact.get("city"),
            "State": contact.get("state"),
            "PostalCode": contact.get("postalCode"),
            "Country": contact.get("country"),
            "Phone": contact.get("telephone"),
            "Fax": contact.get("fax"),
            "Email": contact.get("email"),
        }
    )


def add_raw_text(parsed: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    """Adds the raw WHOIS record, which the API returns HTML-escaped, to a parsed record."""
    raw_text = registry.get("rawText")
    if raw_text:
        parsed["RawText"] = html.unescape(str(raw_text))
    return parsed


def parse_domain_whois(domain: str, response: dict[str, Any]) -> dict[str, Any]:
    registry = response.get("registryData") or {}
    name_servers = [
        host.get("Address")
        for host in as_list((registry.get("nameServers") or {}).get("hostNames"))
        if isinstance(host, dict) and host.get("Address")
    ]
    # Status formats vary by registry, for example "clientHold https://icann.org/epp#clientHold" or "delete prohibited".
    statuses = [
        re.sub(r"\s+https?://\S+$", "", line.strip()) for line in str(registry.get("status") or "").splitlines() if line.strip()
    ]
    parsed = remove_blank_values(
        {
            "RegistrarName": response.get("registrarName"),
            "RegistrarIANAID": response.get("registrarIANAID"),
            "CreatedDate": registry.get("standardCreatedDate") or registry.get("createdDate"),
            "UpdatedDate": registry.get("standardUpdatedDate") or registry.get("updatedDate"),
            "ExpiresDate": registry.get("standardExpiresDate") or registry.get("expiresDate"),
            "AbuseEmail": registry.get("abuseEmail"),
            "Registrant": parse_contact(registry.get("registrant")),
            "Admin": parse_contact(registry.get("administrativeContact")),
            "Tech": parse_contact(registry.get("technicalContact")),
            "NameServers": name_servers,
            "Status": statuses,
        }
    )
    if not parsed:
        # Unregistered domains return a record in which every field is empty and only the raw registry text is set.
        return {}
    parsed["DomainName"] = str(response.get("domainName") or domain).lower()
    return add_raw_text(parsed, registry)


def parse_ip_whois(ip: str, response: dict[str, Any]) -> dict[str, Any]:
    registry = response.get("registryData") or {}
    parsed = remove_blank_values(
        {
            "Registry": response.get("registrarName"),
            "Owner": response.get("owner"),
            "NetName": response.get("netname"),
            "NetRange": response.get("netrange"),
            "CIDR": response.get("cidr"),
            "ASN": response.get("as"),
            "Country": response.get("country"),
            "CreatedDate": registry.get("standardCreatedDate") or registry.get("createdDate"),
            "UpdatedDate": registry.get("standardUpdatedDate") or registry.get("updatedDate"),
            "Abuse": parse_contact(registry.get("abuseContact")),
            "Admin": parse_contact(registry.get("administrativeContact")),
            "Tech": parse_contact(registry.get("technicalContact")),
            "Status": registry.get("status"),
        }
    )
    if not parsed:
        return {}
    parsed["IP"] = str(response.get("ip") or ip)
    return add_raw_text(parsed, registry)


def parse_ip_history(response: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "IP": record.get("ip"),
            "Location": record.get("location"),
            "Owner": record.get("owner"),
            "LastSeen": record.get("lastseen"),
        }
        for record in as_list(response.get("records"))
        if isinstance(record, dict)
    ]


def parse_reverse_ip_domains(response: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"Name": domain.get("name"), "LastResolved": domain.get("last_resolved")}
        for domain in as_list(response.get("domains"))
        if isinstance(domain, dict)
    ]


def parse_domain_names(response: dict[str, Any]) -> list[str]:
    """Normalizes the domain lists of Reverse NS (objects) and Reverse MX (strings) to a list of names."""
    names: list[str] = []
    for domain in as_list(response.get("domains")):
        name = domain.get("domain") if isinstance(domain, dict) else domain
        if name:
            names.append(str(name))
    return names


def whois_table(title: str, whois: dict[str, Any], headers: list[str]) -> str:
    flat: dict[str, Any] = {}
    for key, value in whois.items():
        if key == "RawText":
            continue
        if isinstance(value, dict):
            flat[key] = ", ".join(f"{name}: {item}" for name, item in value.items())
        else:
            flat[key] = value
    return tableToMarkdown(title, flat, headers=headers, removeNull=True)


DOMAIN_WHOIS_HEADERS = [
    "DomainName",
    "RegistrarName",
    "RegistrarIANAID",
    "CreatedDate",
    "UpdatedDate",
    "ExpiresDate",
    "AbuseEmail",
    "Registrant",
    "Admin",
    "Tech",
    "NameServers",
    "Status",
]
IP_WHOIS_HEADERS = [
    "IP",
    "Registry",
    "Owner",
    "NetName",
    "NetRange",
    "CIDR",
    "ASN",
    "Country",
    "CreatedDate",
    "UpdatedDate",
    "Abuse",
    "Admin",
    "Tech",
    "Status",
]

""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Validates the API key with the Account API, which does not consume queries."""
    try:
        client.account_balance()
    except DemistoException as error:
        message = str(error)
        if "invalid api key" in message.lower() or "authorization error" in message.lower():
            return "Authorization Error: make sure the API key is correct."
        raise
    return "ok"


def account_balance_command(client: Client, args: dict[str, Any]) -> CommandResults:
    body = client.account_balance()
    response = body["response"]
    plan = "trial" if "trial" in response else "monthly"
    subscription = response.get(plan) or {}
    limit = to_int(subscription.get("limit"))
    usage = to_int(subscription.get("usage"))
    outputs = {
        "Plan": plan,
        "MonthlyLimit": limit,
        "MonthlyUsage": usage,
        # A limit of 0 means the plan is unlimited, so there is no remaining count.
        "MonthlyRemaining": max(limit - usage, 0) if limit is not None and limit > 0 and usage is not None else None,
        "PrepaidBalance": to_int((response.get("prepaid") or {}).get("balance")),
    }
    return CommandResults(
        outputs_prefix="ViewDNS.Account",
        outputs=outputs,
        readable_output=tableToMarkdown(
            f"{INTEGRATION_NAME} Account Balance",
            outputs,
            headers=["Plan", "MonthlyLimit", "MonthlyUsage", "MonthlyRemaining", "PrepaidBalance"],
            headerTransform=pascalToSpace,
            removeNull=True,
        ),
        raw_response=body,
    )


def reverse_ip_command(client: Client, args: dict[str, Any]) -> CommandResults:
    host = get_required_arg(args, "host")
    page = get_positive_int_arg(args, "page", 1)
    limit = get_positive_int_arg(args, "limit", DEFAULT_LIMIT)
    body = client.reverse_ip(host, page)
    response = body["response"]
    domains = parse_reverse_ip_domains(response)[:limit]
    total = to_int(response.get("domain_count")) or 0
    outputs = {"Host": host, "DomainCount": total, "Page": page, "Domains": domains}
    readable = (
        tableToMarkdown(
            paged_title(f"Reverse IP for {host}", len(domains), total, page),
            domains,
            headers=["Name", "LastResolved"],
            headerTransform=pascalToSpace,
        )
        if domains
        else no_results(f"host {host}")
    )
    return CommandResults(
        outputs_prefix="ViewDNS.ReverseIP",
        outputs_key_field="Host",
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def reverse_whois_command(client: Client, args: dict[str, Any]) -> CommandResults:
    query = get_required_arg(args, "query")
    page = get_positive_int_arg(args, "page", 1)
    limit = get_positive_int_arg(args, "limit", DEFAULT_LIMIT)
    body = client.reverse_whois(query, page)
    response = body["response"]
    matches = [
        {"Domain": match.get("domain"), "CreatedDate": match.get("created_date"), "Registrar": match.get("registrar")}
        for match in as_list(response.get("matches"))
        if isinstance(match, dict)
    ][:limit]
    total = to_int(response.get("result_count")) or 0
    outputs = {
        "Query": query,
        "ResultCount": total,
        "TotalPages": to_int(response.get("total_pages")) or 0,
        "CurrentPage": to_int(response.get("current_page")) or page,
        "Matches": matches,
    }
    readable = (
        tableToMarkdown(
            paged_title(f"Reverse WHOIS for {query}", len(matches), total, page),
            matches,
            headers=["Domain", "CreatedDate", "Registrar"],
            headerTransform=pascalToSpace,
        )
        if matches
        else no_results(f"search term {query}")
    )
    return CommandResults(
        outputs_prefix="ViewDNS.ReverseWhois",
        outputs_key_field="Query",
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def reverse_server_lookup(
    args: dict[str, Any],
    arg_name: str,
    key_field: str,
    title: str,
    outputs_prefix: str,
    lookup: Callable[[str, int | None], dict[str, Any]],
) -> CommandResults:
    """Shared implementation of the Reverse NS and Reverse MX commands, whose responses have the same structure."""
    server = get_required_arg(args, arg_name)
    page = get_positive_int_arg(args, "page", 1)
    limit = get_positive_int_arg(args, "limit", DEFAULT_LIMIT)
    body = lookup(server, page)
    response = body["response"]
    domains = parse_domain_names(response)[:limit]
    total = to_int(response.get("domain_count")) or 0
    outputs = {
        key_field: server,
        "DomainCount": total,
        "TotalPages": to_int(response.get("total_pages")) or 0,
        "CurrentPage": to_int(response.get("current_page")) or page,
        "Domains": domains,
    }
    readable = (
        tableToMarkdown(
            paged_title(f"{title} for {server}", len(domains), total, page),
            [{"Domain": domain} for domain in domains],
            headers=["Domain"],
        )
        if domains
        else no_results(f"{title} of {server}")
    )
    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=key_field,
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def reverse_ns_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return reverse_server_lookup(args, "nameserver", "Nameserver", "Reverse NS", "ViewDNS.ReverseNS", client.reverse_ns)


def reverse_mx_command(client: Client, args: dict[str, Any]) -> CommandResults:
    return reverse_server_lookup(args, "mail_server", "MailServer", "Reverse MX", "ViewDNS.ReverseMX", client.reverse_mx)


def ip_history_command(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = get_required_arg(args, "domain")
    limit = get_positive_int_arg(args, "limit", DEFAULT_LIMIT)
    body = client.ip_history(domain)
    all_records = parse_ip_history(body["response"])
    records = all_records[:limit]
    outputs = {"Domain": domain, "RecordCount": len(all_records), "Records": records}
    readable = (
        tableToMarkdown(
            f"{INTEGRATION_NAME} IP History for {domain} (showing {len(records)} of {len(all_records)})",
            records,
            headers=["IP", "Location", "Owner", "LastSeen"],
            headerTransform=pascalToSpace,
        )
        if records
        else no_results(f"domain {domain}")
    )
    return CommandResults(
        outputs_prefix="ViewDNS.IPHistory",
        outputs_key_field="Domain",
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def dns_record_command(client: Client, args: dict[str, Any]) -> CommandResults:
    domain = get_required_arg(args, "domain")
    record_type = str(args.get("record_type") or "ANY").strip().upper()
    body = client.dns_record(domain, record_type.lower())
    records = [
        remove_blank_values(
            {
                "Name": record.get("name"),
                "TTL": to_int(record.get("ttl")),
                "Class": record.get("class"),
                "Type": record.get("type"),
                "Priority": to_int(record.get("priority")),
                "Data": record.get("data"),
            }
        )
        for record in as_list(body["response"].get("records"))
        if isinstance(record, dict)
    ]
    outputs = {"Domain": domain, "RecordType": record_type, "Records": records}
    readable = (
        tableToMarkdown(
            f"{INTEGRATION_NAME} DNS Records for {domain} ({record_type})",
            records,
            headers=["Name", "Type", "TTL", "Class", "Priority", "Data"],
            removeNull=True,
        )
        if records
        else no_results(f"{record_type} records of {domain}")
    )
    return CommandResults(
        outputs_prefix="ViewDNS.DNSRecord",
        outputs_key_field=["Domain", "RecordType"],
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def whois_command(client: Client, args: dict[str, Any]) -> CommandResults:
    target = get_required_arg(args, "domain")
    body = client.whois(target)
    response = body["response"]
    if is_ip_valid(target, accept_v6_ips=True) or "ip" in (body.get("query") or {}):
        whois = parse_ip_whois(target, response)
        prefix, key_field, headers = "ViewDNS.IPWhois", "IP", IP_WHOIS_HEADERS
    else:
        whois = parse_domain_whois(target, response)
        prefix, key_field, headers = "ViewDNS.Whois", "DomainName", DOMAIN_WHOIS_HEADERS
    if not whois:
        return CommandResults(readable_output=no_results(f"WHOIS of {target}"), raw_response=body)
    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key_field,
        outputs=whois,
        readable_output=whois_table(f"{INTEGRATION_NAME} WHOIS for {target}", whois, headers),
        raw_response=body,
    )


def port_scan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    host = get_required_arg(args, "host")
    body = client.port_scan(host)
    ports = [
        {"Number": to_int(port.get("number")), "Service": port.get("service"), "Status": port.get("status")}
        for port in as_list(body["response"].get("port"))
        if isinstance(port, dict)
    ]
    open_ports = [port["Number"] for port in ports if port["Status"] == "open"]
    outputs = {"Host": host, "OpenPorts": open_ports, "Ports": ports}
    readable = (
        tableToMarkdown(
            f"{INTEGRATION_NAME} Port Scan for {host} ({len(open_ports)} open)",
            ports,
            headers=["Number", "Service", "Status"],
        )
        if ports
        else no_results(f"port scan of {host}")
    )
    return CommandResults(
        outputs_prefix="ViewDNS.PortScan",
        outputs_key_field="Host",
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def ping_command(client: Client, args: dict[str, Any]) -> CommandResults:
    host = get_required_arg(args, "host")
    body = client.ping(host)
    results: list[dict[str, Any]] = []
    for region in as_list(body["response"].get("detail")):
        if not isinstance(region, dict):
            continue
        for location in as_list(region.get("locations")):
            if not isinstance(location, dict):
                continue
            results.append(
                {
                    "Region": region.get("region"),
                    "Location": location.get("location"),
                    "IPAddress": location.get("ip_address"),
                    "MinRTT": to_float(location.get("min_rtt")),
                    "MaxRTT": to_float(location.get("max_rtt")),
                    "AvgRTT": to_float(location.get("avg_rtt")),
                    "PacketLoss": location.get("packet_loss"),
                }
            )
    outputs = {"Host": host, "Results": results}
    readable = (
        tableToMarkdown(
            f"{INTEGRATION_NAME} Ping for {host} (RTT in milliseconds)",
            results,
            headers=["Region", "Location", "IPAddress", "MinRTT", "AvgRTT", "MaxRTT", "PacketLoss"],
            headerTransform=pascalToSpace,
        )
        if results
        else no_results(f"ping of {host}")
    )
    return CommandResults(
        outputs_prefix="ViewDNS.Ping",
        outputs_key_field="Host",
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def traceroute_command(client: Client, args: dict[str, Any]) -> CommandResults:
    host = get_required_arg(args, "host")
    body = client.traceroute(host)
    hops = [
        {
            "Number": to_int(hop.get("number")),
            "Hostname": hop.get("hostname"),
            "IP": hop.get("ip"),
            "RTT": to_float(hop.get("rtt")),
        }
        for hop in as_list(body["response"].get("hops"))
        if isinstance(hop, dict)
    ]
    outputs = {"Host": host, "Hops": hops}
    readable = (
        tableToMarkdown(
            f"{INTEGRATION_NAME} Traceroute to {host} (RTT in milliseconds)",
            hops,
            headers=["Number", "Hostname", "IP", "RTT"],
        )
        if hops
        else no_results(f"traceroute to {host}")
    )
    return CommandResults(
        outputs_prefix="ViewDNS.Traceroute",
        outputs_key_field="Host",
        outputs=outputs,
        readable_output=readable,
        raw_response=body,
    )


def build_dbot_score(indicator: str, indicator_type: str, reliability: str) -> Common.DBotScore:
    """ViewDNS provides context only and no verdict, so the score is always Unknown (0)."""
    return Common.DBotScore(
        indicator=indicator,
        indicator_type=indicator_type,
        integration_name=INTEGRATION_NAME,
        score=Common.DBotScore.NONE,
        reliability=reliability,
    )


def enrich_domain(client: Client, domain: str, reliability: str) -> CommandResults:
    whois = parse_domain_whois(domain, client.whois(domain)["response"])
    history = parse_ip_history(client.ip_history(domain)["response"])
    registrant = whois.get("Registrant") or {}
    admin = whois.get("Admin") or {}
    tech = whois.get("Tech") or {}
    indicator = Common.Domain(
        domain=domain,
        dbot_score=build_dbot_score(domain, DBotScoreType.DOMAIN, reliability),
        organization=registrant.get("Organization"),
        creation_date=whois.get("CreatedDate"),
        updated_date=whois.get("UpdatedDate"),
        expiration_date=whois.get("ExpiresDate"),
        domain_status=whois.get("Status"),
        name_servers=whois.get("NameServers"),
        registrar_name=whois.get("RegistrarName"),
        registrar_abuse_email=whois.get("AbuseEmail"),
        registrant_name=registrant.get("Name"),
        registrant_email=registrant.get("Email"),
        registrant_phone=registrant.get("Phone"),
        registrant_country=registrant.get("Country"),
        admin_name=admin.get("Name"),
        admin_email=admin.get("Email"),
        admin_phone=admin.get("Phone"),
        admin_country=admin.get("Country"),
        tech_name=tech.get("Name"),
        tech_email=tech.get("Email"),
        tech_organization=tech.get("Organization"),
        tech_country=tech.get("Country"),
    )
    shown_history = history[:REPUTATION_MAX_ITEMS]
    outputs = {
        "Name": domain,
        "Whois": {key: value for key, value in whois.items() if key != "RawText"},
        "IPHistoryCount": len(history),
        "IPHistory": shown_history,
    }
    readable = whois_table(f"{INTEGRATION_NAME} WHOIS for {domain}", whois, DOMAIN_WHOIS_HEADERS) if whois else ""
    if shown_history:
        readable += tableToMarkdown(
            f"{INTEGRATION_NAME} IP History for {domain} (showing {len(shown_history)} of {len(history)})",
            shown_history,
            headers=["IP", "Location", "Owner", "LastSeen"],
            headerTransform=pascalToSpace,
        )
    return CommandResults(
        outputs_prefix="ViewDNS.Domain",
        outputs_key_field="Name",
        outputs=outputs,
        indicator=indicator,
        readable_output=readable or no_results(f"domain {domain}"),
    )


def enrich_ip(client: Client, ip: str, reliability: str) -> CommandResults:
    whois = parse_ip_whois(ip, client.whois(ip)["response"])
    reverse_ip = client.reverse_ip(ip)["response"]
    hosted = parse_reverse_ip_domains(reverse_ip)[:REPUTATION_MAX_ITEMS]
    hosted_count = to_int(reverse_ip.get("domain_count")) or 0
    abuse = whois.get("Abuse") or {}
    indicator = Common.IP(
        ip=ip,
        dbot_score=build_dbot_score(ip, DBotScoreType.IP, reliability),
        asn=whois.get("ASN"),
        as_owner=whois.get("Owner"),
        geo_country=whois.get("Country"),
        organization_name=whois.get("Owner"),
        updated_date=whois.get("UpdatedDate"),
        registrar_abuse_name=abuse.get("Name"),
        registrar_abuse_email=abuse.get("Email"),
        registrar_abuse_phone=abuse.get("Phone"),
        registrar_abuse_network=whois.get("CIDR") or whois.get("NetRange"),
    )
    outputs = {
        "Address": ip,
        "Whois": {key: value for key, value in whois.items() if key != "RawText"},
        "HostedDomainCount": hosted_count,
        "HostedDomains": hosted,
    }
    readable = whois_table(f"{INTEGRATION_NAME} WHOIS for {ip}", whois, IP_WHOIS_HEADERS) if whois else ""
    readable += tableToMarkdown(
        f"{INTEGRATION_NAME} Domains Hosted on {ip} (showing {len(hosted)} of {hosted_count})",
        hosted,
        headers=["Name", "LastResolved"],
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        outputs_prefix="ViewDNS.IP",
        outputs_key_field="Address",
        outputs=outputs,
        indicator=indicator,
        readable_output=readable,
    )


def reputation_command(
    client: Client,
    args: dict[str, Any],
    arg_name: str,
    enabled: bool,
    reliability: str,
    enrich: Callable[[Client, str, str], CommandResults],
) -> list[CommandResults]:
    """Shared implementation of the generic reputation commands.

    A failure to enrich one indicator is reported as a warning so that the remaining indicators are still enriched.
    """
    if not enabled:
        return [CommandResults(readable_output=REPUTATION_DISABLED_MESSAGE.format(command=arg_name))]
    indicators = argToList(args.get(arg_name))
    if not indicators:
        raise DemistoException(f"The '{arg_name}' argument is required.")
    results: list[CommandResults] = []
    for indicator in indicators:
        try:
            results.append(enrich(client, str(indicator).strip(), reliability))
        except DemistoException as error:
            results.append(
                CommandResults(
                    readable_output=f"{INTEGRATION_NAME}: could not enrich {indicator}. {error}",
                    entry_type=EntryType.WARNING,
                )
            )
    return results


def domain_command(client: Client, args: dict[str, Any], enabled: bool, reliability: str) -> list[CommandResults]:
    return reputation_command(client, args, "domain", enabled, reliability, enrich_domain)


def ip_command(client: Client, args: dict[str, Any], enabled: bool, reliability: str) -> list[CommandResults]:
    return reputation_command(client, args, "ip", enabled, reliability, enrich_ip)


""" MAIN FUNCTION """

COMMANDS: dict[str, Callable[[Client, dict[str, Any]], CommandResults]] = {
    "viewdns-account-balance": account_balance_command,
    "viewdns-reverse-ip": reverse_ip_command,
    "viewdns-reverse-whois": reverse_whois_command,
    "viewdns-reverse-ns": reverse_ns_command,
    "viewdns-reverse-mx": reverse_mx_command,
    "viewdns-ip-history": ip_history_command,
    "viewdns-dns-record": dns_record_command,
    "viewdns-whois": whois_command,
    "viewdns-port-scan": port_scan_command,
    "viewdns-ping": ping_command,
    "viewdns-traceroute": traceroute_command,
}


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = str((params.get("credentials") or {}).get("password") or "").strip()
    if api_key:
        add_sensitive_log_strs(api_key)

    demisto.debug(f"Command being called is {command}")
    try:
        if not api_key:
            raise DemistoException("The API key is required.")
        reliability = params.get("integrationReliability") or DBotScoreReliability.C
        if not DBotScoreReliability.is_valid_type(reliability):
            raise DemistoException(f"Invalid source reliability: {reliability}")
        reputation_enabled = argToBoolean(params.get("enable_reputation") or False)
        client = Client(
            base_url=str(params.get("url") or DEFAULT_BASE_URL).rstrip("/"),
            api_key=api_key,
            verify=not argToBoolean(params.get("insecure") or False),
            proxy=argToBoolean(params.get("proxy") or False),
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "domain":
            return_results(domain_command(client, args, reputation_enabled, reliability))
        elif command == "ip":
            return_results(ip_command(client, args, reputation_enabled, reliability))
        elif command in COMMANDS:
            return_results(COMMANDS[command](client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as error:
        message = str(error)
        details = traceback.format_exc()
        if api_key:
            message = message.replace(api_key, "<api-key>")
            details = details.replace(api_key, "<api-key>")
        demisto.debug(details)
        return_error(f"Failed to execute {command} command.\nError:\n{message}", error=error)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
