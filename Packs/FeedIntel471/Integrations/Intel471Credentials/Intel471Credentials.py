"""Intel471 Credentials.

Fetches leaked credentials from the Intel471 Credentials API.

Each credential becomes an incident; indicators are then extracted from that credential's payload
and associated back to the incident that produced them via the indicator's ``relatedIncidents``
field. Previously this integration was a feed: the indicator was the primary artifact and the
incident was produced as a by-product inside the indicator-building loop.

More than the login is extracted: the infected host's IP addresses, PC name and the
detection/credential domains all become indicators of their own, all pointing at the same incident.
"""

import re
import urllib.parse
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

urllib3.disable_warnings()

INTEGRATION_NAME = "Intel471 Credentials"
API_BASE_URL = "https://api.intel471.cloud"
FEED_CREDENTIALS_PATH = "/integrations/creds/v1/credentials/stream"
FEED_URL_CREDENTIALS = f"{API_BASE_URL}{FEED_CREDENTIALS_PATH}"
DEMISTO_VERSION = demisto.demistoVersion()
CONTENT_PACK = f"Intel471 Feed/{get_pack_version()!s}"
USER_AGENT = f"XSOAR/{DEMISTO_VERSION['version']}.{DEMISTO_VERSION['buildNumber']} - {CONTENT_PACK} - {INTEGRATION_NAME}"
MAX_PAGE_SIZE = 1000
DEFAULT_MAX_INCIDENTS = 200
MAX_INCIDENTS_TO_FETCH = 1000
REQUEST_TIMEOUT = 60
DEFAULT_INCIDENT_TYPE = "Intel471 Leaked Credential"
BATCH_SIZE = 2000
INFO_STEALER_FIELDS = (
    "antivirus_software",
    "computer_username",
    "infection_ts",
    "ip",
    "isp",
    "machine_id",
    "malware_family",
    "malware_install_path",
    "os",
    "pc_name",
    "screenshot_path",
    "version",
)
# Override for keys whose XSOAR cliName can't be derived by stripping underscores.
CLI_NAME_OVERRIDES = {"infection_ts": "intel471infostealerinfectiontimestamp"}
REPUTATION_TO_SCORE = {
    "None": Common.DBotScore.NONE,
    "Good": Common.DBotScore.GOOD,
    "Suspicious": Common.DBotScore.SUSPICIOUS,
    "Bad": Common.DBotScore.BAD,
}
DOMAIN_REGEX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class Client(BaseClient):
    """Client for the Intel471 Credentials API."""

    def __init__(
        self,
        auth: tuple[str, str],
        verify: bool = True,
        proxy: bool = False,
        credential_set_name: str | None = None,
        credential_set_id: str | None = None,
        credential_login: str | None = None,
        domain: str | None = None,
        affiliation_group: str | None = None,
        password_strength: str | None = None,
        detected_malware: str | None = None,
        girs: str | None = None,
        password_length_gte: int | None = None,
        password_lowercase_gte: int | None = None,
        password_uppercase_gte: int | None = None,
        password_numbers_gte: int | None = None,
        password_punctuation_gte: int | None = None,
        password_symbols_gte: int | None = None,
        password_separators_gte: int | None = None,
        first_fetch: str | None = None,
    ):
        super().__init__(
            base_url=API_BASE_URL,
            verify=verify,
            proxy=proxy,
            headers={"user-agent": USER_AGENT},
            auth=auth,
            timeout=REQUEST_TIMEOUT,
        )
        self.credential_set_name = credential_set_name
        self.credential_set_id = credential_set_id
        self.credential_login = credential_login
        self.domain = domain
        self.affiliation_group = affiliation_group
        self.password_strength = password_strength
        self.detected_malware = detected_malware
        self.girs = girs
        self.password_length_gte = password_length_gte
        self.password_lowercase_gte = password_lowercase_gte
        self.password_uppercase_gte = password_uppercase_gte
        self.password_numbers_gte = password_numbers_gte
        self.password_punctuation_gte = password_punctuation_gte
        self.password_symbols_gte = password_symbols_gte
        self.password_separators_gte = password_separators_gte
        self.first_fetch = first_fetch

    def fetch_credentials(self, from_ts: str, cursor: str, limit: int) -> tuple[list, str]:
        """Pull leaked credentials from /credentials/stream.

        Args:
            from_ts: ``last_updated_from`` watermark (UNIX millis as str or period like ``7days``).
            cursor: stream cursor returned by previous call. Empty on the first run.
            limit: maximum number of credentials to return.

        Returns:
            A tuple of (credentials, next_cursor).
        """
        result: list = []
        next_cursor: str = cursor

        params: dict[str, Any] = {}
        if self.credential_set_name:
            params["credential_set_name"] = self.credential_set_name
        if self.credential_set_id:
            params["credential_set_id"] = self.credential_set_id
        if self.credential_login:
            params["credential_login"] = self.credential_login
        if self.domain:
            params["domain"] = self.domain
        if self.affiliation_group:
            params["affiliation_group"] = self.affiliation_group
        if self.password_strength:
            params["password_strength"] = self.password_strength
        if self.detected_malware:
            params["detected_malware"] = self.detected_malware
        if self.girs:
            params["girs"] = self.girs
        if self.password_length_gte is not None:
            params["password_length_gte"] = self.password_length_gte
        if self.password_lowercase_gte is not None:
            params["password_lowercase_gte"] = self.password_lowercase_gte
        if self.password_uppercase_gte is not None:
            params["password_uppercase_gte"] = self.password_uppercase_gte
        if self.password_numbers_gte is not None:
            params["password_numbers_gte"] = self.password_numbers_gte
        if self.password_punctuation_gte is not None:
            params["password_punctuation_gte"] = self.password_punctuation_gte
        if self.password_symbols_gte is not None:
            params["password_symbols_gte"] = self.password_symbols_gte
        if self.password_separators_gte is not None:
            params["password_separators_gte"] = self.password_separators_gte

        params["last_updated_from"] = from_ts
        if cursor:
            params["cursor"] = cursor

        should_continue = True
        while should_continue:
            remaining = limit - len(result)
            if remaining <= 0:
                break
            # Cap each request to what's still needed so cursor_next never advances
            # past items we don't keep — otherwise the next fetch would skip them.
            params["size"] = str(min(MAX_PAGE_SIZE, remaining))
            try:
                data = self._http_request(
                    method="GET",
                    url_suffix=FEED_CREDENTIALS_PATH,
                    params=params,
                    params_parser=urllib.parse.quote,
                )
                credentials: list = data.get("credentials", [])

                if credentials:
                    result.extend(credentials)
                else:
                    should_continue = False

                returned_cursor = data.get("cursor_next", "")
                if returned_cursor:
                    next_cursor = returned_cursor
                    params["cursor"] = returned_cursor
                else:
                    should_continue = False

            except Exception as err:
                if result:
                    demisto.error(f"Partial fetch failure: {err}\n{traceback.format_exc()}")
                    break
                raise

        return result, next_cursor


""" HELPER FUNCTIONS """


def _format_info_stealer_value(raw: Any) -> str:
    if raw is None or raw == "":
        return ""
    if isinstance(raw, list):
        values = [str(v) for v in raw if v not in (None, "")]
        return ", ".join(values)
    return str(raw)


def _first_info_stealer_value(raw: Any) -> str:
    if raw is None or raw == "":
        return ""
    if isinstance(raw, list):
        for v in raw:
            if v not in (None, ""):
                return str(v)
        return ""
    return str(raw)


def _as_list(raw: Any) -> list[str]:
    """Normalizes an ``InfoStealerResponse_Set`` value (scalar or array) into a list of strings."""
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return [str(v) for v in raw if v not in (None, "")]
    return [str(raw)]


def _indicator_type_for_login(login: str) -> str:
    if login and "@" in login:
        return FeedIndicatorType.Email
    return FeedIndicatorType.Account


def _flatten_info_stealer(info_stealer: dict[str, Any]) -> list[dict[str, str]]:
    """Builds XSOAR incident labels from the credential's info_stealer payload.

    The /credentials/stream payload uses ``InfoStealerResponse_Set`` (array per field) — values are
    joined with commas so they render as a single label string per attribute.
    """
    labels: list[dict[str, str]] = []
    for key in INFO_STEALER_FIELDS:
        value = _format_info_stealer_value(info_stealer.get(key))
        if value:
            labels.append({"type": f"info_stealer.{key}", "value": value})
    return labels


def _credential_tags(credential: dict[str, Any], indicator_tags: list[str] | None = None) -> list[str]:
    """Aggregates malware families, affiliations and the configured instance tags."""
    data = credential.get("data", {}) or {}
    info_stealer = data.get("info_stealer", {}) or {}

    tags: list[str] = []
    tags.extend(_as_list(info_stealer.get("malware_family")))
    tags.extend(_as_list(data.get("affiliations")))
    if indicator_tags:
        tags.extend(indicator_tags)
    return tags


""" INCIDENT BUILDING """


def compose_incident_details(credential: dict[str, Any]) -> str:
    """Builds a human-readable ``details`` blob for an Intel471 leaked-credential incident.

    Mirrors ``compose_incident_details`` in the Intel471WatcherAlerts integration so leaked-credential
    incidents render the same shape of summary as the watcher-alert credential adapter — but extended
    with the info_stealer + activity fields the ``/credentials/stream`` payload carries.
    """
    data = credential.get("data", {}) or {}
    activity = credential.get("activity", {}) or {}
    info_stealer = data.get("info_stealer", {}) or {}
    password = data.get("password", {}) or {}

    lines: list[str] = ["Source Object: CREDENTIAL"]

    login = data.get("credential_login", "")
    if login:
        lines.append(f"Credential Login: {login}")

    detection_domain = data.get("detection_domain", "")
    if detection_domain:
        lines.append(f"Detection Domain: {detection_domain}")

    credential_domain = data.get("credential_domain", "")
    if credential_domain and credential_domain != detection_domain:
        lines.append(f"Credential Domain: {credential_domain}")

    strength = password.get("strength", "")
    if strength:
        lines.append(f"Password Strength: {strength}")

    affiliations = data.get("affiliations", []) or []
    if affiliations:
        lines.append(f"Affiliations: {', '.join(str(a) for a in affiliations)}")

    first_seen = activity.get("first_seen_ts", "")
    if first_seen:
        lines.append(f"First Seen: {first_seen}")
    last_seen = activity.get("last_seen_ts", "")
    if last_seen:
        lines.append(f"Last Seen: {last_seen}")

    info_stealer_lines: list[str] = []
    for key in INFO_STEALER_FIELDS:
        value = _format_info_stealer_value(info_stealer.get(key))
        if value:
            info_stealer_lines.append(f"  {key}: {value}")
    if info_stealer_lines:
        lines.append("")
        lines.append("Info Stealer:")
        lines.extend(info_stealer_lines)

    return "\n".join(lines)


def build_incident(credential: dict[str, Any], incident_type: str = DEFAULT_INCIDENT_TYPE) -> dict[str, Any]:
    """Builds an XSOAR incident dict from a single /credentials/stream record."""
    data = credential.get("data", {}) or {}
    login = data.get("credential_login", "") or "(unknown login)"
    domain = data.get("detection_domain", "") or data.get("credential_domain", "")
    occurred = credential.get("last_updated_ts", "")
    info_stealer = data.get("info_stealer", {}) or {}

    name = f"Intel471 Leaked Credential: {login}"
    if domain:
        name = f"{name} @ {domain}"

    incident: dict[str, Any] = {
        "name": name,
        "type": incident_type,
        "details": compose_incident_details(credential),
        "rawJSON": json.dumps(credential),
    }
    if occurred:
        incident["occurred"] = occurred

    labels = _flatten_info_stealer(info_stealer)
    if labels:
        incident["labels"] = labels

    return incident


""" INDICATOR EXTRACTION """


def extract_indicators(
    credential: dict[str, Any],
    indicator_tags: list[str] | None = None,
    tlp_color: str | None = None,
    reputation: str | None = None,
) -> list[dict[str, Any]]:
    """Extracts every indicator carried by a single /credentials/stream record.

    The login is the primary indicator and is the only one that carries the ``intel471infostealer*``
    custom fields — those describe the host the credential was stolen from, so duplicating them onto
    the host's own IP/Host indicators would be redundant. The remaining observables (infected host
    IPs, PC name, detection/credential domains) are extracted as plain typed indicators.

    Returns:
        A list of indicator dicts, in the order login, domains, IPs, hosts. Empty if the record
        carries no usable observable at all.
    """
    data = credential.get("data", {}) or {}
    activity = credential.get("activity", {}) or {}
    info_stealer = data.get("info_stealer", {}) or {}

    tags = _credential_tags(credential, indicator_tags)
    base_fields: dict[str, Any] = {
        "firstseenbysource": activity.get("first_seen_ts", ""),
        "lastseenbysource": activity.get("last_seen_ts", ""),
    }
    if tlp_color:
        base_fields["trafficlightprotocol"] = tlp_color
    score = REPUTATION_TO_SCORE.get(reputation or "", Common.DBotScore.NONE)

    def _indicator(value: str, indicator_type: str, extra_fields: dict[str, Any] | None = None) -> dict[str, Any]:
        # Each indicator gets its own tags list — the server mutates the dicts it is handed.
        fields = dict(base_fields, tags=list(tags))
        if extra_fields:
            fields.update(extra_fields)
        indicator: dict[str, Any] = {
            "value": value,
            "type": indicator_type,
            "rawJSON": credential,
            "fields": fields,
        }
        if score:
            indicator["score"] = score
        return indicator

    indicators: list[dict[str, Any]] = []

    login = data.get("credential_login", "") or ""
    if login:
        indicators.append(_indicator(login, _indicator_type_for_login(login), _info_stealer_fields(info_stealer)))

    seen: set[tuple[str, str]] = {(i["type"], i["value"]) for i in indicators}

    def _add(value: str, indicator_type: str) -> None:
        if not value or (indicator_type, value) in seen:
            return
        seen.add((indicator_type, value))
        indicators.append(_indicator(value, indicator_type))

    for domain in (data.get("detection_domain", ""), data.get("credential_domain", "")):
        if domain and DOMAIN_REGEX.match(str(domain)):
            _add(str(domain), FeedIndicatorType.Domain)

    for ip in _as_list(info_stealer.get("ip")):
        if is_ip_valid(ip, accept_v6_ips=True):
            _add(ip, FeedIndicatorType.ip_to_indicator_type(ip))

    for pc_name in _as_list(info_stealer.get("pc_name")):
        _add(pc_name, FeedIndicatorType.Host)

    return indicators


def _info_stealer_fields(info_stealer: dict[str, Any]) -> dict[str, Any]:
    """Maps the info_stealer payload onto the pack's ``intel471infostealer*`` indicator fields."""
    fields: dict[str, Any] = {}
    for key in INFO_STEALER_FIELDS:
        raw = info_stealer.get(key)
        # infection_ts maps to a date-typed indicator field, so keep it as a single ISO string
        # rather than the comma-joined form used for the multi-value shortText fields.
        value = _first_info_stealer_value(raw) if key == "infection_ts" else _format_info_stealer_value(raw)
        if value:
            fields[CLI_NAME_OVERRIDES.get(key, f"intel471infostealer{key.replace('_', '')}")] = value
    return fields


def associate_indicators_to_incident(indicators: list[dict[str, Any]], incident_id: str, incident_name: str) -> None:
    """Points every extracted indicator at the incident the credential produced.

    ``relatedIncidents`` is the field the server uses to link an indicator to incidents. It is
    populated with the real incident ID returned by ``demisto.createIncidents`` when available;
    the server only echoes created incidents back on some versions, so the incident name is used
    as a fallback so the association is never silently dropped.
    """
    related = incident_id or incident_name
    if not related:
        return
    for indicator in indicators:
        indicator["relatedIncidents"] = [related]


def created_incident_ids(created: Any, incidents: list[dict[str, Any]]) -> list[str]:
    """Normalizes the ``demisto.createIncidents`` return value into one ID per submitted incident.

    The server returns either a list of created incident objects, a single object, or nothing at
    all depending on the version. Created incidents are matched back to what was submitted by name
    where possible, falling back to submission order. Entries with no resolvable ID are returned as
    empty strings so the caller can fall back to the incident name.
    """
    if isinstance(created, dict):
        created_list = [created]
    elif isinstance(created, list):
        created_list = [item for item in created if isinstance(item, dict)]
    else:
        created_list = []

    by_name = {item.get("name"): str(item.get("id") or "") for item in created_list if item.get("name")}
    ids: list[str] = []
    for index, incident in enumerate(incidents):
        incident_id = by_name.get(incident.get("name"), "")
        if not incident_id and index < len(created_list):
            incident_id = str(created_list[index].get("id") or "")
        ids.append(incident_id)
    return ids


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Verifies API connectivity by issuing a small /credentials/stream request."""
    start_date, _end = parse_date_range(client.first_fetch or "1 day", utc=True, to_timestamp=True)
    client.fetch_credentials(str(start_date), "", 1)
    return "ok"


def fetch_incidents_command(
    client: Client,
    max_results: int,
    last_run: dict[str, Any],
    incident_type: str = DEFAULT_INCIDENT_TYPE,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Fetches leaked credentials and builds one incident per credential.

    Indicator extraction is deliberately *not* done here: the indicators have to reference the IDs
    the server assigns when the incidents are created, so the caller creates the incidents first
    and then calls :func:`extract_indicators` per credential.

    Returns:
        A tuple of (incidents, credentials, next_run). ``incidents[i]`` was built from
        ``credentials[i]``, so the caller can zip the two once it holds the created incident IDs.
    """
    cursor = last_run.get("cursor", "")
    from_ts = last_run.get("from_ts", "")

    if not from_ts:
        start_date, _end = parse_date_range(client.first_fetch or "7 days", utc=True, to_timestamp=True)
        from_ts = str(start_date)

    credentials, next_cursor = client.fetch_credentials(from_ts, cursor, max_results)

    incidents = [build_incident(credential, incident_type) for credential in credentials]
    next_run = {"cursor": next_cursor or cursor, "from_ts": from_ts}
    return incidents, credentials, next_run


def create_incidents_with_indicators(
    incidents: list[dict[str, Any]],
    credentials: list[dict[str, Any]],
    indicator_tags: list[str] | None = None,
    tlp_color: str | None = None,
    reputation: str | None = None,
) -> tuple[int, int]:
    """Creates the incidents, then extracts and associates the indicators for each one.

    Returns:
        A tuple of (incidents created, indicators created).
    """
    if not incidents:
        return 0, 0

    created: Any = []
    for incident_batch in batch(incidents, batch_size=BATCH_SIZE):
        batch_result = demisto.createIncidents(incident_batch)
        if isinstance(batch_result, list):
            created.extend(batch_result)
        elif isinstance(batch_result, dict):
            created.append(batch_result)

    incident_ids = created_incident_ids(created, incidents)

    indicators: list[dict[str, Any]] = []
    for incident, incident_id, credential in zip(incidents, incident_ids, credentials):
        extracted = extract_indicators(credential, indicator_tags, tlp_color, reputation)
        if not extracted:
            continue
        associate_indicators_to_incident(extracted, incident_id, incident["name"])
        indicators.extend(extracted)

    for indicator_batch in batch(indicators, batch_size=BATCH_SIZE):
        demisto.createIndicators(indicator_batch)

    return len(incidents), len(indicators)


def get_indicators_command(
    client: Client,
    args: dict[str, str],
    indicator_tags: list[str] | None = None,
    tlp_color: str | None = None,
    reputation: str | None = None,
) -> CommandResults:
    """War-room preview of the indicators the next fetch would extract. Persists no state."""
    limit = arg_to_number(args.get("limit")) or 50
    start_date, _end = parse_date_range(client.first_fetch or "7 days", utc=True, to_timestamp=True)
    credentials, _cursor = client.fetch_credentials(str(start_date), "", limit)

    indicators: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for credential in credentials:
        incident_name = build_incident(credential)["name"]
        for indicator in extract_indicators(credential, indicator_tags, tlp_color, reputation):
            indicators.append(indicator)
            rows.append(
                {
                    "Value": indicator.get("value"),
                    "Type": indicator.get("type"),
                    "Incident": incident_name,
                    "fields": indicator.get("fields"),
                }
            )

    human_readable = tableToMarkdown(
        "Indicators extracted from Intel471 Credentials:",
        rows,
        headers=["Value", "Type", "Incident", "fields"],
        removeNull=True,
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Intel471Credentials.Indicators",
        outputs_key_field="value",
        outputs=indicators,
        raw_response=indicators,
    )


def main():
    args = demisto.args()
    params = demisto.params()
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    first_fetch = params.get("first_fetch")
    incident_type = params.get("incidentType") or DEFAULT_INCIDENT_TYPE
    credential_set_name = params.get("credential_set_name")
    credential_set_id = params.get("credential_set_id")
    credential_login = params.get("credential_login")
    domain = params.get("domain")
    affiliation_group = params.get("affiliation_group")
    password_strength = params.get("password_strength")
    detected_malware = params.get("detected_malware")
    girs = params.get("girs")
    tlp_color = params.get("tlp_color")
    reputation = params.get("indicator_reputation")

    def _non_negative_param(name: str) -> int | None:
        value = arg_to_number(params.get(name))
        if value is not None and value < 0:
            raise DemistoException(f'"{name}" must be greater than or equal to 0.')
        return value

    password_length_gte = _non_negative_param("password_length_gte")
    password_lowercase_gte = _non_negative_param("password_lowercase_gte")
    password_uppercase_gte = _non_negative_param("password_uppercase_gte")
    password_numbers_gte = _non_negative_param("password_numbers_gte")
    password_punctuation_gte = _non_negative_param("password_punctuation_gte")
    password_symbols_gte = _non_negative_param("password_symbols_gte")
    password_separators_gte = _non_negative_param("password_separators_gte")
    indicator_tags = argToList(params.get("indicator_tags"))
    max_results = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_INCIDENTS
    max_results = min(max_results, MAX_INCIDENTS_TO_FETCH)

    credentials_param = params.get("credentials", {})
    if not credentials_param:
        raise DemistoException("Integration credentials not entered.")
    auth = (credentials_param.get("identifier", ""), credentials_param.get("password", ""))

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = Client(
            auth=auth,
            verify=verify,
            proxy=proxy,
            credential_set_name=credential_set_name,
            credential_set_id=credential_set_id,
            credential_login=credential_login,
            domain=domain,
            affiliation_group=affiliation_group,
            password_strength=password_strength,
            detected_malware=detected_malware,
            girs=girs,
            password_length_gte=password_length_gte,
            password_lowercase_gte=password_lowercase_gte,
            password_uppercase_gte=password_uppercase_gte,
            password_numbers_gte=password_numbers_gte,
            password_punctuation_gte=password_punctuation_gte,
            password_symbols_gte=password_symbols_gte,
            password_separators_gte=password_separators_gte,
            first_fetch=first_fetch,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            incidents, creds, next_run = fetch_incidents_command(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun() or {},
                incident_type=incident_type,
            )
            # The incidents are created here rather than handed back through ``demisto.incidents``
            # so their server-assigned IDs are available to associate the extracted indicators with.
            incident_count, indicator_count = create_incidents_with_indicators(
                incidents, creds, indicator_tags, tlp_color, reputation
            )
            demisto.info(f"Created {incident_count} incidents and {indicator_count} associated indicators.")
            demisto.setLastRun(next_run)
            # Nothing is left for the server to create — the incidents were already submitted above.
            demisto.incidents([])
        elif command == "intel471-credentials-get-indicators":
            return_results(get_indicators_command(client, args, indicator_tags, tlp_color, reputation))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as err:
        err_msg = f"Error in {INTEGRATION_NAME} Integration. [{err}]"
        return_error(err_msg, error=err)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
