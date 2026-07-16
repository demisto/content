import urllib.parse
from typing import Any

import urllib3
from CommonServerPython import *

urllib3.disable_warnings()

INTEGRATION_NAME = "Intel 471 Credentials"
FEED_URL_CREDENTIALS = "https://api.intel471.cloud/integrations/creds/v1/credentials/stream"
DEMISTO_VERSION = demisto.demistoVersion()
CONTENT_PACK = f"Intel471 Feed/{get_pack_version()!s}"
USER_AGENT = f'XSOAR/{DEMISTO_VERSION["version"]}.{DEMISTO_VERSION["buildNumber"]} - {CONTENT_PACK} - {INTEGRATION_NAME}'
MAX_PAGE_SIZE = 1000
DEFAULT_MAX_INCIDENTS = 200
REQUEST_TIMEOUT = 60
INCIDENT_TYPE = "Intel 471 Leaked Credential"
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


class Client:
    """Client for the Intel 471 Credentials API."""

    headers = {"user-agent": USER_AGENT}

    def __init__(
        self,
        auth: tuple[str, str],
        insecure: bool = False,
        credential_set_name: str | None = None,
        credential_set_id: str | None = None,
        domain: str | None = None,
        affiliation_group: str | None = None,
        password_strength: str | None = None,
        detected_malware: str | None = None,
        girs: str | None = None,
        fetch_time: str | None = None,
    ):
        self.auth = auth
        self._verify = insecure
        self.credential_set_name = credential_set_name
        self.credential_set_id = credential_set_id
        self.domain = domain
        self.affiliation_group = affiliation_group
        self.password_strength = password_strength
        self.detected_malware = detected_malware
        self.girs = girs
        self.fetch_time = fetch_time
        self._proxies = handle_proxy(proxy_param_name="proxy", checkbox_default_value=False)

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

        params["size"] = str(min(MAX_PAGE_SIZE, max(limit, 1)))
        params["last_updated_from"] = from_ts
        if cursor:
            params["cursor"] = cursor

        should_continue = True
        while should_continue:
            encoded_params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            try:
                response = requests.get(
                    url=FEED_URL_CREDENTIALS,
                    params=encoded_params,
                    verify=self._verify,
                    proxies=self._proxies,
                    headers=self.headers,
                    auth=self.auth,
                    timeout=REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                data = response.json()
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

                if len(result) >= limit:
                    should_continue = False
                    result = result[:limit]

            except requests.exceptions.Timeout as err:
                demisto.debug(str(err))
                raise Exception(
                    f"Timeout error in the API call to {INTEGRATION_NAME}.\nRequest exceeded {REQUEST_TIMEOUT}s.\n\n{err}"
                )
            except requests.exceptions.SSLError as err:
                demisto.debug(str(err))
                raise Exception(
                    f"Connection error in the API call to {INTEGRATION_NAME}.\nCheck your not secure parameter.\n\n{err}"
                )
            except requests.ConnectionError as err:
                demisto.debug(str(err))
                raise Exception(
                    f"Connection error in the API call to {INTEGRATION_NAME}.\nCheck your Server URL parameter.\n\n{err}"
                )
            except requests.exceptions.HTTPError as err:
                demisto.debug(f"Got an error from {FEED_URL_CREDENTIALS} while fetching credentials {err!s}")
                raise Exception(f"HTTP error in the API call to {INTEGRATION_NAME}.\nCheck your configuration.\n\n{err}")
            except ValueError as err:
                demisto.debug(str(err))
                raise ValueError(f"Could not parse returned data to JSON. \n\nError message: {err}")

        return result, next_cursor


def test_module(client: Client, *_) -> str:
    """Verifies API connectivity by issuing a small /credentials/stream request."""
    start_date, _end = parse_date_range(client.fetch_time or "1 day", utc=True, to_timestamp=True)
    client.fetch_credentials(str(start_date), "", 1)
    return "ok"


def _indicator_type_for_login(login: str) -> str:
    if login and "@" in login:
        return FeedIndicatorType.Email
    return FeedIndicatorType.Account


def build_indicator(credential: dict[str, Any]) -> dict[str, Any]:
    """Builds an XSOAR indicator dict from a single /credentials/stream record.

    Returns an empty dict when no usable login value is present.
    """
    data = credential.get("data", {}) or {}
    login = data.get("credential_login", "") or ""
    if not login:
        return {}

    indicator_type = _indicator_type_for_login(login)
    activity = credential.get("activity", {}) or {}

    info_stealer = data.get("info_stealer", {}) or {}
    malware_families = info_stealer.get("malware_family", []) or []

    fields: dict[str, Any] = {
        "firstseenbysource": activity.get("first_seen_ts", ""),
        "lastseenbysource": activity.get("last_seen_ts", ""),
        "tags": [],
    }
    if malware_families:
        fields["tags"].extend(malware_families)
    affiliations = data.get("affiliations", []) or []
    if affiliations:
        fields["tags"].extend(affiliations)

    for key in INFO_STEALER_FIELDS:
        raw = info_stealer.get(key)
        # infection_ts maps to a date-typed indicator field, so keep it as a single ISO string
        # rather than the comma-joined form used for the multi-value shortText fields.
        if key == "infection_ts":
            value = _first_info_stealer_value(raw)
        else:
            value = _format_info_stealer_value(raw)
        if value:
            cli_name = CLI_NAME_OVERRIDES.get(key, f"intel471infostealer{key.replace('_', '')}")
            fields[cli_name] = value

    return {
        "value": login,
        "type": indicator_type,
        "rawJSON": credential,
        "fields": fields,
    }


def _flatten_info_stealer(info_stealer: dict[str, Any]) -> list[dict[str, str]]:
    """Builds XSOAR incident labels from the credential's info_stealer payload.

    The /credentials/stream payload uses ``InfoStealerResponse_Set`` (array per field) — values are
    joined with commas so they render as a single label string per attribute.
    """
    labels: list[dict[str, str]] = []
    for key in INFO_STEALER_FIELDS:
        raw = info_stealer.get(key)
        if raw is None or raw == "":
            continue
        if isinstance(raw, list):
            values = [str(v) for v in raw if v not in (None, "")]
            if not values:
                continue
            value = ", ".join(values)
        else:
            value = str(raw)
        labels.append({"type": f"info_stealer.{key}", "value": value})
    return labels


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


def compose_incident_details(credential: dict[str, Any]) -> str:
    """Builds a human-readable ``details`` blob for an Intel 471 leaked-credential incident.

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


def build_incident(credential: dict[str, Any]) -> dict[str, Any]:
    """Builds an XSOAR incident dict from a single /credentials/stream record."""
    data = credential.get("data", {}) or {}
    login = data.get("credential_login", "") or "(unknown login)"
    domain = data.get("detection_domain", "") or data.get("credential_domain", "")
    occurred = credential.get("last_updated_ts", "")
    info_stealer = data.get("info_stealer", {}) or {}

    name = f"Intel 471 Leaked Credential: {login}"
    if domain:
        name = f"{name} @ {domain}"

    incident: dict[str, Any] = {
        "name": name,
        "type": INCIDENT_TYPE,
        "details": compose_incident_details(credential),
        "rawJSON": json.dumps(credential),
    }
    if occurred:
        incident["occurred"] = occurred

    labels = _flatten_info_stealer(info_stealer)
    if labels:
        incident["labels"] = labels

    return incident


def fetch_indicators_command(client: Client, max_items: int) -> tuple[list, list, dict]:
    """Fetches leaked credentials and turns each one into an indicator and an incident.

    Indicators are the primary output; incidents are produced inline within the
    indicator-creation loop so each credential yields exactly one of each, linked
    together via the indicator's ``relatedIncidents`` field.

    Returns:
        A tuple of (indicators, incidents, next_run).
    """
    last_run = demisto.getLastRun() or {}
    cursor = last_run.get("cursor", "")
    from_ts = last_run.get("from_ts", "")

    if not from_ts:
        start_date, _end = parse_date_range(client.fetch_time or "7 days", utc=True, to_timestamp=True)
        from_ts = str(start_date)

    credentials, next_cursor = client.fetch_credentials(from_ts, cursor, max_items)

    indicators: list = []
    incidents: list = []
    for credential in credentials:
        indicator = build_indicator(credential)
        if not indicator:
            continue
        incident = build_incident(credential)
        indicator["relatedIncidents"] = [incident["name"]]
        indicators.append(indicator)
        incidents.append(incident)

    next_run = {"cursor": next_cursor or cursor, "from_ts": from_ts}
    return indicators, incidents, next_run


def get_indicators_command(client: Client, args: dict[str, str]) -> CommandResults:
    """War-room wrapper that returns the pending indicators without persisting state."""
    limit = arg_to_number(args.get("limit")) or 50
    start_date, _end = parse_date_range(client.fetch_time or "7 days", utc=True, to_timestamp=True)
    credentials, _cursor = client.fetch_credentials(str(start_date), "", limit)

    indicators: list = []
    for credential in credentials:
        indicator = build_indicator(credential)
        if indicator:
            indicators.append(indicator)

    hr = [{"Value": i.get("value"), "Type": i.get("type"), "fields": i.get("fields")} for i in indicators]
    human_readable = tableToMarkdown(
        "Indicators from Intel 471 Credentials:", hr, headers=["Value", "Type", "fields"], removeNull=True
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Intel471Credentials.Indicators",
        outputs_key_field="value",
        raw_response=indicators,
    )


def main():
    args = demisto.args()
    params = demisto.params()
    use_ssl = not params.get("insecure", False)
    fetch_time = params.get("fetch_time")
    credential_set_name = params.get("credential_set_name")
    credential_set_id = params.get("credential_set_id")
    domain = params.get("domain")
    affiliation_group = params.get("affiliation_group")
    password_strength = params.get("password_strength")
    detected_malware = params.get("detected_malware")
    girs = params.get("girs")
    max_items = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_INCIDENTS

    credentials = params.get("credentials", {})
    if not credentials:
        raise DemistoException("Integration credentials not entered.")
    auth = (credentials.get("identifier", ""), credentials.get("password", ""))

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = Client(
            auth,
            use_ssl,
            credential_set_name,
            credential_set_id,
            domain,
            affiliation_group,
            password_strength,
            detected_malware,
            girs,
            fetch_time,
        )

        if command == "test-module":
            return_results(test_module(client, params))
        elif command == "fetch-indicators":
            indicators, incidents, next_run = fetch_indicators_command(client, max_items)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
            for iter_ in batch(incidents, batch_size=2000):
                demisto.createIncidents(iter_)
            demisto.setLastRun(next_run)
        elif command == "intel471-credentials-get-indicators":
            return_results(get_indicators_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as err:
        err_msg = f"Error in {INTEGRATION_NAME} Integration. [{err}]"
        return_error(err_msg)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
