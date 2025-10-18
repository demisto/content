# Prometheus.py
# Cortex XSOAR integration for querying Prometheus instant vectors by metric-name regex.
# Supports passing a pipe-separated metric list (e.g., "co2|solar|load|...").
# Commands:
#   - prometheus-query
#   - prometheus-raw
#   - test-module
#
# Outputs under: Prometheus.Metrics

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

# Disable insecure warnings if user chooses insecure=true
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PrometheusClient(BaseClient):
    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[tuple[str, str]] = None,
        timeout: int = 30,
    ):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, auth=auth)
        self.timeout = timeout

    def instant_query(self, query: str, at_time: Optional[str] = None) -> Dict[str, Any]:
        """
        Call /api/v1/query with a Prometheus query.
        at_time: RFC3339 or unix timestamp string (optional).
        """
        params: Dict[str, str] = {"query": query}
        if at_time:
            params["time"] = at_time
        return self._http_request(
            method="GET",
            url_suffix="/api/v1/query",
            params=params,
            timeout=self.timeout,
        )


def build_name_regex(fields: str, anchor: bool) -> str:
    """
    Normalize the user-provided pipe-separated metric list into a regex for __name__.
    Example input: "co2|solar|load"
    When anchor=True -> "^(co2|solar|load)$"
    When anchor=False -> "co2|solar|load"
    """
    parts = [p.strip() for p in fields.split("|") if p.strip()]
    if not parts:
        raise ValueError("fields resolved to an empty list.")
    regex_inner = "|".join(parts)
    if anchor:
        return f"^({regex_inner})$"
    return regex_inner


def format_result_rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert Prometheus instant query vector result into rows.
    Each item: {'metric': {...}, 'value': [ <unix_ts>, "<value_str>" ]}
    Output row keys:
      - name (metric __name__)
      - value (float where possible)
      - ts (ISO8601)
      - ts_unix (int)
      - labels (dict of the metric labels excluding __name__)
    """
    rows: List[Dict[str, Any]] = []
    data = result.get("data", {})
    if data.get("resultType") != "vector":
        return rows

    for item in data.get("result", []):
        metric = item.get("metric", {}) or {}
        val = item.get("value", [])
        if not isinstance(val, list) or len(val) < 2:
            continue
        ts_unix = int(float(val[0]))
        value_str = val[1]
        try:
            value = float(value_str)
        except Exception:
            value = value_str

        ts_iso = datetime.fromtimestamp(ts_unix).replace(tzinfo=timezone.utc).isoformat()
        name = metric.get("__name__", "")
        labels = {k: v for k, v in metric.items() if k != "__name__"}

        rows.append({"name": name, "value": value, "ts": ts_iso, "ts_unix": ts_unix, "labels": labels})
    return rows


def prometheus_query_command(client: PrometheusClient, args: Dict[str, Any], default_fields: Optional[str]) -> CommandResults:
    """
    Build query from fields (pipe-separated) and call /api/v1/query.
    """
    raw_query = args.get("query")
    fields = args.get("fields") or default_fields
    anchor = argToBoolean(args.get("anchor", "true"))
    at_time = args.get("time")

    if raw_query:
        query = raw_query
    else:
        if not fields:
            raise DemistoException('You must provide "fields" in the command or set "default_fields" in the instance.')
        name_regex = build_name_regex(fields, anchor)
        query = f'{{__name__=~"{name_regex}"}}'

    api_result = client.instant_query(query, at_time)
    status = api_result.get("status", "error")
    if status != "success":
        raise DemistoException(f"Prometheus API error (status={status}): {api_result}")

    rows = format_result_rows(api_result)
    readable = tableToMarkdown(
        name="Prometheus Instant Query Results",
        t=rows if rows else [{"note": "No results"}],
        headers=["name", "value", "ts", "ts_unix", "labels"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="Prometheus.Metrics",
        outputs_key_field=["name", "ts_unix"],
        outputs=rows,
        raw_response=api_result,
    )


def prometheus_raw_command(client: PrometheusClient, args: Dict[str, Any]) -> CommandResults:
    """
    Run any raw Prometheus query string (instant).
    """
    query = args.get("query")
    if not query:
        raise DemistoException('Argument "query" is required.')
    at_time = args.get("time")
    api_result = client.instant_query(query, at_time)
    status = api_result.get("status", "error")
    if status != "success":
        raise DemistoException(f"Prometheus API error (status={status}): {api_result}")

    rows = format_result_rows(api_result)
    readable = tableToMarkdown(
        name="Prometheus Raw Query Results",
        t=rows if rows else [{"note": "No results"}],
        headers=["name", "value", "ts", "ts_unix", "labels"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="Prometheus.Metrics",
        outputs_key_field=["name", "ts_unix"],
        outputs=rows,
        raw_response=api_result,
    )


def test_module(client: PrometheusClient) -> str:
    """
    Basic connectivity check using a constant vector that should always succeed: vector(1)
    """
    try:
        response = client.instant_query("vector(1)")
        if response.get("status") == "success":
            return "ok"
        return f"Failed: {response}"
    except Exception as exception:
        return f"Failed: {exception}"


def main() -> None:
    params = demisto.params()

    base_url = params.get("url")
    if not base_url:
        return_error('Parameter "url" is required.')

    credentials = params.get("credentials") or {}
    username = credentials.get("identifier")
    password = credentials.get("password")
    auth_tuple: Optional[tuple[str, str]] = (username, password) if (username and password) else None

    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    timeout = arg_to_number(params.get("timeout", 30)) or 30
    default_fields = params.get("default_fields")

    headers: Dict[str, str] = {}
    if username == "Bearer" and password:
        headers["Authorization"] = f"Bearer {password}"

    client = PrometheusClient(
        base_url=base_url.rstrip("/"),
        verify=verify,
        proxy=proxy,
        headers=headers if headers else None,
        auth=None if "Authorization" in headers else auth_tuple,
        timeout=int(timeout),
    )

    try:
        command = demisto.command()
        args = demisto.args()

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "prometheus-query":
            return_results(prometheus_query_command(client, args, default_fields))

        elif command == "prometheus-raw":
            return_results(prometheus_raw_command(client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        return_error(f"Error in Prometheus integration: {str(e)}\n{traceback.format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
