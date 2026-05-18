Query Prometheus via its HTTP API (/api/v1/query). Supports a pipe-separated metric list (e.g., "co2|solar|load") which is converted to a metric-name regex on __name__. Returns a tidy table plus machine-readable outputs under Prometheus.Metrics.

This integration was integrated and tested with version 2.55 of Prometheus.

## Configure Prometheus in Cortex

| __Parameter__ | __Description__ | __Required__ |
| --- | --- | --- |
| Prometheus URL |  | True |
| Username / Token label (set to "Bearer" to send a Bearer token) | If you set the username to "Bearer", the password will be used as a Bearer token in the Authorization header. | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Request timeout (seconds) |  | False |
| Default fields (pipe-separated) | Optional default metric list, e.g. co2\|solar\|load\|battery\|temperature\|ambient_temperature\|ambient_humidity\|humidity\|NH3\|oxidising\|reducing\|PM10\|pressure\|proximity | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### prometheus-query

***

Query Prometheus instant vectors by metric name using a pipe-separated "fields" list. Builds {__name__=~"..."} (anchored by default) and calls /api/v1/query.

#### Base Command

`prometheus-query`

#### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| fields | Pipe-separated metric names (e.g., "co2\|solar\|load"). If omitted, falls back to instance "default_fields". | Optional |
| anchor | Anchor metric-name regex with ^ and $ to avoid partial matches (default: true).. Possible values are: true, false. | Optional |
| time | Query evaluation time (RFC3339 timestamp or unix seconds). Optional. | Optional |
| query | Raw Prometheus query string to use instead of building from fields. Example: {__name__=~"(co2\|solar)"} or rate(http_requests_total[5m]). | Optional |

#### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Prometheus.Metrics.name | String | Metric name \(__name__\). |
| Prometheus.Metrics.value | Unknown | Metric value \(float if numeric, otherwise string\). |
| Prometheus.Metrics.ts | Date | Sample timestamp \(ISO8601, UTC\). |
| Prometheus.Metrics.ts_unix | Number | Sample timestamp \(unix seconds\). |
| Prometheus.Metrics.labels | Unknown | Metric labels \(excluding __name__\). |

#### Command example

```!prometheus-query fields="go_info|node_hwmon_temp_celsius"```

### prometheus-raw

***

Run any raw Prometheus instant query string against /api/v1/query.

#### Base Command

`prometheus-raw`

#### Input

| __Argument Name__ | __Description__ | __Required__ |
| --- | --- | --- |
| query | Prometheus query string (required). | Required |
| time | Query evaluation time (RFC3339 timestamp or unix seconds). Optional. | Optional |

#### Context Output

| __Path__ | __Type__ | __Description__ |
| --- | --- | --- |
| Prometheus.Metrics.name | String | Metric name \(__name__\). |
| Prometheus.Metrics.value | Unknown | Metric value \(float if numeric, otherwise string\). |
| Prometheus.Metrics.ts | Date | Sample timestamp \(ISO8601, UTC\). |
| Prometheus.Metrics.ts_unix | Number | Sample timestamp \(unix seconds\). |
| Prometheus.Metrics.labels | Unknown | Metric labels \(excluding __name__\). |

#### Command example

```!prometheus-raw query="{__name__=~'^(go_info|node_hwmon_temp_celsius)$'}"```
