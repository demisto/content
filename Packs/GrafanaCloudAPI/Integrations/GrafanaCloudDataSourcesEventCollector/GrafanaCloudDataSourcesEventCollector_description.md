## Grafana Cloud Data Sources Event Collector

This integration collects the **data source inventory** from a Grafana instance and ingests it into
the Cortex Platform (dataset: `grafana_datasources_raw`).

A Grafana data source is a configured connection to a backend system, holding its URL, its access
mode and, where basic authentication is used, a stored credential. It is therefore both a
credential store and a path out of the estate. The inventory answers what this Grafana can reach
and how it authenticates.

Credential values are never collected. Grafana holds them in `secureJsonData`, which the list
endpoint omits entirely. The basic authentication username is collected, because it identifies the
account in use without exposing its secret.

## Prerequisites

1. In Grafana, go to **Administration > Users and access > Service accounts** and add a service
   account with the **Admin** role in the organisation you want to collect.
2. Add a service account token to it and copy the `glsa_` value.
3. Note your Grafana instance URL, the `https://your-stack.grafana.net` form.

> Grafana replaced standalone API keys with service account tokens, so a legacy API key will not
> work on a current instance or on Grafana Cloud.

## Configuration

- **Grafana instance URL**: your instance base URL.
- **Service account token**: paste the token created above into the password field.
- **Events Fetch Interval**: 60 minutes by default. This is current configuration rather than an
  event stream, so it changes rarely.

The token value is stored encrypted by the platform and is never written to logs.
