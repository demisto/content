# Grafana Cloud Data Sources Event Collector

Collect the Grafana data source inventory and ingest it into the Cortex Platform.

## Required permission

Create a Grafana **service account** with the **Admin** role in the organisation being collected,
then add a service account token to it. Grafana replaced standalone API keys with service account
tokens, so a legacy API key will not work on a current instance or on Grafana Cloud.

The narrower permission this collector needs is `datasources:read`, if you prefer a custom role to Admin.

## Configure Grafana Cloud Data Sources Event Collector in the Cortex Platform

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Grafana instance URL | The instance base URL, for example `https://your-stack.grafana.net`. | True |
| Service account token | A Grafana service account token (`glsa_`) with the Admin role. | True |
| Events Fetch Interval | How often the collector runs, in minutes. Default 60. | False |
| Maximum number of records per fetch | Ceiling per run. Default 5000. | False |
| Trust any certificate (not secure) | Skip certificate verification. | False |
| Use system proxy settings | Route requests through the configured proxy. | False |

## Commands

### grafana-datasources-get-events

Retrieve and preview the Grafana data source inventory. Used for testing and development.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of records to return. | Optional |
| should_push_events | If `true`, also push the records to the dataset. Default is `false`. | Optional |

#### Context Output

There is no context output for this command. Records are rendered to the War Room and, when
`should_push_events=true`, sent to the `grafana_datasources_raw` dataset.

## Collection behaviour

This is a snapshot of current state, not an event stream, so the full inventory is re-sent on
every run. Duplicate rows across runs are expected and correct.

The endpoint **ignores pagination**: it accepts page parameters and returns the whole list
regardless. It is therefore requested once per run, because a page loop over it would re-send the
same records indefinitely.

## About GoCortex

Independent tools, projects, and ideas to complement and extend the Palo Alto Networks Cortex
ecosystem.

[gocortex.io](https://gocortex.io)
