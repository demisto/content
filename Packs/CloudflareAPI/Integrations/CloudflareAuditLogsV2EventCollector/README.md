# Cloudflare Audit Logs V2 Event Collector

Collect account audit logs from Cloudflare's version 2 audit API, including dashboard sign-in
events, and ingest them into the Cortex Platform.

This integration was integrated and tested with the Cloudflare API v4 `logs/audit` endpoint.

## Why both audit collectors are needed

Cloudflare exposes two audit APIs that return **different records with different identifiers**.
Only version 2 reports authentication:

| Endpoint | Collector | Sign-in events |
| --- | --- | --- |
| `/accounts/{id}/logs/audit` | Cloudflare Audit Logs V2 Event Collector | Yes, as `LOGIN` |
| `/accounts/{id}/audit_logs` | Cloudflare Audit Logs Event Collector | No |

Over an identical period, version 1 returns records containing no sign-in of any
kind. An account can therefore look fully audited while every dashboard login goes unrecorded.
Neither endpoint is a replacement for the other, so running both is deliberate.

A `LOGIN` record carries the actor's email address, source IP address and outcome, which is what
makes an authentication detection possible.

## Required API token permission

Create a Cloudflare **API Token** with the **Account Settings > Read** permission. In the token
editor (My Profile > API Tokens > your token > Edit), under **Permissions** set the three
dropdowns to:

1. **Account**
2. **Account Settings**
3. **Read**

Scope the token to the account(s) you want to collect from (Account Resources > your account).

> **Important:** use **Account Settings: Read**, *not* **"Access: Audit Logs Read"** or
> **"Access: Users"**. Those are for Cloudflare Access (Zero Trust), not the account audit trail.
> A token holding only those returns `403 Authentication error (code 10000)`.

## Configure Cloudflare Audit Logs V2 Event Collector in the Cortex Platform

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Cloudflare API base URL. | True |
| API Token | A Cloudflare API Token with the **Account Settings &gt; Read** permission. | True |
| Account IDs | A comma-separated list of Cloudflare account IDs. | True |
| First fetch time | The time range to fetch on the first run (e.g. `3 days`). | False |
| Maximum number of events per account per fetch | Ceiling per account per run. Default `5000`. | False |
| Trust any certificate (not secure) | Skip certificate verification. | False |
| Use system proxy settings | Route requests through the configured proxy. | False |

## Commands

### cloudflare-audit-v2-get-events

Retrieve and preview version 2 audit log events. Used for testing and development.

#### Base Command

`cloudflare-audit-v2-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | Comma-separated Cloudflare account IDs. Defaults to the instance-configured IDs. | Optional |
| since | The time range to fetch events from (e.g. `1 day`). | Optional |
| limit | Maximum number of events to return per account. | Optional |
| should_push_events | If `true`, also push the events to the dataset. Default is `false`. | Optional |

#### Context Output

There is no context output for this command. Events are rendered to the War Room and, when
`should_push_events=true`, sent to the `cloudflare_account_audit_v2_raw` dataset.

## Endpoint behaviour worth knowing

- Every request requires both a start and an end bound.
- The endpoint **ignores page numbers**: requesting page 1, 2 or 3 returns the identical records.
  Paging is by an opaque cursor, which this collector follows automatically until it is exhausted.
- Sign-in events have been observed arriving within roughly ninety seconds. Allow for that lag
  when setting the search window on any correlation built over this dataset.

## About GoCortex

Independent tools, projects, and ideas to complement and extend the Palo Alto Networks Cortex
ecosystem.

[gocortex.io](https://gocortex.io)
