## Grafana Cloud Organisation Users Event Collector

This integration collects the **organisation user inventory** from a Grafana instance and ingests
it into the Cortex Platform (dataset: `grafana_org_users_raw`).

This is the human identity half of the picture the Service Accounts collector covers for machines.
It answers who can sign in to this Grafana, at what role, whether their identity comes from an
external provider, and when they were last seen. The last-seen timestamp is what makes a dormant
privileged account visible.

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
