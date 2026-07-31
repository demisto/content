## Grafana Cloud Service Accounts Event Collector

This integration collects the **service account and token inventory** from a Grafana instance and
ingests it into the Cortex Platform (dataset: `grafana_service_accounts_raw`).

Service accounts are Grafana's machine-credential surface. They replaced standalone API keys, they
carry a role that can reach Admin, and each holds one or more long-lived tokens. The inventory
answers which non-human identities can reach this Grafana, what they are permitted to do, and
whether their tokens ever expire.

Token secrets are not returned by the Grafana API and are never collected. Only a token's name,
lifecycle dates and revocation state are read.

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
