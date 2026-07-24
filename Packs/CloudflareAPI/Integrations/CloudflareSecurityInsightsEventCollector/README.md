# Cloudflare Security Insights Event Collector

Collect Cloudflare Security Center insights (findings) via
`GET /accounts/{account_id}/security-center/insights` and ingest them into the
`cloudflare_security_insights_raw` dataset in Cortex XSIAM.
Insights are current findings (a snapshot), so each run sends the full set.

## Configure Cloudflare Security Insights Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Cloudflare API base URL. | True |
| API Token | A Cloudflare API Token with the "Account Security Insights" read permission. | True |
| Account IDs | A comma-separated list of Cloudflare account IDs. | True |
| Maximum number of insights per fetch | Upper bound of insight records pulled each run. | False |

## Commands

### cloudflare-security-insights-get-events

Manual command to retrieve and preview Cloudflare Security Center insights.
