## Cloudflare Security Insights Event Collector

This integration collects **Security Center insights** (findings) from the Cloudflare API
(`GET /accounts/{account_id}/security-center/insights`) and ingests them into Cortex XSIAM
(dataset: `cloudflare_security_insights_raw`). Insights are current findings (an inventory), so
each run sends the full snapshot.

### Prerequisites

1. Create a Cloudflare **API Token** (My Profile > API Tokens > Create Token).
2. Grant the token the **Account > Security Center Insights > Read** permission
   (permission group "Account Security Insights").
3. Note the **Account ID(s)** you want to collect from.
