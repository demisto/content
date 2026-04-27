## Cyberint Premium Feed

Use the **Check Point EM Premium Feed** integration to ingest high-fidelity Indicators-of-Compromise from the Cyberint Infinity External Risk Management (Argos) Premium IOC APIs into Cortex XSOAR Threat Intel Management, and to enrich a single IOC on demand from the war room or a playbook task.

### Get your Cyberint API access token

1. Sign in to your Cyberint Argos tenant at `https://<your-company>.cyberint.io`.
2. Open **Settings → API Access** (or contact your Cyberint account manager) and generate a long-lived **API access token** with read access to the Premium IOC feed and enrichment APIs.
3. Copy the token — you will paste it into the integration instance below.

### Configure an integration instance

1. In Cortex XSOAR, navigate to **Settings → Integrations → Servers & Services**, search for **Check Point EM Premium Feed** and click **Add instance**.
2. Fill in the **Connect** section:
   - **Cyberint API URL** — your Argos base URL, e.g. `https://your-company.cyberint.io`.
   - **Company Name** — the customer/tenant name registered with Cyberint (sent as a telemetry header).
   - **API Key** — leave blank. Paste the token from step 3 above into the **password** field.
   - **Trust any certificate** / **Use system proxy settings** — toggle as needed for your network.
3. Fill in the **Collect** section to scope the feed:
   - **Indicator Type / Activity / Confidence / Severity / Malicious** — server-side filters; leave at defaults to ingest everything.
   - **First Fetch Time** — how far back to look on the very first run (default `3 days`). Subsequent runs only pull indicators added since the last successful fetch.
   - **Feed Fetch Interval** — how often the integration polls (default `240` minutes / 4 hours).
4. Click **Test** to verify connectivity and authentication, then **Save & exit**.

### Troubleshooting

- **Authorization Error: invalid `API Token`** — the token is missing, malformed, expired, or lacks Premium IOC scope. Regenerate it in the Cyberint console and re-save the instance.
- **Repeated 429 / 503 responses** — the integration retries up to 3 times with exponential backoff (5s → 10s → 20s). Sustained throttling means your tenant is at the Premium API rate limit; reduce **Feed Fetch Interval** frequency or contact Cyberint support.
- **Fetch appears to take multiple runs to catch up** — by design. The integration caps each execution at ~20 minutes / 100 000 indicators and persists a cursor. After the catch-up window completes, every subsequent run is incremental.

For more details, see the [Cortex XSOAR integration description guidelines](https://xsoar.pan.dev/docs/documentation/integration-description#general).
