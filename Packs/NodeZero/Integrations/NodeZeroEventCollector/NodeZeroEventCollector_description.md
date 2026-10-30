## NodeZero Event Collector

Collects every weakness from completed NodeZero pentests, at all severities, into the Cortex XSIAM dataset `horizon3_nodezero_raw`.

### Obtain an API key

The API key must have **read** access to pentests and weaknesses.

1. Log in to the [Horizon3.ai Portal](https://portal.horizon3ai.com/).
2. Navigate to **Settings** > **My Settings** > **API Keys**.
3. Click **Generate API Key** and copy the key value.
4. Paste the key into the **API Key** parameter when configuring the integration instance.

### How events are collected

- Each fetch collects weaknesses only from completed (done) pentests whose results became fully available since the previous fetch. A pentest that is stopped before it completes is not collected.
- The first fetch goes back as far as the **First fetch time** parameter (7 days by default).
- By default, the integration checks NodeZero for finished pentests every 30 minutes. To change this, set the **Events Fetch Interval** parameter.
- Each weakness becomes one event. The event time is when NodeZero discovered the weakness during the pentest.
- To see the events, run the XQL query `dataset = horizon3_nodezero_raw`.