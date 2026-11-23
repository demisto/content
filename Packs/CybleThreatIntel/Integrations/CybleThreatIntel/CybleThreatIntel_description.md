# Cyble Threat Intel

Cyble Threat Intel is an integration that helps users fetch Cyble’s IOC
Feed service into the Cortex XSOAR environment. Users need to contact
their Cyble Account Manager to obtain the required prerequisites for
accessing the Cyble IOC Feed service.

### Setup

1. **Base URL**: `https://api.cyble.ai/engine/api/v4`, unless your Cyble Account Manager gave you a different one.
2. **Access Token**: your Cyble Vision API token.
3. **Max indicators per fetch run**: leave at `100` unless you have a TIM license that allows more.
4. Optionally, set the IOC filters (**IOC Types**, **Confidence Rating**, **Minimum / Maximum Risk Score**, **Target Industries**, **Target Countries**, **Target Regions**). Leave a filter empty to fetch everything for that field.

The first fetch goes back 1 hour; later fetches continue from where the previous one stopped.

### Standard feed settings

- **Source Reliability**: keep `A - Completely reliable`.
- **Indicator Reputation**: leave empty. A value here overrides the reputation of every fetched indicator.
- **Tags** and **Traffic Light Protocol Color**: not used by this integration; leave empty.
- **Indicator Expiration Method** and **Bypass exclusion list**: keep the defaults unless your policy requires otherwise.

To ingest Wallet-Address IOCs, install the **Cryptocurrency** pack.

For more details, contact your Cyble Account Manager.
