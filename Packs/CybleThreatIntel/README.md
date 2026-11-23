# Cyble Threat Intelligence – Cortex Integration

This integration enables Cortex to ingest and query Indicators of
Compromise (IOCs) from the **Cyble Vision API**.
It supports two capabilities:

1. **IOC Lookup (Interactive command for analysts)**
2. **IOC Fetching (Fetch Indicators)**

---

## What does this pack do?

The Cyble Vision platform provides enriched, high-fidelity threat
intelligence including malware associations, threat actor links,
behaviour tags, risk scoring, and more.
This integration allows Cortex to:

* Pull fresh IOCs at scheduled intervals, optionally filtered by IOC type, confidence, risk score, industry, country and region
* Score and store indicators in the Cortex indicator store
* Support analyst lookups for a single IOC via the command line or
  playbooks

---

## Configuration

To obtain the Base URL and Access Token, contact your Cyble Account Manager.

### Connection

| Parameter                              | Description                                                   | Example                              |
|----------------------------------------|---------------------------------------------------------------|--------------------------------------|
| **Base URL**                           | Cyble Vision API endpoint                                     | `https://api.cyble.ai/engine/api/v4` |
| **Access Token**                       | Cyble Vision API Bearer token                                 | *(stored securely in Cortex)*        |
| **Trust any certificate (not secure)** | Skip TLS certificate validation                               | Unchecked                            |
| **Use system proxy settings**          | Route requests through the Cortex system proxy                | Unchecked                            |

### Fetch

| Parameter                        | Description                                                                                                                        | Default            |
|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| **Fetch indicators**             | Enables the indicator feed                                                                                                         | Checked            |
| **Feed Fetch Interval**          | How often Cortex runs a fetch                                                                                                      | 1440 minutes (24h) |
| **Max indicators per fetch run** | The most indicators submitted in one fetch run. Non-TIM Cortex licenses ingest at most 100 per fetch; leave at 100 unless you have a TIM license that allows more. | `100`              |

The first fetch goes back **1 hour**. Every later fetch continues from where the previous one stopped, so no IOCs are missed between runs.

### Optional IOC Filters

All filters are optional and combined with AND. Leave a filter empty to fetch everything for that field. Multi-select filters match any of the selected values. Filters apply to fetching only; the ***cyble-vision-ioc-lookup*** command ignores them.

| Parameter              | Description                                                                                                                     | Example                 |
|------------------------|---------------------------------------------------------------------------------------------------------------------------------|-------------------------|
| **IOC Types**          | Fetch only these IOC types: Domain, Email, FileHash-MD5, FileHash-SHA1, FileHash-SHA256, IPv4, IPv6, URL, Wallet-Address        | `Domain`, `IPv4`        |
| **Confidence Rating**  | Fetch only IOCs with these confidence ratings (High, Medium, Low)                                                               | `High`                  |
| **Minimum Risk Score** | Lowest risk score to fetch (0–100)                                                                                              | `70`                    |
| **Maximum Risk Score** | Highest risk score to fetch (0–100). Must not be lower than the minimum.                                                        | `100`                   |
| **Target Industries**  | Fetch only IOCs targeting these industries                                                                                      | `BFSI`                  |
| **Target Countries**   | Fetch only IOCs targeting these countries                                                                                       | `India (IN)`            |
| **Target Regions**     | Fetch only IOCs targeting these regions                                                                                         | `Asia & Pacific (APAC)` |

Most IOCs have no target industry, country or region. Setting any of those three filters therefore returns far fewer IOCs.

### Standard Cortex Feed Settings

The setup page also shows settings that Cortex adds to every feed integration. The Cyble risk score and verdict are always stored in the **Cyble Risk Score** and **Cyble Verdict** indicator fields, whatever these settings are.

| Parameter                                      | What it does with this integration                                                                                                   | Recommendation                                |
|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| **Source Reliability**                         | Required by Cortex. Applied by Cortex to every fetched indicator and used when indicators from several sources disagree.              | Keep the default, `A - Completely reliable`.  |
| **Indicator Reputation**                       | Applied by Cortex to every fetched indicator, overriding any other reputation.                                                         | Leave empty (`None`).                         |
| **Indicator Expiration Method**                | Applied by Cortex: when fetched indicators expire.                                                                                     | Keep the default, or set it to your policy.   |
| **Bypass exclusion list**                      | Applied by Cortex: when checked, indicators on the Cortex exclusion list are still ingested.                                           | Leave unchecked.                              |
| **Tags**                                       | Not used by this integration. Fetched indicators do not get these tags.                                                                | Leave empty.                                  |
| **Traffic Light Protocol Color**               | Not used by this integration. Fetched indicators do not get this TLP color.                                                            | Leave empty.                                  |
| **Do not use by default**                      | When checked, commands run without `using=` (such as automatic enrichment) skip this instance. Fetching is not affected.               | Leave unchecked.                              |

### IOC Type Mapping

| Cyble IOC type                                | Cortex indicator type      |
|-----------------------------------------------|----------------------------|
| Domain                                        | Domain                     |
| Email                                         | Email                      |
| FileHash-MD5, FileHash-SHA1, FileHash-SHA256  | File                       |
| IPv4                                          | IP                         |
| IPv6                                          | IPv6                       |
| URL                                           | URL                        |
| Wallet-Address                                | Cryptocurrency Address     |

*Cryptocurrency Address* is provided by the **Cryptocurrency** pack. Install it to ingest Wallet-Address IOCs.

### Fetch Behavior

* The integration fetches indicators **in 15-minute chunks** until the full range is covered.
* Each page of IOCs is inserted immediately using
  `demisto.createIndicators`.
* Fetch uses the built-in HTTP client retry mechanism for transient API errors.
* `last_run` is updated after every page, so an interrupted fetch resumes where it stopped.
* A fetch run stops when it reaches **Max indicators per fetch run**; the next run continues from the same point.

---

## Commands

## 📌 1. cyble-vision-ioc-lookup

Lookup a single IOC using the Cyble Vision API.

### **Command**

```text
!cyble-vision-ioc-lookup ioc=<IOC_VALUE>
```

### **Arguments**

| Name    | Required | Description                           |
| ------- | -------- | ------------------------------------- |
| **ioc** | Yes      | IOC string (IP / Domain / URL / Hash) |

### **Outputs**

Prefix: `CybleIntel.IOCLookup`

| Field                 | Description               |
| --------------------- | ------------------------- |
| IOC                   | IOC value                 |
| IOC Type              | Type (IP / Domain / URL / Hash) |
| First Seen            | UTC timestamp             |
| Last Seen             | UTC timestamp             |
| Risk Score            | 0–100                     |
| Sources               | Reporting sources         |
| Behaviour Tags        | Tags assigned by Cyble    |
| Confidence Rating     | Low / Medium / High       |
| Target Countries      | Target geography          |
| Target Regions        | Regions affected          |
| Target Industries     | Target verticals          |
| Related Malware       | Linked malware families   |
| Related Threat Actors | Associated threat actors  |

### **Example**

```text
!cyble-vision-ioc-lookup ioc=1.1.1.1

```

---

## 📌 2. fetch-indicators

Fetch IOCs from Cyble Vision and insert them into the Cortex indicator store.

### **Execution**

This command is **not run manually**.
It is used by the Cortex engine when *Fetches Indicators* is enabled.

### Behavior

* Builds indicators with these fields:

  | Indicator field            | Cyble value                                                  |
  |----------------------------|--------------------------------------------------------------|
  | `confidence`               | Confidence rating (High / Medium / Low)                      |
  | `cybleverdict`             | Verdict calculated from risk score and confidence rating     |
  | `cybleriskscore`           | Risk score (0–100)                                           |
  | `cyblefirstseen`           | First seen                                                   |
  | `cyblelastseen`            | Last seen                                                    |
  | `cyblebehaviourtags`       | Behaviour tags                                               |
  | `cyblesources`             | Sources                                                      |
  | `cybletargetcountries`     | Target countries (country codes)                             |
  | `cybletargetregions`       | Target regions                                               |
  | `cybletargetindustries`    | Target industries                                            |
  | `cyblerelatedmalware`      | Related malware                                              |
  | `cyblerelatedthreatactors` | Related threat actors                                        |

* The full Cyble record is kept as the indicator's raw JSON.

## Deprecated Commands

***cyble-vision-fetch-taxii*** and ***cyble-vision-get-collection-names*** are deprecated and only return a deprecation message.

## Known Limitations

* The first fetch goes back 1 hour; older IOCs are not backfilled.
* Some IOCs labelled Wallet-Address by Cyble are not cryptocurrency addresses (for example, file hashes). They are ingested as Cryptocurrency Address indicators as labelled.

---

## Support

For issues, contact **[support@cyble.com](mailto:support@cyble.com)**
or your assigned Cyble Technical Advisor.
