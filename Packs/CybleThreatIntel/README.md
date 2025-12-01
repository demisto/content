# Cyble Threat Intelligence – Cortex XSOAR Integration

This integration enables Cortex XSOAR to ingest and query Indicators of Compromise (IOCs) from the **Cyble Vision API**.
It supports two capabilities:

1. **IOC Lookup (Interactive command for analysts)**
2. **IOC Fetching (Fetch Indicators)**

---

## Overview

The Cyble Vision platform provides enriched, high-fidelity threat intelligence including malware associations, threat actor links, behaviour tags, risk scoring, and more.
This integration allows XSOAR to:

* Pull fresh IOCs at scheduled intervals
* Tag, score, and store indicators in the Cortex XSOAR indicator store
* Support analyst lookups for a single IOC via the command line or playbooks

---

## Configuration

### Required Parameters

| Parameter                  | Description                                                        | Example                                  |
| -------------------------- | ------------------------------------------------------------------ | ---------------------------------------- |
| **Base URL**               | Cyble Vision API endpoint                                          | `https://api.cyble.ai/engine/api/v4` |
| **API Key (Access Token)** | Cyble Vision API Bearer token                                      | *(stored securely in XSOAR)*             |
| **First Fetch (hours)**    | Number of hours to fetch backward on first run (1–3 hours allowed) | `2`                                      |
| **Max Fetch**              | Maximum indicators per API page                                    | `100`                                    |

### Fetch Behavior

* Fetch is performed **in 1-hour chunks** until the full range is covered.
* Each page of IOCs is inserted immediately using `demisto.createIndicators`.
* Fetch uses a retry mechanism (up to 5 attempts per page).
* `last_run` is updated after every chunk.
* Supported fetch window: **1–3 hours** (anything outside is automatically corrected).

---

# Commands

## 📌 1. cyble-vision-ioc-lookup

Lookup a single IOC using the Cyble Vision API.

### **Command**

```
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
| IOC Type              | Type (IP/Domain/URL/Hash) |
| First Seen            | UTC timestamp             |
| Last Seen             | UTC timestamp             |
| Risk Score            | 0–100                     |
| Sources               | Reporting sources         |
| Behaviour Tags        | Tags assigned by Cyble    |
| Confidence Rating     | Low/Medium/High           |
| Target Countries      | Target geography          |
| Target Regions        | Regions affected          |
| Target Industries     | Target verticals          |
| Related Malware       | Linked malware families   |
| Related Threat Actors | Associated threat actors  |

### **Example**

```
!cyble-vision-ioc-lookup ioc=45.67.23.9
```

---

## 📌 2. fetch-indicators

Fetch IOCs from Cyble Vision and insert them into XSOAR's indicator store.

### **Execution**

This command is **not run manually**.
It is used by the XSOAR engine when *Fetches Indicators* is enabled.

### Behavior

* Builds indicators with:

  * `cybleverdict`
  * `cybleriskscore`
  * `cyblefirstseen`
  * `cyblelastseen`
  * `cyblebehaviourtags`
  * `cyblesources`
  * `cybletargetcountries`
  * `cybletargetregions`
  * `cybletargetindustries`
  * `cyblerelatedmalware`
  * `cyblerelatedthreatactors`
* Automatically maps each IOC into XSOAR Indicator fields.
* Updates `last_run` after each successful chunk.


## Known Limitations

* Fetching supports **hours only (days not supported)**.
* Maximum initial backfill: **3 hours**.

---

## Support

For issues, contact **[support@cyble.com](mailto:support@cyble.com)**
or your assigned Cyble Technical Advisor.
