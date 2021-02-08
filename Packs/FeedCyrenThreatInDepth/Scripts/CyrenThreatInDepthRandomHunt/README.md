This script will take a random Cyren Threat InDepth feed indicator and its relationships
and create a threat hunting incident for you.

The main query parameters for the resulting, internal indicator query are:

* Seen for the first time by the feed source within the last 7 days.
* No investigation on it yet.
* Must have relationships to other indicators.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | incidents, ioc, cyren, hunt |
| XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_type | *Optional*: One of `ip_reputation`, `malware_files`, `malware_urls`, `phishing_urls`, will determine the Cyren Threat InDepth feed the indicator is taken from (if not provided a random indicator type is chosen) |
| incident_type | *Optional*: If not provided, an incident of type "Hunt" is created |

## Outputs
---

There are no outputs for this script.

## Human Readable Output
---

Successfully created incident Cyren Threat InDepth Threat Hunt.
Click here to investigate: 1234.
