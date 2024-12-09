## Overview
---

Use the Google Chronicle Backstory Streaming API integration to ingest detections created by both user-created rules and Chronicle Rules as XSOAR incidents.
This integration was integrated and tested with version 2 of Google Chronicle Backstory Streaming API (Detection Engine API).

#### Troubleshoot

**Note:** The streaming mechanism will do up to 7 internal retries with a gap of 2, 4, 8, 16, 32, 64, and 128 seconds (exponentially) between the retries.

##### Problem #1
Duplication of rule detection incidents when fetched from Chronicle.

##### Solution #1

- To avoid duplication of incidents with duplicate detection ids and to drop them, XSOAR provides inbuilt features of Pre-process rules.
- End users must configure this setting in the XSOAR platform independently, as it is not included in the integration pack.
- Pre-processing rules enable users to perform certain actions on incidents as they are ingested into XSOAR.
- Using these rules, users can filter incoming incidents and take specific actions, such as dropping all incidents or dropping and updating them based on certain conditions.
- Please refer for information on [Pre-Process rules](https://xsoar.pan.dev/docs/incidents/incident-pre-processing#:~:text=Creating%20Rules&text=Navigate%20to%20Settings%20%3E%20Integrations%20%3E%20Pre,viewing%20the%20list%20of%20rules).

## Configure Chronicle Streaming API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| User's Service Account JSON | Your Customer Experience Engineer (CEE) will provide you with a [Google Developer Service Account Credential](https://developers.google.com/identity/protocols/OAuth2#serviceaccount) to enable the Google API client to communicate with the Backstory API. | True |
| Region | Select the region based on the location of the chronicle backstory instance. If the region is not listed in the dropdown, choose the "Other" option and specify the region in the "Other Region" text field. | False |
| Other Region | Specify the region based on the location of the chronicle backstory instance. Only applicable if the "Other" option is selected in the Region dropdown. | False |
| Incident type |  | False |
| First fetch time | The date or relative timestamp from where to start fetching detections. Default will be the current time.<br/><br/>Note: The API is designed to retrieve data for the past 7 days only. Requests for data beyond that timeframe will result in errors.<br/><br/>Supported formats: N minutes, N hours, N days, N weeks, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 10 minutes, 5 hours, 6 days, 1 week, 2024-12-31, 01 Mar 2024, 01 Feb 2024 04:45:33, 2024-04-17T14:05:44Z | False |
| Chronicle Alert Type | Select Chronicle Alert types to be considered for Fetch Incidents. Available options are Curated Rule Detection Alerts and Rule Detection Alerts \(If not selected, fetches all detections\). | False |
| Severity of Detection | Select the severity of detections to be considered for Fetch Incidents. Available options are 'High', 'Medium', 'Low', 'Informational' and 'Unspecified' \(If not selected, fetches all detections\). | False |
| Rule Names for Detection Ingestion | Only detections with the given rule names will be allowed for ingestion. | False |
| If selected, detections with the above rule names will be denied for ingestion. |  | False |
| Rule IDs for Detection Ingestion | Only the detections with the given rule IDs will be allowed for ingestion. | False |
| If selected, detections with above rule IDs will be denied for ingestion. |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Generic Notes

- This integration would only ingest the **detections** created by both **user-created rules** and **Chronicle Rules**.
- Also, It only ingests the detections created by rules whose **alerting status** was **enabled** at the time of detection.
- Enable alerting using the **Chronicle UI** by setting the **Alerting** option to **enabled**.
  - For **user-created rules**, use the Rules Dashboard to enable each rule's alerting status.
  - For **Chronicle Rules**, enable alerting status of the Rule Set to get detections created by corresponding rules.
- You are limited to a maximum of 10 simultaneous streaming integration instances for the particular Service Account Credential (your instance will receive a **429 error** if you attempt to create more).
- For more, please check out the [Google Chronicle reference doc](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#streamdetectionalerts).