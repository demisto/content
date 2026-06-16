# Cisco ETD Pack

## Overview

The Cisco ETD Pack provides integration for Cisco Email Threat Defense (ETD) within Cortex XSIAM.

The pack enables ingestion, visualization, and monitoring of Cisco ETD Message Event Logs for email security analytics and threat visibility.

---

## Included Content

### Integrations

* Cisco ETD Integration

---

## Key Features

* Cisco ETD Message Event Log ingestion
* Email threat classification
* Email traffic trend visualization
* XQL-based analytics

---

## Supported Platform

* Cortex XSIAM

---

## Use Cases

* Email threat monitoring
* SIEM correlation
* Email security analytics
* Threat visibility and reporting

---

## Supported Log Types

The integration ingests the following Cisco ETD log types:

* Message Logs
* Audit Logs
* Connection Logs

---

## Requirements

* Cisco Email Threat Defense access
* Cisco ETD API credentials
* Cortex XSIAM instance

---

## Configuration

### Prerequisites

Before configuring the integration, ensure the following requirements are met:

* Cisco Email Threat Defense (ETD) tenant access
* Cisco ETD API credentials
* Cortex XSIAM tenant with permissions to configure integrations

### Obtain Cisco ETD API Credentials

1. Log in to the Cisco ETD administration portal.
2. Navigate to the API access or application management section.
3. Create or locate an API application.
4. Record the following values:

   * Client ID
   * Client Secret
   * API Key

### Configure the Integration

1. Navigate to **Settings → Configurations → Integrations**.
2. Search for **Cisco ETD Connector**.
3. Click **Add Instance**.
4. Configure the following parameters:

| Parameter                 | Description                                                                   |
| ------------------------- | ----------------------------------------------------------------------------- |
| ETD Base URL              | Cisco ETD API URL (for example: `https://api.ironport.com`)                   |
| Client ID                 | Cisco ETD Client ID                                                           |
| Client Secret             | Cisco ETD Client Secret                                                       |
| API Key                   | Cisco ETD API Key                                                             |
| First Fetch Time          | Initial log collection window (for example: `5 days`, `7 days`, or `30 days`) |
| Fetch Events              | Enable continuous log ingestion into Cortex XSIAM                             |
| Use system proxy settings | Enable if your environment requires a proxy                                   |
| Trust any certificate     | Enable only for testing environments using self-signed certificates           |

> **Note:** Fetch Events must be enabled for continuous log ingestion into Cortex XSIAM.

### Verify Connectivity

1. Click **Test**.
2. Verify that the integration returns:

```text
ok
```

3. Click **Save & Enable**.

### Log Collection

Once enabled, the integration automatically retrieves Cisco ETD logs and ingests them into Cortex XSIAM.

The integration collects the following log types:

* Message Logs
* Audit Logs
* Connection Logs

### Verify Data Ingestion

Successfully ingested events are available in the following dataset:

```text
cisco_etd_raw
```

You can verify ingestion by running:

```xql
dataset = cisco_etd_raw
| limit 10
```

---

## Dashboard Configuration

The Cisco ETD integration does not automatically deploy a Cortex XSIAM dashboard. After installing the integration and ingesting data into the `cisco_etd_raw` dataset, users can create a custom dashboard using the following widgets.

### Create a Dashboard

1. Navigate to **Dashboards** in Cortex XSIAM.
2. Click **Create Dashboard**.
3. Enter a dashboard name (for example, **Cisco ETD Dashboard**).
4. Add the widgets described below.

---

### Widget 1: Total ETD Logs

**Visualization Type:** Pie Chart

**XQL Query:**

```xql
dataset = cisco_etd_raw
| comp count() as log_count by logType
| view graph type = pie xaxis = logType yaxis = log_count
```

**Purpose**

Displays the distribution of ETD log types (Message, Audit, and Connection logs).

---

### Widget 2: Email Classification Summary

**Visualization Type:** Pie Chart

**XQL Query:**

```xql
dataset = cisco_etd_raw
| filter logType = "message"
| alter verdict = json_extract_scalar(message, "$.verdict.verdict")
| alter category = if(verdict in ("phishing", "bec", "scam", "malicious"), "Threat", if(verdict in ("spam", "graymail"), "Unwanted", "Legit"))
| comp count() as category_count by category
| view graph type = pie xaxis = category yaxis = category_count
```

**Purpose**

Provides a high-level classification of email activity into:

* Threat
* Unwanted
* Legit

---

### Widget 3: ETD Log Activity Trend

**Visualization Type:** Line Chart

**XQL Query:**

```xql
dataset = cisco_etd_raw
| comp count() as event_count by logDate, logType
| sort asc logDate
| view graph type = line xaxis = logDate yaxis = event_count series = logType
```

**Purpose**

Displays ETD activity trends over time and allows users to monitor ingestion volume by log type.

---

### Recommended Dashboard Layout

| Row                 | Widget                       |
| ------------------- | ---------------------------- |
| Top Left            | Total ETD Logs               |
| Top Right           | Email Classification Summary |
| Bottom (Full Width) | ETD Log Activity Trend       |

This layout provides a high-level overview of Cisco ETD activity, email classification statistics, and ingestion trends within Cortex XSIAM.

---

## Troubleshooting

### Test Connection Fails

Verify:

* ETD Base URL is correct
* Client ID is valid
* Client Secret is valid
* API Key is valid
* Network connectivity exists between Cortex XSIAM and Cisco ETD

### No Events Ingested

Verify:

* Fetch Events is enabled
* Cisco ETD contains data for the selected time range
* The dataset contains records

Run:

```xql
dataset = cisco_etd_raw
| limit 10
```

### Dashboard Widgets Show No Data

Verify:

* Events are present in the `cisco_etd_raw` dataset
* The dashboard time range contains data
* The XQL queries return results when executed manually in XQL Search

Run:

```xql
dataset = cisco_etd_raw
| limit 10
```

---

## Author

NuSummit

---

## Version

1.0.0
