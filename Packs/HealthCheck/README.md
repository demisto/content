# System Diagnostics and Health Check (Version 3.5.0)

The **System Diagnostics and Health Check** pack automatically reviews your platform configuration, server operations, and content health to detect issues and enforce best practices across Palo Alto Networks Cortex environments.

Starting with **Version 3.5.0**, the pack introduces comprehensive support for **Cortex XSIAM**, alongside unified and dedicated support for **Cortex XSOAR v8** and **Cortex XSOAR v6**.

---

## What's New in Version 3.5.0

* **Cortex XSIAM Support**: End-to-end health evaluation for XSIAM environments.
* **Dedicated Platform Playbooks**:
  * **Cortex XSIAM**: `HealthCheck-xsiam` — Tailored for XSIAM architectures, custom XQL query histories, and dashboard telemetry collection.
  * **Cortex XSOAR v8**: `HealthCheck-x8` — Optimized for cloud-native XSOAR 8 multi-tenant and single-tenant environments.
  * **Cortex XSOAR v6**: `HealthCheck` — Comprehensive diagnostics for on-premises and hosted XSOAR 6 deployments.
* **XSIAM Dashboards Telemetry**:
  * **Agent and Asset Dashboard**: Evaluates endpoint policy distribution, default policy saturation, scan states, auto-upgrade configurations, and disabled EDR protections.
  * **Ingestion / Integration Dashboard**: Monitors identity ingestion (CIE), reporting freshness, playbook task failure rates, and authentication, network, and SaaS audit data feeds.
  * **Issues / Cases Dashboard**: Detects correlation engine imbalances, noisy detection categories, and unprevented security issues.

---

## Dedicated Playbooks

| Platform | Playbook | Description |
| :--- | :--- | :--- |
| **Cortex XSIAM** | `HealthCheck-xsiam` | Collects XSIAM dashboard metrics via XQL, runs threshold diagnostics, and populates actionable items. |
| **Cortex XSOAR v8** | `HealthCheck-x8` | Runs server and content diagnostics against XSOAR 8 cloud endpoints. |
| **Cortex XSOAR v6** | `HealthCheck` | Runs comprehensive system, worker, database, and content health diagnostics on XSOAR 6. |
| **All Platforms** | `Health_Check_-_Collect_Log_Bundle` | Gathers diagnostic log bundles and server statistics for analysis. |
| **All Platforms** | `Health_Check_-_Log_Analysis_Read_All_files` | Automated inspection of collected diagnostic log files. |

---

## Prerequisites

### Cortex XSIAM & Cortex XSOAR v8

1. Ensure the executing role has sufficient permissions to query XQL search history and access dashboard metrics.
2. Configure **Core REST API** integration instance if tenant-level API interaction is required.

### Cortex XSOAR v6

#### Single-Server Deployment

1. Configure a **Core REST API** integration instance with an **Admin** user.

#### Multi-Tenant Deployment

1. Create an API Key on the **Main Tenant**.
2. Create a **Core REST API** integration instance on the Main Tenant using this API Key:
   * Set the **URL** parameter to `https://127.0.0.1` (do not include tenant name in URL).
3. Propagate the **Core REST API** instance to all required tenants using propagation labels.

---

## How to Run

1. Create a new incident manually in your Cortex environment.
2. Select the incident type **System Diagnostics and Health Check**.
3. Launch the dedicated playbook corresponding to your platform (`HealthCheck-xsiam`, `HealthCheck-x8`, or `HealthCheck`).
4. Once completed, inspect the incident layout tabs for summary charts, diagnostic findings, and actionable recommendations.
