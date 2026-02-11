<~XSIAM>

## Overview

DOCA Argus is a DOCA service running on NVIDIA® BlueField® networking platforms, designed to immediately detect and enable response to attacks, minimizing their potential impact and risk.

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling NVIDIA DOCA Argus logs that are ingested via the HTTP Event Collector into Cortex XSIAM.
  * The ingested logs can be queried in XQL Search using the *`nvidia_doca_argus`* dataset.

## Supported log categories

| Category                    | Category Display Name                 |
|:----------------------------|:--------------------------------------|
| [Event](https://docs.nvidia.com/doca/sdk/doca-argus-service-guide/index.html#src-4412999970_safe-id-aWQtLkRPQ0FBcmd1c1NlcnZpY2VHdWlkZXYzLjIuMExDLVN1cHBvcnRlZEFsZXJ0cyxFdmVudHNhbmRTeXN0ZW1BY3Rpdml0eU1lc3NhZ2Vz)  | EVENT                           |
| [Alert](https://docs.nvidia.com/doca/sdk/doca-argus-service-guide/index.html#src-4412999970_safe-id-aWQtLkRPQ0FBcmd1c1NlcnZpY2VHdWlkZXYzLjIuMExDLVN1cHBvcnRlZEFsZXJ0cyxFdmVudHNhbmRTeXN0ZW1BY3Rpdml0eU1lc3NhZ2Vz)  | ALERT                            |
| [System Activity](https://docs.nvidia.com/doca/sdk/doca-argus-service-guide/index.html#src-4412999970_id-.DOCAArgusServiceGuidev3.2.0LC-SystemEvents)  | SYSTEM_ACTIVITY                           |

### Supported timestamp formats

iso_8601 (*`2025-11-18T10:18:50.625005951+00:00`*)
***

## Data Collection

### Cortex XSIAM side - Custom - HTTP based Collector

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. If you have already configured a **Custom - HTTP based Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "http" and then select **Connect**.
3. Set the following values:

    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
    | `Name`        | nvidia doca_argus Logs            |
    | `Compression` | uncompressed     |
    | `Log Format`  | json     |
    | `Vendor`      | nvidia                     |
    | `Product`     | doca_argus                    |

4. Creating a new HTTP Log Collector will allow you to generate a unique token, please save it since it will be used later.
5. Click the 3 dots sign next to the newly created instance and copy the API URL, it will also be used later.

For more information, see this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-an-HTTP-Log-Collector-to-Receive-Logs).

### Nvidia BlueField service deployment

* For DPU container deployment, see [DOCA Container Deployment Guide](https://docs.nvidia.com/doca/sdk/DOCA+Container+Deployment+Guide).
* For Argus-specific deployment, refer to the [service container's page](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/doca/containers/doca_argus).
* For offline deployment (no Internet access), see the Offline Deployment section in [DOCA Container Deployment Guide](https://docs.nvidia.com/doca/sdk/DOCA+Container+Deployment+Guide).

For detailed Information and Prerequisites, please refer to [**DOCA Argus Service Guide**](https://docs.nvidia.com/doca/sdk/doca-argus-service-guide/index.html#).

### Fluent Bit side

Fluent Bit is a lightweight, high-performance log processor and forwarder used to collect, parse, enrich, and route logs from systems, containers, and services to external destinations.
In this integration, Fluent Bit acts as the log shipping layer between NVIDIA DOCA Argus and Cortex XSIAM.

#### HTTP out to XSIAM — fill in your [OUTPUT] details

Edit Fluent Bit conf file **/fluent-bit/etc/fluent-bit.conf** and input the following:

  | Parameter    | Value                                                                                                                                           |
  |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
  | `Name`        | http            |
  | `Match` | argus     |
  | `Host`  | api-**<tenant_name>**.xdr.**<tenant_region>**.paloaltonetworks.com     |
  | `Port`      | 443                     |
  | `URI`     | /logs/v1/event                    |
  | `Format`     | json                    |
  | `tls`     | On                    |
  | `tls.verify`     | On                    |
  | `Header`     | Authorization Bearer **<your_http_collector_api_token>**                     |
  | `Retry_Limit`     | False                    |

Refer to the [Fluent Bit manual](https://docs.fluentbit.io/manual/data-pipeline/outputs/output_formats) for details on additional output plugins and configurations.

</~XSIAM>
