<~XSIAM>

## Overview

NVIDIA OpenShell runs AI coding agents in isolated sandboxes with policy-enforced network egress. Each sandbox is managed by a supervisor that records network, HTTP, SSH, process, policy and security activity as OCSF v1.8.0 events.

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling NVIDIA OpenShell OCSF logs that are ingested via the HTTP Log Collector into Cortex XSIAM.
  * The ingested logs can be queried in XQL Search using the *`nvidia_openshell_raw`* dataset.
* A dashboard summarizing sandbox egress, policy decisions and event volume.

## Supported log categories

| OCSF Class                 | Class UID |
|:---------------------------|:----------|
| Network Activity           | 4001      |
| HTTP Activity              | 4002      |
| SSH Activity               | 4007      |
| Process Activity           | 1007      |
| Detection Finding          | 2004      |
| Device Config State Change | 5019      |
| Application Lifecycle      | 6002      |
| Base Event                 | 0         |

### Supported timestamp formats

Epoch milliseconds (*`1791280847468`*), from the OCSF `time` field.

***

## Data Collection

### Cortex XSIAM side - Custom - HTTP based Collector

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. If you have already configured a **Custom - HTTP based Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "http" and then select **Connect**.
3. Set the following values:

    | Parameter     | Value            |
    |:--------------|:-----------------|
    | `Name`        | NVIDIA OpenShell |
    | `Compression` | uncompressed     |
    | `Log Format`  | json             |
    | `Vendor`      | nvidia           |
    | `Product`     | openshell        |

4. Creating a new HTTP Log Collector will allow you to generate a unique token, please save it since it will be used later.
5. Click the 3 dots sign next to the newly created instance and copy the API URL, it will also be used later.

For more information, see this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-an-HTTP-Log-Collector-to-Receive-Logs).

### NVIDIA OpenShell side

Enable OCSF JSON export on the sandbox supervisors:

```shell
openshell settings set --global --key ocsf_json_enabled --value true
```

Each supervisor then writes OCSF JSONL to `/var/log/openshell-ocsf.YYYY-MM-DD.log` in its own filesystem. The location depends on the compute driver:

| Compute driver  | Supervisor log location                                   |
|:----------------|:----------------------------------------------------------|
| Kubernetes      | `/var/log` in the supervisor pod's `supervisor` container |
| Docker / Podman | `/var/log` in the supervisor container                    |
| VM              | `/var/log` on the host running the supervisor             |

Forward these files to the HTTP Log Collector with a log shipper such as Fluent Bit, using the API URL and token from the Cortex XSIAM side. Configure the shipper to follow daily file rotation.

For details, refer to the [OpenShell Accessing Logs](https://docs.nvidia.com/openshell/dev/observability/accessing-logs) and [OCSF JSON Export](https://docs.nvidia.com/openshell/dev/observability/ocsf-json-export) documentation.

#### Remarks

* Supervisor logs on Kubernetes and Docker are stored on ephemeral volumes and are removed with the sandbox. Run the shipper alongside the supervisor so events are forwarded before teardown.
* Sandbox attribution relies on the OCSF `container` object. Keep the export at OCSF v1.8.0; downgrading to an earlier version removes it.

</~XSIAM>
