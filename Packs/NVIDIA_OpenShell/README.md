# NVIDIA OpenShell

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) runs AI agents in sandboxes and enforces a network and credential policy for each agent. Each sandbox is managed by a supervisor that records network, HTTP, SSH, process, policy and security activity as OCSF v1.8.0 events.

This pack brings OpenShell into Cortex: it normalizes OpenShell OCSF telemetry into the Cortex Data Model, and lets a playbook or an analyst contain an agent through the OpenShell gateway.

## This pack includes

| Content | Name | Purpose |
| --- | --- | --- |
| Parsing rule | NVIDIA OpenShell | Sets the event time from the OCSF `time` field (Cortex XSIAM) |
| Modeling rule | NVIDIA OpenShell | Maps OpenShell OCSF events to the Cortex Data Model (Cortex XSIAM) |
| Dashboard | NVIDIA OpenShell Agent Activity | Policy denials, events by OCSF class, top denied destinations, busiest sandboxes and denial reasons (Cortex XSIAM) |
| Integration | NVIDIA OpenShell | Sandbox lifecycle, network policy, logs and credential providers |
| Playbook | NVIDIA OpenShell - Contain AI Agent Sandbox | Gets the sandbox state and recent logs, waits for analyst approval, stops the sandbox and verifies that it stopped |

<~XSIAM>

## Data normalization

The ingested logs can be queried in XQL Search using the *`nvidia_openshell_raw`* dataset.

### Supported log categories

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

1. Enable OCSF JSON output on the sandbox supervisors (OpenShell 0.1.3 or later). The setting takes effect within about 10 seconds, without a restart:

    ```shell
    openshell settings set --global --key ocsf_json_enabled --value true
    ```

2. Send each OCSF event to the HTTP Log Collector as a plain JSON object, using the API URL and token from the Cortex XSIAM side. Use one of these sources:

    * **Supervisor container logs (recommended).** Each supervisor writes one line per event to its container stderr, in the format `<UTC timestamp> OCSF-JSON <compact OCSF JSON>`. Read it through the platform log interface or a container log collector (`docker logs`, `podman logs`, or `kubectl logs <supervisor-pod> -c supervisor`). As NVIDIA recommends, configure the log collector to select only lines containing `OCSF-JSON` and to decode everything after the following space as JSON. Forward that JSON object, not the whole log line. This also skips the shorthand copy of each event and the diagnostic lines.

    * **Supervisor JSONL files.** Each supervisor also writes one OCSF JSON object per line to `/var/log/openshell-ocsf.YYYY-MM-DD.jsonl` (`.log` before OpenShell 0.1.3) in its own filesystem: in the supervisor container on Kubernetes, Docker and Podman, or on the host running the supervisor for the VM driver. On Kubernetes (emptyDir) and Docker / Podman (tmpfs) these files are on ephemeral storage.

For details, refer to the [OpenShell OCSF JSON Export](https://docs.nvidia.com/openshell/latest/observability/ocsf-json-export) documentation.

#### Remarks

* The HTTP Log Collector rejects records that are not JSON. Send one OCSF JSON object per record. Records without an OCSF `class_uid` are stored but not modeled.
* Console output is best-effort: it uses a bounded queue of 1,024 lines, and new lines are dropped when it is full. Collect continuously.
* Sandbox attribution uses `device.container` on supervisor records and `unmapped.sandbox_id` / `unmapped.sandbox_name` on gateway records (OpenShell 0.1.8 and later), and the top-level `container` object on earlier versions.

</~XSIAM>

## Response

| Action | Command |
| --- | --- |
| Stop, start, suspend or resume an agent sandbox | `openshell-sandbox-stop`, `openshell-sandbox-start`, `openshell-sandbox-suspend`, `openshell-sandbox-resume` |
| Block an agent from reaching a host, while the agent keeps running | `openshell-egress-block-host` |
| Remove a network rule, endpoint or binary from the sandbox policy | `openshell-policy-rule-remove`, `openshell-policy-endpoint-remove`, `openshell-policy-binary-remove` |
| Stop an agent from receiving credentials | `openshell-provider-detach` |
| Investigate an agent | `openshell-sandbox-logs`, `openshell-policy-get`, `openshell-policy-history` |

### Requirements

- OpenShell gateway 0.1.6 or later.
- An engine that can reach the gateway. The gateway is usually private, so a cloud-hosted integration cannot reach it.
- Gateway mTLS credentials (`ca.crt`, `tls.crt`, `tls.key`) or an OIDC bearer token.

### Limitations

- The integration does not run commands inside a sandbox.
- `openshell-sandbox-suspend` requires a sandbox driver that supports suspend.
