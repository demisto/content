<~XSIAM>

# NVIDIA OpenShell

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) is an open source runtime security layer for autonomous AI agents. It supervises agent shell sessions inside sandboxes, enforces network, filesystem and process policy, and emits security relevant telemetry in [OCSF](https://schema.ocsf.io/) format.

This pack ingests that telemetry, models it to XDM, and ships detections for sandbox policy evasion and egress abuse.

## What this pack supports

| OCSF class | UID | Covers | Observed |
| --- | --- | --- | --- |
| Network Activity | 4001 | Proxy CONNECT tunnels, egress policy decisions, bypass detection | Yes |
| SSH Activity | 4007 | SSH handshakes, authentication, channel operations | Yes |
| Device Config State Change | 5019 | Policy load and reload, Landlock, TLS setup, settings changes | Yes |
| HTTP Activity | 4002 | HTTP forwarding and layer 7 enforcement decisions | Not yet |
| Process Activity | 1007 | Process launch, exit, timeout | Not yet |
| Detection Finding | 2004 | Nonce replay, proxy bypass, unsafe policy findings | Not yet |
| Application Lifecycle | 6002 | Supervisor start, SSH server ready | Not yet |
| Base Event | 0 | Relay and mediation failures with no network endpoint | Yes |

"Observed" means the class was seen on a live OpenShell 0.1.2 sandbox during
development. Classes marked "Not yet" are mapped from the `openshell-ocsf`
crate's serialized struct definitions rather than from captured events. Their
field names are taken from source, so they are expected to be correct, but
they have not been confirmed against a running system. Treat detections built
on those classes as unverified until you see the events in your own
environment.

OpenShell emits OCSF v1.8.0 by default. It can be configured to downgrade to 1.3 or 1.1, which strips the `container` object. Downgraded events lose sandbox attribution, so running at the native version is recommended.

## Collection

**Collect from each sandbox's supervisor.** The supervisor is the aggregation point for sandbox OCSF telemetry, one per sandbox. The gateway's log stream is a bounded in-memory buffer for operators and agents to inspect recent activity; it is not a collection path and is lost on gateway restart.

| Source | Enable with | Produces | Classes |
| --- | --- | --- | --- |
| Sandbox supervisor | `ocsf_json_enabled` setting | `/var/log/openshell-ocsf.YYYY-MM-DD.log` in the supervisor's filesystem | 4001, 4002, 4007, 1007, 2004, 6002, 0 |
| Gateway | `[openshell.gateway.ocsf_log]` in `gateway.toml` (0.1.3 and later) | JSONL file at the configured path | 5019 only |

Both sinks are disabled by default and produce the same event schema, so one parsing rule covers both. Use `metadata.product.name` to tell them apart: `OpenShell Sandbox Supervisor` or `OpenShell Gateway`.

### Enable the sandbox export

```shell
openshell settings set --global --key ocsf_json_enabled --value true
```

The supervisor picks the change up on its next poll, by default within 10 seconds. No restart is needed.

### Where the supervisor writes

The supervisor runs separately from the sandbox workload. `openshell sandbox exec` runs in the workload and cannot reach the supervisor's files.

| Compute driver | Supervisor log location | Lifetime |
| --- | --- | --- |
| Kubernetes | `/var/log` in the supervisor pod's `supervisor` container | `emptyDir`, removed with the pod |
| Docker / Podman | `/var/log` in the separate supervisor container | `tmpfs`, lost when the container stops |
| VM | `/var/log` on the host running the supervisor, if writable | Host-managed |

OpenShell does not configure a file collector. Ship files before rotation or teardown; on Kubernetes and Docker the logs disappear with the sandbox. The default supervisor image has no shell or `tar`, so `kubectl exec`, `kubectl cp` and `docker cp` cannot retrieve the files. Mount or sidecar the log volume with your collector. If the supervisor cannot open `/var/log` it falls back to stderr-only logging, which does not contain full OCSF JSON.

### Enable the gateway export (0.1.3 and later)

```toml
[openshell.gateway.ocsf_log]
path = "/var/log/openshell/gateway-ocsf.jsonl"
rotation = "daily"
max_files = 7
```

Rotation renames the active file to `<path>.<date>.<uuid>`, so configure the collector to follow renamed files.

### Forward to Cortex XSIAM

Use the **HTTP Log Collector** with Vendor `nvidia` and Product `openshell`, which produces the `nvidia_openshell_raw` dataset. Point any JSONL shipper at the files above and post one JSON object per line.

The gateway exposes delivery-loss counters on `/metrics`. Monitor `openshell_ocsf_log_dropped_total` to confirm no events are being dropped before they reach the collector.

## Notes on the data

- **Sandbox identity is `container.uid`.** Do not use `metadata.uid`, which is a fresh UUID per event. The `container` object is absent on gateway-wide events.
- **`activity_id` is only meaningful alongside `class_uid`.** The same integer means different things per class: `1` is `Open` for network activity and `Launch` for process activity.
- **`firewall_rule.type` carries the deciding policy engine**, for example `opa`, `nftables`, `l7` or `ssrf`. It is not an OCSF rule type.
- **One blocked egress attempt produces two events.** The policy DNS stage emits `activity_id` `5` (`Refuse`) with `status_detail` `policy_dns_ineligible`, then the TCP stage emits `activity_id` `1` (`Open`) with `transparent_tcp_policy_denied`. Count one stage only, or every threshold doubles. The detection below filters to the TCP stage.
- **`Refuse` events carry a hostname and nothing else.** No `dst_endpoint.port`, no `actor`. Do not key logic on either field for class `4001`.
- **Denial reasons in `status_detail` are machine tokens**, for example `transparent_tcp_policy_denied` and `policy_dns_ineligible`. They are not the prose strings shown in some documentation.
- **Process `pid` is `0`** for sandbox-side processes. Use `actor.process.file.path` for identity; PID-keyed correlation does not work.
- **Gateway replicas share `device.uid`.** Two installations using the same gateway name are indistinguishable from event content alone, so label them at the collector if you ingest more than one.

## Detections

This pack ships **no correlation rules**, by design.

OpenShell's default policy denies all egress, including routine destinations
such as `api.github.com`, so any detection keyed on denial volume fires
continuously until a real policy is applied. Useful thresholds need a baseline
from your own environment.

Hunt with the normalized fields in the meantime:

```
datamodel dataset = nvidia_openshell_raw
| filter xdm.event.outcome = "FAILED" and xdm.target.host.hostname != null
| comp count() as denials by xdm.source.agent.identifier, xdm.target.host.hostname
| sort desc denials
```

</~XSIAM>
