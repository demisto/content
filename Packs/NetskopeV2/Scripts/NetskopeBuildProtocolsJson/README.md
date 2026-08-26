Builds the JSON array that ***netskopev2-create-private-app***/***netskopev2-update-private-app*** expect for their `protocols` argument (e.g. `[{"type": "tcp", "port": "443"}]`) from a plain comma-separated port list, so callers don't need to hand-write JSON.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ports | Comma-separated port numbers (e.g. "443,8080,22"). Leave empty to leave protocols unset (e.g. when modifying a private app without changing its protocols). |
| protocol_type | Transport protocol applied to every port in "ports" (e.g. "tcp" or "udp"). Netskope private apps support one protocol type per value, so all ports built here share the same type. Default is "tcp". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BuiltProtocols.protocols_json | JSON array of \{type, port\} objects, ready to pass as the "protocols" argument. Empty string if no ports were provided. | String |
