Gets the hostname correlated with the inputed IP address.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | - |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ip | The IP address to check. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Endpoint | The endpoint object. | Unknown |
| Endpoint.Hostname | The endpoint hostname. | string |
| Endpoint.IP | The endpoint IP address. | string |
