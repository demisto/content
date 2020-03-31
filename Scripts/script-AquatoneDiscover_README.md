Finds the targets nameservers and shuffle DNS lookups between them. If a lookup fails on the target domains nameservers, Aquatone Discover will use the Google public DNS servers to maximize discovery.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags |  |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| domain | The domain to discover. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Aquatone.discover | Finds the targets nameservers and shuffle DNS lookups between them. | Unknown |
