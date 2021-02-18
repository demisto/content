Copy all entries marked as notes from current incident to another incident.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| target_incident | Incident ID to copy notes to. |
| tags | Replicate only notes with these tags \(array or comma separated\). |

## Outputs
---
There are no outputs for this script.


## Script Example
```!CopyNotesToIncident target_incident=20723```

## Context Example
```json
{}
```

## Human Readable Output

>## 3 notes copied
