Verify that the CIDRs are valid.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | indicator-format |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | A comma-separated list of CIDR inputs. |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!VerifyCIDR input=190.0.0.0/1,200.200.200.200/29,300.0.0.0```
### Context Example
```json
{}
```

### Human Readable Output

>200.200.200.200/29
