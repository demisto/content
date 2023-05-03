This is a wrapper around the setIndicators script.

## Script Data

---

| **Name** | **Description** |
| --- |-----------------|
| Script Type | python3         |
| Cortex XSOAR Version | 6.0.0           |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| Indicators | The CSV list of indicators to tag. |
| Tags | The tags to add to the indicators. |

## Outputs

---
There are no outputs for this script.

## Script Examples

### Example command

```!TagIndicatorButton Indicators=1.1.1.1 Tags=allow```

### Context Example

```json
{}
```

### Human Readable Output

>done - updated 1 indicators
