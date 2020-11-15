Converts Domain(s) to URL(s).
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
| domains | List of Domain\(s\) to be converted to URL\(s\). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainToURL | Converted URLs | Unknown |


## Script Example
```!ConvertDomainToURLs domains=demo.com```

## Context Example
```
{
    "DomainToURL": [
        "http://demo.com",
        "https://demo.com"
    ]
}
```

## Human Readable Output
{}
