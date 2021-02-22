Collect all asset identifiers - Hostname, IP address and MAC address in the context.
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
| artifact_identifiers | Hostname, IP address or MAC address that can identify the asset. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AssetIdentifiers | Collects all the asset identifier. | Unknown |

## Script Example
```
!ChronicleAssetIdentifierScript artifact_identifiers="{
        \"AccessedDomain\": \"dummy-accessed-domain.com\",
        \"FirstAccessedTime\": \"2018-10-03T02:59:56Z\",
        \"HostName\": \"dummy-host-name\",
        \"LastAccessedTime\": \"2020-07-02T20:42:30Z\"
    }"
```

##### Context Example
```
{
    "AssetIdentifiers": [
        "dummy-host-name"
    ]
}
```

##### Human Readable Output
{}
