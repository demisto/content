Looks up Zero Networks Segment assets by FQDN and quarantines or releases them.
This integration was integrated and tested with version 1.26 of Zero Networks Segment.

## Configure Zero Networks Segment Assets in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of the Zero Networks portal. The API path is appended to it. | True |
| API Key | The API key to use for connection. The key must allow write operations for the quarantine commands. | True |
| Use system proxy settings | Whether to route requests through the system proxy. | False |
| Trust any certificate (not secure) | Whether to accept any certificate presented by the server. Do not enable this outside of testing. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zero-networks-segment-asset-search

***
Searches for an asset by its fully qualified domain name (FQDN) and returns the properties of the matching asset.

#### Base Command

`zero-networks-segment-asset-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fqdn | The fully qualified domain name of the asset to search for. For example, server.domain.local. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroNetworks.Asset.ID | String | The Zero Networks asset ID. |
| ZeroNetworks.Asset.Name | String | The asset display name. |
| ZeroNetworks.Asset.FQDN | String | The fully qualified domain name of the asset. |
| ZeroNetworks.Asset.Domain | String | The domain the asset belongs to. |
| ZeroNetworks.Asset.AssetType | String | The asset type. For example, Client, Server, or Printer. |
| ZeroNetworks.Asset.OSType | String | The operating system family of the asset. For example, Windows, Linux, or Mac. |
| ZeroNetworks.Asset.OperatingSystem | String | The operating system reported for the asset. |
| ZeroNetworks.Asset.IPv4Addresses | Unknown | The IPv4 addresses of the asset. |
| ZeroNetworks.Asset.IPv6Addresses | Unknown | The IPv6 addresses of the asset. |
| ZeroNetworks.Asset.ProtectionState | String | The segmentation protection state of the asset. For example, Segmented or Learning. |
| ZeroNetworks.Asset.IdentityProtectionState | String | The identity protection state of the asset. |
| ZeroNetworks.Asset.RPCProtectionState | String | The RPC protection state of the asset. |
| ZeroNetworks.Asset.IsQuarantined | Boolean | Whether the asset is currently quarantined. |
| ZeroNetworks.Asset.RiskScore | Number | The risk score of the asset. |
| ZeroNetworks.Asset.Source | String | The source the asset was discovered from. For example, Active Directory or AWS. |
| ZeroNetworks.Asset.HealthStatus | String | The health status of the asset. For example, Healthy, Warning, or Error. |
| ZeroNetworks.Asset.Labels | Unknown | The names of the labels assigned to the asset. |
| ZeroNetworks.Asset.LastLogon | Date | The date of the last logon recorded for the asset, in UTC \(e.g., 2024-08-29T12:00:15.000Z\). |
| ZeroNetworks.Asset.ProtectedAt | Date | The date the asset became protected, in UTC \(e.g., 2024-07-30T12:00:15.000Z\). |
| ZeroNetworks.Asset.InactiveSince | Date | The date the asset became inactive, in UTC \(e.g., 2024-07-30T12:00:15.000Z\). |

#### Command example

```!zero-networks-segment-asset-search fqdn="server.domain.local"```

#### Context Example

```json
{
    "ZeroNetworks": {
        "Asset": {
            "AssetType": "Server",
            "Domain": "domain.local",
            "FQDN": "server.domain.local",
            "HealthStatus": "Healthy",
            "ID": "a:a:JF2xro6g",
            "IPv4Addresses": [
                "10.0.0.15"
            ],
            "IdentityProtectionState": "Unsegmented",
            "IsQuarantined": false,
            "Labels": [
                "Crown Jewels",
                "Production"
            ],
            "LastLogon": "2024-08-29T12:00:15.000Z",
            "Name": "SERVER01",
            "OSType": "Windows",
            "OperatingSystem": "Windows Server 2019 Datacenter",
            "ProtectedAt": "2024-07-30T12:00:15.000Z",
            "ProtectionState": "Segmented",
            "RPCProtectionState": "Unsegmented",
            "RiskScore": 42,
            "Source": "Active Directory"
        }
    }
}
```

#### Human Readable Output

>### Zero Networks asset for server.domain.local
>
>|ID|Name|FQDN|Asset Type|Operating System|IPv4 Addresses|Protection State|Is Quarantined|Risk Score|
>|---|---|---|---|---|---|---|---|---|
>| a:a:JF2xro6g | SERVER01 | server.domain.local | Server | Windows Server 2019 Datacenter | 10.0.0.15 | Segmented | false | 42 |

### zero-networks-segment-asset-quarantine

***
Quarantines an asset, which blocks its network traffic. Specify the asset either by its asset ID or by its FQDN.

#### Base Command

`zero-networks-segment-asset-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the asset to quarantine. For example, a:a:JF2xro6g. Cannot be used together with the fqdn argument. | Optional |
| fqdn | The fully qualified domain name of the asset to quarantine. The asset ID is resolved from it. Cannot be used together with the asset_id argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroNetworks.Asset.ID | String | The Zero Networks asset ID. |
| ZeroNetworks.Asset.FQDN | String | The fully qualified domain name the asset was resolved from, when the fqdn argument was used. |
| ZeroNetworks.Asset.IsQuarantined | Boolean | Whether the asset is quarantined. Always true when the command succeeds. |

#### Command example

```!zero-networks-segment-asset-quarantine fqdn="server.domain.local"```

#### Context Example

```json
{
    "ZeroNetworks": {
        "Asset": {
            "FQDN": "server.domain.local",
            "ID": "a:a:JF2xro6g",
            "IsQuarantined": true
        }
    }
}
```

#### Human Readable Output

>Asset server.domain.local was successfully quarantined.

### zero-networks-segment-asset-unquarantine

***
Releases an asset from quarantine, which restores its network traffic. Specify the asset either by its asset ID or by its FQDN.

#### Base Command

`zero-networks-segment-asset-unquarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the asset to release from quarantine. For example, a:a:JF2xro6g. Cannot be used together with the fqdn argument. | Optional |
| fqdn | The fully qualified domain name of the asset to release from quarantine. The asset ID is resolved from it. Cannot be used together with the asset_id argument. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ZeroNetworks.Asset.ID | String | The Zero Networks asset ID. |
| ZeroNetworks.Asset.FQDN | String | The fully qualified domain name the asset was resolved from, when the fqdn argument was used. |
| ZeroNetworks.Asset.IsQuarantined | Boolean | Whether the asset is quarantined. Always false when the command succeeds. |

#### Command example

```!zero-networks-segment-asset-unquarantine asset_id="a:a:JF2xro6g"```

#### Context Example

```json
{
    "ZeroNetworks": {
        "Asset": {
            "ID": "a:a:JF2xro6g",
            "IsQuarantined": false
        }
    }
}
```

#### Human Readable Output

>Asset a:a:JF2xro6g was successfully released from quarantine.
