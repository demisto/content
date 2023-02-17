This is a wrapper to isolate or unisolate hash lists from Cortex XDR, MSDE or CrowdStrike (Available from Cortex XSOAR 6.0.0).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| device_ids | Device IDs to isolate or unisolate. |
| action | The action to apply to device IDs - isolate or unisolate. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | String |
| MicrosoftATP.MachineAction.Type | The type of the machine action. | String |
| MicrosoftATP.MachineAction.Scope | The scope of the action. | Unknown |
| MicrosoftATP.MachineAction.Requestor | The ID of the user that executed the action. | String |
| MicrosoftATP.MachineAction.RequestorComment | The comment that was written when issuing the action. | String |
| MicrosoftATP.MachineAction.Status | The current status of the command. | String |
| MicrosoftATP.MachineAction.MachineID | The machine ID on which the action was executed. | String |
| MicrosoftATP.MachineAction.ComputerDNSName | The machine DNS name on which the action was executed. | String |
| MicrosoftATP.MachineAction.CreationDateTimeUtc | The date and time the action was created. | Date |
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | The last date and time the action status was updated. | Date |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | The file identifier. | String |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | The type of the file identifier. Possible values: "SHA1" ,"SHA256", and "MD5". | String |
| PaloAltoNetworksXDR.Isolation.endpoint_id | The endpoint ID. | String |
| PaloAltoNetworksXDR.UnIsolation.endpoint_id | Isolates the specified endpoint. | String |


## Script Examples
### Example command
```!IsolationAssetWrapper action=unisolate device_ids=15dbb9d8f06b45fe9f61eb46e829d986,046761c46ec84f40b27b6f79ce7cd32c```
### Context Example
```json
{
    "MicrosoftATP": {
        "MachineAction": {
            "Status": "Pending", 
            "Commands": [], 
            "CreationDateTimeUtc": "2022-03-27T10:14:29.9635187Z", 
            "MachineID": null, 
            "LastUpdateTimeUtc": null, 
            "ComputerDNSName": null, 
            "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
            "RelatedFileInfo": {
                "FileIdentifier": null, 
                "FileIdentifierType": null
            }, 
            "Scope": null, 
            "Type": "Unisolate", 
            "ID": "7e7cae42-6e9b-41a2-be6a-69817ec077a6", 
            "RequestorComment": "XSOAR - related incident ab57e22c-ad03-4aba-8b6c-b42bd895a116"
        }
    }
}
```

### Human Readable Output

### Results Summary
|Instance|Command|Result|Comment|
|---|---|---|---|
| ***CrowdstrikeFalcon***: CrowdstrikeFalcon_instance_1 | ***command***: cs-falcon-lift-host-containment<br>**args**:<br>	***ids***: 15dbb9d8f06b45fe9f61eb46e829d986,046761c46ec84f40b27b6f79ce7cd32c | Success |  |
| ***Cortex XDR - IR***: Cortex XDR - IR_instance_1_copy | ***command***: xdr-unisolate-endpoint<br>**args**:<br>	***endpoint_id***: 15dbb9d8f06b45fe9f61eb46e829d986 | Error | Error: Endpoint 1<XX_REPLACED>dbb9d8f06b4<XX_REPLACED>fe9f61eb46e829d986 was not found |
| ***Cortex XDR - IR***: Cortex XDR - IR_instance_1 | ***command***: xdr-unisolate-endpoint<br>**args**:<br>	***endpoint_id***: 15dbb9d8f06b45fe9f61eb46e829d986 | Error | Error: Endpoint 1<XX_REPLACED>dbb9d8f06b4<XX_REPLACED>fe9f61eb46e829d986 was not found |
| ***Cortex XDR - IR***: Cortex XDR - IR_instance_1_copy | ***command***: xdr-unisolate-endpoint<br>**args**:<br>	***endpoint_id***: 046761c46ec84f40b27b6f79ce7cd32c | Error | Error: Endpoint 046761c46ec84f40b27b6f79ce7cd32c was not found |
| ***Cortex XDR - IR***: Cortex XDR - IR_instance_1 | ***command***: xdr-unisolate-endpoint<br>**args**:<br>	***endpoint_id***: 046761c46ec84f40b27b6f79ce7cd32c | Error | Error: Endpoint 046761c46ec84f40b27b6f79ce7cd32c was not found |
| ***Microsoft Defender Advanced Threat Protection***: Microsoft Defender Advanced Threat Protection_instance_1 | ***command***: microsoft-atp-unisolate-machine<br>**args**:<br>	***machine_id***: 15dbb9d8f06b45fe9f61eb46e829d986,046761c46ec84f40b27b6f79ce7cd32c<br>	***comment***: XSOAR - related incident ab57e22c-ad03-4aba-8b6c-b42bd895a116 | Error | Microsoft Defender ATP The command was failed with the errors: {'15dbb9d8f06b45fe9f61eb46e829d986': NotFoundError({'error': {'code': 'ResourceNotFound', 'message': 'Machine 15dbb9d8f06b45fe9f61eb46e829d986 was not found. OrgId: b7df6ab7-5c73-4e13-8cd3-82e1f3d849ed.', 'target': '9b321da9-6458-4ab3-a818-92f33247508a'}}), '046761c46ec84f40b27b6f79ce7cd32c': NotFoundError({'error': {'code': 'ResourceNotFound', 'message': 'Machine 046761c46ec84f40b27b6f79ce7cd32c was not found. OrgId: b7df6ab7-5c73-4e13-8cd3-82e1f3d849ed.', 'target': 'd3d4f57f-73a2-4905-bd35-13eccbcaedb6'}})} |

Containment has been lift off host '15dbb9d8f06b45fe9f61eb46e829d986', '046761c46ec84f40b27b6f79ce7cd32c'
