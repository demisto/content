Automation used to more easily populate a grid field.  This is necessary when you want to assign certain values as static or if you have context paths that you will assign to different values as well.  Example of command:
`!GridFieldSetup keys=ip,src val1=${AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress} val2="AWS" gridfiled="gridfield"`

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| keys | columns for the grid field in comma separated format |
| val1 | value for 1st key \(can be string or context path\) |
| val2 | value for 2nd key \(can be string or context path\) |
| val3 | value for 3rd key \(can be string or context path\) |
| val4 | value for 4th key \(can be string or context path\) |
| val5 | value for 5th key \(can be string or context path\) |
| gridfield | Grid field to populate |
| overwrite | whether to overwrite what is in the gridfield or not \(default is to append\) |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!GridFieldSetup keys=url,verified val1="https://xsoar.pan.dev/" val2="verified" gridfield="urlsslverification"```
### Context Example
```json
{}
```

### Human Readable Output

>|Field|URL SSL Verification|
>|---|---|
>| Old Value | [{"url":"https://www.paloaltonetworks.com","verified":"verified"}] |
>| New Value | [{"url":"https://www.paloaltonetworks.com","verified":"verified"},{"url":"https://xsoar.pan.dev/","verified":"verified"}] |

### Example command
```!GridFieldSetup keys=url,verified val1="https://www.paloaltonetworks.com" val2="verified" gridfield="urlsslverification" overwrite=true```
### Context Example
```json
{}
```

### Human Readable Output

>|Field|URL SSL Verification|
>|---|---|
>| Old Value | [{"url":"https://xsoar.pan.dev/","verified":"verified"},{"url":"https://xsoar.pan.dev/","verified":"verified"}] |
>| New Value | [{"url":"https://www.paloaltonetworks.com","verified":"verified"}] |
