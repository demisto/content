Automation used to more easily populate a grid field.  This is necessary when you want to assign certain values as static or if you have context paths that you will assign to different values as well.  Instead of a value you can enter `TIMESTAMP` to get the current timestamp in ISO format.  For example:
`!GridFieldSetup keys=ip,src,timestamp val1=${AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress} val2="AWS" val3="TIMESTAMP" gridfiled="gridfield"`

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
| val1 | A value for the 1st key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val2 | A value for the 2nd key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val3 | A value for the 3rd key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val4 | A value for the 4th key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val5 | A value for the 5th key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val6 | A value for the 6th key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val7 | A value for the 7th key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val8 | A value for the 8th key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val9 | A value for the 9th key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
| val10 | A value for the 10th key. \(Can be a string or context path or `TIMESTAMP` to get the current timestamp in ISO format.\) |
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
