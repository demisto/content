Automation used to setup temporary context to be used then by the !setGridField command.  This is necessary when you want to assign certain values as static or if you have context paths that you will assign to different values as well.  Example of command:
`!GridFieldSetup keys=ip,src val1=${AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress} val2="AWS" context_path=temp`

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| context_path | context path to store the temporary list of dictionaries reference in \!setGridField command. |
| keys | columns for the grid field in comma separated format |
| val1 | value for 1st key \(can be string or context path\) |
| val2 | value for 2nd key \(can be string or context path\) |
| val3 | value for 3rd key \(can be string or context path\) |
| val4 | value for 4th key \(can be string or context path\) |
| val5 | value for 5th key \(can be string or context path\) |

## Outputs
---
There are no outputs for this script.
