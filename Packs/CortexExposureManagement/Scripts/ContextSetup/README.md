This script simplifies how you add data to Cortex XSOAR's context. Use it to set static values or to map different values to existing context paths. Instead of a value you can enter TIMESTAMP to get the current timestamp in ISO format. For example:
`!ContextSetup keys=ip,src,timestamp val1=${AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress} val2="AWS" val3="TIMESTAMP" context_key="key"`.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Set

## Used In

---
This script is used in the following playbooks and scripts.

* Cortex EM - Exposure Issue
* Cortex EM - ServiceNow CMDB

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| keys | A comma-separated list of columns for the context key. |
| val1 | A value for the 1st key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val2 | A value for the 2nd key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val3 | A value for the 3rd key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val4 | A value for the 4th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val5 | A value for the 5th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val6 | A value for the 6th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val7 | A value for the 7th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val8 | A value for the 8th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val9 | A value for the 9th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val10 | A value for the 10th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val11 | A value for the 11th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val12 | A value for the 12th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val13 | A value for the 13th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val14 | A value for the 14th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val15 | A value for the 15th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val16 | A value for the 16th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val17 | A value for the 17th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val18 | A value for the 18th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val19 | A value for the 19th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| val20 | A value for the 20th key. \(Can be a string or context path or \`TIMESTAMP\` to get the current timestamp in ISO format.\) |
| context_key | Context key to populate. |
| overwrite | Whether to overwrite \(true\) or append \(false\) what is in the context key \(default is false\). |

## Outputs

---
There are no outputs for this script.
