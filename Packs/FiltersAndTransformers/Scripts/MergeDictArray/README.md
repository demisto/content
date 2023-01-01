Each entry in an array is merged into the existing array if the keyed-value matches.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | transformer, general, entirelist |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The input value |
| array_path | The relative path to the array from \`value\`. |
| merge_with | An array to merge from |
| mapping | A comma separated list of pairs \[key of merge_with\]:\[key of value.arrah_path\]. e.g. ip:dst_ip, hostname:dst_host |
| out_key | The key to the value where each of the destination value is to be set |
| out_path | The relative path to the destination array where the marged array is set |
| appendable | true if it allows to simply append source entries which doesn't match, otherwise false |
| conflict_strategy | How to merge the values if the key conflicts. 'source' means data of 'merge_with', 'destination' means data of 'array_path'. Default is 'merge'.|
| overwrite_by_source | The comma separeted list of keys to overwrite by source value if the key conflicts. |
| overwrite_by_destination | The comma separeted list of keys to overwrite by destination value if the key conflicts. |

## Outputs
---
There are no outputs for this script.
