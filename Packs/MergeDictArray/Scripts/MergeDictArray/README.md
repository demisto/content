Each entry in an array is merged into the existing array if the keyed-value matches.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | transformer, general, entirelist |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The input value |
| array_path | The relative path to the array from \`value\`. |
| merge_with | An array to merge from |
| mapping | A comma separated list of pairs \[key of value.arrah_path\]:\[key of merge_with\]. e.g. ip:dst_ip, hostname:dst_host |
| out_key | The key to the value where each of the destination value is to be set |
| out_path | The relative path to the destination array where the marged array is set |
| appendable | true if it allows to simply append source entries which doesn't match, otherwise false |

## Outputs
---
There are no outputs for this script.


----
## Examples
---

#### Example 1

##### Context
    {
        "Shodan": {
            "IP": {
                "Address": "8.8.8.8", 
                "ISP": "Google LLC", 
                "Longitude": -122.0775, 
                "Port": [
                    53
                ], 
                "CountryName": "United States", 
                "Latitude": 37.4056, 
                "Org": "Google LLC", 
                "ASN": "AS15169"
            }
        }, 
        "DBotScore": [
            {
                "Indicator": "8.8.8.8", 
                "Score": 0, 
                "Type": "ip"
            },
            {
                "Address": "8.8.4.4", 
                "Score": 0, 
                "Type": "ip"
            }
        ]
    }

##### Parameters

| **Argument Name** | **Value** |
| --- | --- |
| value | ${DBotScore} |
| array_path |  |
| merge_with | ${Shodan.IP} |
| mapping | Address:Indicator |
| out_key | |
| out_path | |
| appendable | true |

```
!MergeDictArray value=${DBotScore} mapping=Address:Indicator merge_with=${Shodan.IP} appendable=true
```

##### Output
    [
        {
            "Indicator": "8.8.8.8", 
            "Score": 0, 
            "Type": "ip",
            "Address": "8.8.8.8", 
            "ISP": "Google LLC", 
            "Longitude": -122.0775, 
            "Port": [
                53
            ], 
            "CountryName": "United States", 
            "Latitude": 37.4056, 
            "Org": "Google LLC", 
            "ASN": "AS15169"
        },
        {
            "Address": "8.8.4.4", 
            "Score": 0, 
            "Type": "ip"
        }
    ]


#### Example 2

##### Context
    {
        "Shodan": {
            "IP": {
                "Address": "8.8.8.8", 
                "ISP": "Google LLC", 
                "Longitude": -122.0775, 
                "Port": [
                    53
                ], 
                "CountryName": "United States", 
                "Latitude": 37.4056, 
                "Org": "Google LLC", 
                "ASN": "AS15169"
            }
        }, 
        "DBotScore": [
            {
                "Indicator": "8.8.8.8", 
                "Score": 0, 
                "Type": "ip"
            },
            {
                "Address": "8.8.4.4", 
                "Score": 0, 
                "Type": "ip"
            }
        ]
    }

##### Parameters

| **Argument Name** | **Value** |
| --- | --- |
| value | ${DBotScore} |
| array_path |  |
| merge_with | ${Shodan.IP} |
| mapping | Address:Indicator |
| out_key | Shodan |
| out_path | |
| appendable | true |

```
!MergeDictArray value=${DBotScore} mapping=Address:Indicator merge_with=${Shodan.IP} out_key=Shodan appendable=true
```

##### Output
    [
        {
            "Indicator": "8.8.8.8", 
            "Score": 0, 
            "Type": "ip",
            "Shodan": {
                "Address": "8.8.8.8", 
                "ISP": "Google LLC", 
                "Longitude": -122.0775, 
                "Port": [
                    53
                ],
                "CountryName": "United States", 
                "Latitude": 37.4056, 
                "Org": "Google LLC", 
                "ASN": "AS15169"
            }
        },
        {
            "Address": "8.8.4.4", 
            "Score": 0, 
            "Type": "ip"
        }
    ]
