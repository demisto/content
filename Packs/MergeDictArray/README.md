Each entry in an array is merged into the existing array if the keyed-value matches.

---
## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | transformer, entirelist, general |


---
## Examples

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
        "IP": [
            {
                "Address": "8.8.8.8", 
                "ANS": 15169, 
                "Hostname": "dns.google"
            },
            {
                "Address": "8.8.4.4", 
                "ANS": 15169, 
                "Hostname": "dns.google"
            }
        ]
    }
    
    
    Merge two arrays (Shodan.IP and IP) into an array. ->

    [
        {
            "Address": "8.8.8.8", 
            "ANS": 15169, 
            "Hostname": "dns.google",
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
            "ANS": 15169, 
            "Hostname": "dns.google"
        }
    ]
