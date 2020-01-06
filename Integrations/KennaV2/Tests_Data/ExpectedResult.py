VULNERABILITIES_SEARCH_EXPECTED ={
    'Kenna':[{
        "AssetID": 1,
        "Connectors": [
            {
                "DefinitionName": "Kenna",
                "ID": 1,
                "Name": "Kenna",
                "Vendor": "Kenna"
            },
            {
                "DefinitionName": "Kenna",
                "ID": 1,
                "Name": "Kenna",
                "Vendor": "Kenna"
            }
        ],
        "CveID": "Kenna",
        "FixID": 1,
        "ID": 1,
        "Patch": True,
        "RiskMeterScore": None,
        "ScannerVulnerabilities": [
            {
                "ExternalID": "Kenna",
                "Open": True,
                "Port": None
            },
            {
                "ExternalID": "Kenna",
                "Open": True,
                "Port": None
            }
        ],
        "Score": None,
        "Severity": 1,
        "Status": "open",
        "Threat": 1,
        "TopPriority": True
    },
    ]
}

GET_CONNECTORS_EXPECTED ={
        "Kenna.ConnectorsList(val.ID === obj.ID)": [
            {
                "Host": None,
                "ID": 152075,
                "Name": "Nessus XML",
                "Running": True
            },
            {
                "Host": None,
                "ID": 152076,
                "Name": "Generic",
                "Running": True
            },
            {
                "Host": None,
                "ID": 152077,
                "Name": "Checkmarx XML",
                "Running": True
            },
            {
                "Host": "ven01347.service-now.com:443",
                "ID": 152078,
                "Name": "ServiceNow",
                "Running": True
            }
        ]
}
SEARCH_FIXES_EXPECTED ={
    "Kenna.Fixes(val.ID === obj.ID)": [
        {
            "Assets": [
                {
                    "DisplayLocator": "Kenna",
                    "ID": 2,
                    "Locator": "Kenna",
                    "PrimaryLocator": "Kenna"
                }
            ],
            "Category": None,
            "CveID": [
                "Kenna"
            ],
            "ID": 2,
            "LastUpdatedAt": "Kenna",
            "MaxScore": 2,
            "Title": "Kenna",
            "VulnerabilityCount": 2
        }
    ]
}
SEARCH_ASSETS_EXPECTED ={
        "Kenna.Assets(val.ID === obj.ID)": [
            {
                "Fqdn": None,
                "Hostname": None,
                "ID": 3,
                "IpAddress": "Kenna",
                "MinScore": None,
                "OperatingSystem": "Kenna",
                "Owner": None,
                "Priority": 3,
                "Status": "active",
                "Tags": [
                    "Kenna"
                ],
                "VulnerabilitiesCount": 3,
                "Notes": None
            }
    ]
}
GET_ASSETS_VULNERABILITIES_EXPECTED ={
        "Kenna.VulnerabilitiesOfAsset(val.ID === obj.ID)": [
            {
                "AssetID": 4,
                "CveID": "Kenna",
                "ID": 4,
                "Patch": True,
                "Status": "open",
                "TopPriority": True
            }
        ]
}
