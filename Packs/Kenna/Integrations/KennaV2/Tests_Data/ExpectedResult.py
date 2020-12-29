VULNERABILITIES_SEARCH_EXPECTED = {
    'Kenna.Vulnerabilities(val.ID === obj.ID)': [{
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
        "Score": 1,
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
        "Severity": 1,
        "Status": "open",
        "Threat": 1,
        "TopPriority": True
    },
    ]
}

GET_CONNECTORS_EXPECTED = {
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
SEARCH_FIXES_EXPECTED = {
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
SEARCH_ASSETS_EXPECTED = {
    "Kenna.Assets(val.ID === obj.ID)": [
        {
            "Fqdn": None,
            "Hostname": None,
            "ID": 3,
            "IpAddress": "Kenna",
            "Score": 3,
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
GET_ASSETS_VULNERABILITIES_EXPECTED = {
    "Kenna.VulnerabilitiesOfAsset(val.ID === obj.ID)": [
        {
            "AssetID": 4,
            "CveID": "Kenna",
            "ID": 4,
            "Patch": True,
            "Status": "open",
            "TopPriority": True,
            "Score": 4
        }
    ]
}

GET_CONNECTOR_RUNS_EXPECTED = {'Kenna.ConnectorRunsList(val.ID === obj.ID)':
    [
        {
            'id': 1462281,
            'start_time': '2020-12-21T06:32:03.000Z',
            'end_time': '2020-12-21T07:52:28.000Z',
            'success': True,
            'total_payload_count': 6819,
            'processed_palyoad_count': None,
            'failed_payload_count': 0,
            'processed_assets_count': 6456,
            'assets_with_tags_reset_count': 0,
            'processed_scanner_vuln_count': 651063,
            'created_scanner_vuln_count': 0,
            'closed_scanner_vuln_count': 0,
            'autoclosed_scanner_vuln_count': 0,
            'reopened_scanner_vuln_count': 0,
            'closed_vuln_count': 0,
            'autoclosed_vuln_count': 0,
            'reopened_vuln_count': 0
            },
        {'id': 1460258,
            'start_time': '2020-12-20T06:32:05.000Z',
            'end_time': '2020-12-20T07:48:42.000Z',
            'success': True, 'total_payload_count': 6819,
            'processed_palyoad_count': None,
            'failed_payload_count': 0,
            'processed_assets_count': 6456,
            'assets_with_tags_reset_count': 0,
            'processed_scanner_vuln_count': 651063,
            'created_scanner_vuln_count': 0,
            'closed_scanner_vuln_count': 0,
            'autoclosed_scanner_vuln_count': 0,
            'reopened_scanner_vuln_count': 0,
            'closed_vuln_count': 0,
            'autoclosed_vuln_count': 0,
            'reopened_vuln_count': 0
            }
    ]
}