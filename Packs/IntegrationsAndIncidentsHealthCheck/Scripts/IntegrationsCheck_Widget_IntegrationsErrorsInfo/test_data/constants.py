FAILED_TABLE = """[{"brand": "Active Directory Query v2", "category": "Data Enrichment & Threat Intelligence",
                 "information": "Failed to access LDAP server. Please validate the server host and port are configured correctly (85)",
                 "instance": "Active Directory Query v2_instance_1"},
                {"brand": "BigFix", "category": "Vulnerability Management",
                 "information": "Invalid URL 'xd7x91xd7x94xd7xa0/api/help': No schema supplied. Perhaps you meant http://בהנ/api/help? (85)",
                 "instance": "BigFix_instance_1"}, {"brand": "Tanium Threat Response", "category": "Endpoint",
                                                    "information": "Error in Tanium Threat Response Integration: Invalid URL 'sfgdfg/api/v2/session/login': No schema supplied. Perhaps you meant http://sfgdfg/api/v2/session/login? (85)",
                                                    "instance": "Tanium Threat Response_instance_1"},
                {"category": "Forensics & Malware Analysis",
                 "instance": "Threat Grid_instance_1", "brand": "Threat Grid"},
                {"instance": "VirusTotal_instance_1", "brand": "VirusTotal",
                 "category": "Data Enrichment & Threat Intelligence",
                 "information": "403 Forbidden - The API key is not valid (85)"},
                {"brand": "remoteaccess", "category": "Endpoint",
                 "information": "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain",
                 "instance": "remoteaccess_instance_1"}]"""

FAILED_TABLE_EXPECTED = {
    "data": [
        {
            "Brand": "Active Directory Query v2",
            "Category": "Data Enrichment & Threat Intelligence",
            "Information": "Failed to access LDAP server. Please validate the "
            "server host and port are configured correctly (85)",
            "Instance": "Active Directory Query v2_instance_1",
        },
        {
            "Brand": "BigFix",
            "Category": "Vulnerability Management",
            "Information": "Invalid URL 'xd7x91xd7x94xd7xa0/api/help': No "
            "schema supplied. Perhaps you meant "
            "http://בהנ/api/help? (85)",
            "Instance": "BigFix_instance_1",
        },
        {
            "Brand": "Tanium Threat Response",
            "Category": "Endpoint",
            "Information": "Error in Tanium Threat Response Integration: "
            "Invalid URL 'sfgdfg/api/v2/session/login': No "
            "schema supplied. Perhaps you meant "
            "http://sfgdfg/api/v2/session/login? (85)",
            "Instance": "Tanium Threat Response_instance_1",
        },
        {
            "Brand": "Threat Grid",
            "Category": "Forensics & Malware Analysis",
            "Information": None,
            "Instance": "Threat Grid_instance_1",
        },
        {
            "Brand": "VirusTotal",
            "Category": "Data Enrichment & Threat Intelligence",
            "Information": "403 Forbidden - The API key is not valid (85)",
            "Instance": "VirusTotal_instance_1",
        },
        {
            "Brand": "remoteaccess",
            "Category": "Endpoint",
            "Information": "ssh: handshake failed: ssh: unable to authenticate, "
            "attempted methods [none], no supported methods "
            "remain",
            "Instance": "remoteaccess_instance_1",
        },
    ],
    "total": 6,
}
