RESPONSE_DATA = [
    {
        "id": 31,
        "serviceArea": "SharePoint",
        "serviceAreaDisplayName": "SharePoint Online and OneDrive for Business",
        "urls": [
            "*.sharepoint.com",
            "www.sharepoint.com"
        ],
        "ips": [
            "7.7.7.7",
            "23.62.60.187",
            "6.7.8.9",
            "10.1.1.254",
        ],
        "tcpPorts": "80,443",
        "expressRoute": True,
        "category": "Optimize",
        "required": True
    },
    {
        "id": 32,
        "serviceArea": "SharePoint",
        "serviceAreaDisplayName": "SharePoint Online and OneDrive for Business",
        "urls": [
            "microsoftonline.com",
            "storage.live.com"
        ],
        "tcpPorts": "443",
        "expressRoute": False,
        "category": "Default",
        "required": False,
        "notes": "OneDrive for Business: supportability, telemetry, APIs, and embedded email links"
    },
    {
        "id": 33,
        "serviceArea": "SharePoint",
        "serviceAreaDisplayName": "SharePoint Online and OneDrive for Business",
        "urls": [
            "*.demisto.us.net",
            "test.com"
        ],
        "tcpPorts": "443",
        "expressRoute": False,
        "category": "Default",
        "required": False,
        "notes": "SharePoint Hybrid Search - Endpoint to SearchContentService where the hybrid crawler feeds documents"
    }
]
