RESPONSE_LIST_WORKFLOWS = {
    "result": {
        "workflows":
            [
                {
                    "workflow": "SOCTeamReview",
                    "type": "USER",
                    "value": "admin"
                },
                {
                    "workflow": "ActivityOutlierWorkflow",
                    "type": "USER",
                    "value": "admin"
                },
                {
                    "workflow": "AccessCertificationWorkflow",
                    "type": "USER",
                    "value": "admin"
                }
            ]
    }
}
RESPONSE_DEFAULT_ASSIGNEE = {
    "result": {
        "type": "USER",
        "value": "admin"
    }
}
RESPONSE_POSSIBLE_THREAT_ACTIONS = {
    "result": [
        "Mark as concern and create incident",
        "Non-Concern",
        "Mark in progress (still investigating)"
    ]
}
RESPONSE_LIST_RESOURCE_GROUPS = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" \
                                "<resourceGroups>" \
                                "<resourceGroup>" \
                                "<name>Bluecoat Proxy</name>" \
                                "<type>Bluecoat Proxy</type>" \
                                "</resourceGroup>" \
                                "<resourceGroup>" \
                                "<name>Ironport Data</name>" \
                                "<type>Cisco Ironport Email</type>" \
                                "</resourceGroup>" \
                                "<resourceGroup>" \
                                "<name>Windchill Data</name>" \
                                "<type>Windchill</type>" \
                                "</resourceGroup>" \
                                "</resourceGroups>"
