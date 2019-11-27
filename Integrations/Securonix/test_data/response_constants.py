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

