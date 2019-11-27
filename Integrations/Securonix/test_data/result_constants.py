EXPECTED_LIST_WORKFLOWS = {
    'Securonix.Workflows(val.Workflow == obj.Workflow)':
        [
            {
                'Workflow': 'SOCTeamReview', 'Type': 'USER', 'Value': 'admin'
            },
            {
                'Workflow': 'ActivityOutlierWorkflow', 'Type': 'USER', 'Value': 'admin'
            },
            {
                'Workflow': 'AccessCertificationWorkflow', 'Type': 'USER', 'Value': 'admin'
            }
        ]
}
EXPECTED_DEFAULT_ASSIGNEE = {
    'Securonix.Workflows(val.Workflow == obj.Workflow)': {
        'Workflow': 'SOCTeamReview',
        'Type': 'USER',
        'Value': 'admin'
    }
}
EXPECTED_POSSIBLE_THREAT_ACTIONS = {
    'Securonix.ThreatActions': [
        "Mark as concern and create incident",
        "Non-Concern",
        "Mark in progress (still investigating)"
    ]
}
