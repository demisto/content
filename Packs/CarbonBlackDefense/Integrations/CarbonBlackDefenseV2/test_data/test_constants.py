
PROCESS_CASES = [
    (
        'get_alert_by_id',
        'get_alert_details_command',
        {'alertId': '1234'},
        {'id': '1234', 'severity': 7, 'category': 'THREAT', 'device_username': 'demo'},
        {
            'CarbonBlackDefense.GetAlertDetails(val.id == obj.id)': {
                'id': '1234', 'severity': 7, 'category': 'THREAT', 'device_username': 'demo'
            }
        }
    ),
    (
        'get_devices',
        'device_search_command',
        {'device_id': '1234', 'os': 'MAC', 'status': 'sleep', 'target_priority': 'HIGH'},
        {
            "results": [
                {'id': 1234, 'name': 'carbon-black-integration-endpoint', 'os': 'MAC'}
            ]
        },
        {
            'CarbonBlackDefense.Device(val.id == obj.id)': [
                {'id': 1234, 'name': 'carbon-black-integration-endpoint', 'os': 'MAC'}
            ]
        }
    ),
    (
        'get_events',
        'find_events_command',
        {},
        {'job_id': '123456'},
        {'CarbonBlackDefense.Events(val.job_id == obj.job_id)': {'job_id': '123456'}}
    ),
    (
        'get_processes',
        'processes_search_command',
        {},
        {'job_id': '123456'},
        {'CarbonBlackDefense.Process(val.job_id == obj.job_id)': {'job_id': '123456'}}
    )
]
