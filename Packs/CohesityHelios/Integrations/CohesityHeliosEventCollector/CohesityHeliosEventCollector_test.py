# Fetch should test 3 case:
# 1: There are fewer events than page_size on first request
# 2: There are more than page_size events but there are less than max_fetch events
# 3: There are more than max_fetch events


def test_dedup_elements():
    from CohesityHeliosEventCollector import adjust_and_dedup_elements
    """
    Case 1
    """
    new_elements = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids)
    assert deduped_elements == []
    assert new_elements == [{'id': '1'}, {'id': '2'}, {'id': '3'}]
    """
    Case 2
    """
    new_elements = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
    existing_element_ids = ['1']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids)
    assert deduped_elements == [{'id': '2'}, {'id': '3'}]
    assert new_elements == [{'id': '1'}, {'id': '2'}, {'id': '3'}]
    """
    Case 2
    """
    new_elements = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
    existing_element_ids = []
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids)
    assert deduped_elements == [{'id': '1'}, {'id': '2'}, {'id': '3'}]
    assert new_elements == [{'id': '1'}, {'id': '2'}, {'id': '3'}]
    """
    Case 3
    """
    new_elements = []
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids)
    assert deduped_elements == []
    assert new_elements == []
    """
    Case 4
    """
    new_elements = [{'id': '2'}, {'id': '3'}]
    existing_element_ids = ['1', '2', '3']
    deduped_elements = adjust_and_dedup_elements(new_elements=new_elements, existing_element_ids=existing_element_ids)
    assert deduped_elements == []
    assert new_elements == [{'id': '2'}, {'id': '3'}]


def test_get_earliest_event_ids_with_the_same_time():
    from CohesityHeliosEventCollector import get_earliest_event_ids_with_the_same_time, ALERT_TIME_FIELD, AUDIT_LOGS_TIME_FIELD

    time_field = ALERT_TIME_FIELD
    """
    Case 1: list of Alert events where there is only one event that has the earliest timestamp
    Ensure only the ID of the earliest Alert is returned
    """
    events = [
        {'latestTimestampUsecs': '3', 'id': 'c'},
        {'latestTimestampUsecs': '2', 'id': 'b'},
        {'latestTimestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a']

    """
    Case 2: list of Alert events where there are two "earliest" events
    Ensure the ID of the TWO earliest Alerts is returned
    """
    events = [
        {'latestTimestampUsecs': '3', 'id': 'd'},
        {'latestTimestampUsecs': '2', 'id': 'c'},
        {'latestTimestampUsecs': '1', 'id': 'b'},
        {'latestTimestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a', 'b']

    time_field = AUDIT_LOGS_TIME_FIELD
    """
    Case 3: list of Audit Log events where there is only one event that has the earliest timestamp
    Ensure only the ID of the earliest event is returned
    """
    events = [
        {'timestampUsecs': '3', 'id': 'c'},
        {'timestampUsecs': '2', 'id': 'b'},
        {'timestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a']

    """
    Case 4: list of Audit Log events where there are two "earliest" events
    Ensure the ID of the TWO earliest Audit logs is returned
    """
    events = [
        {'timestampUsecs': '3', 'id': 'd'},
        {'timestampUsecs': '2', 'id': 'c'},
        {'timestampUsecs': '1', 'id': 'b'},
        {'timestampUsecs': '1', 'id': 'a'}
    ]
    earliest_event_fetched_ids = get_earliest_event_ids_with_the_same_time(events=events, time_field=time_field)
    assert earliest_event_fetched_ids == ['a', 'b']


def test_hash_fields_to_create_id():
    """
    Given: Dummy audit log event with the relevant fields
    """
    from CohesityHeliosEventCollector import hash_fields_to_create_id
    event = {
        'details': 'dummy_details',
        'username': 'dummy_username',
        'domain': 'dummy_domain',
        'sourceType': 'dummy_sourceType',
        'entityName': 'dummy_entityName',
        'entityType': 'dummy_entityType',
        'action': 'dummy_action',
        'timestampUsecs': 'dummy_timestampUsecs',
        'ip': 'dummy_ip',
        'isImpersonation': 'dummy_isImpersonation',
        'tenantId': 'dummy_tenantId',
        'originalTenantId': 'dummy_originalTenantId',
        'serviceContext': 'dummy_serviceContext'
    }
    _id = hash_fields_to_create_id(event)
    assert _id == '8bb89cb674035796b755e9e1db5022dc750e904f520eb290d18e134b12656bf2'

# def test_fetch

