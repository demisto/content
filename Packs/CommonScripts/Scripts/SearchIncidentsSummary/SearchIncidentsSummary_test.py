from SearchIncidentsSummary import check_if_found_incident, is_valid_args, apply_filters, add_incidents_link, \
    search_incidents


def test_check_if_found_incident():
    assert check_if_found_incident([{'Contents': {'data': ''}}])


def test_is_valid_args():
    assert is_valid_args({'id': '33'})


def test_apply_filters():
    assert apply_filters([{'name': 'test', 'type': 'test', 'CustomFields': {}}], {}) == [
        {'id': 'n/a', 'name': 'test', 'type': 'test', 'severity': 'n/a', 'status': 'n/a', 'owner': 'n/a',
         'created': 'n/a', 'closed': 'n/a'}]
