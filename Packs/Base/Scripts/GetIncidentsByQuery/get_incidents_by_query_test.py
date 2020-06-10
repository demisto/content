from CommonServerPython import *
from GetIncidentsByQuery import build_incidents_query, get_incidents, parse_relative_time, main,\
    preprocess_incidents_fields_list

incident1 = {
    'id': 1,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'CustomFields': {
        'testField': "testValue"
    },
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}, {'type': 'unique', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}]
}
incident2 = dict(incident1)
incident2['id'] = 2


def get_args():
    args = {}
    args['incidentTypes'] = 'Phishing,Malware'
    args['timeField'] = 'created'
    args['fromDate'] = '2019-10-01'
    args['toDate'] = '3 days ago'
    args['limit'] = '10'
    args['includeContext'] = 'false'
    args['outputFormat'] = 'pickle'
    return args


def test_build_query(mocker):
    mocker.patch.object(demisto, 'args', side_effect=get_args)
    query = build_incidents_query("Extra part", "Phishing,Malware", "modified", "2019-01-10", "3 days ago",
                                  ["status", "closeReason"])
    assert query == '(Extra part) and (type:("Phishing" "Malware")) and (modified:>="2019-01-10T00:00:00") ' \
                    'and (modified:<"3 days ago") and (status:* and closeReason:*)'
    query = build_incidents_query("Extra part", "Phishing", "modified", "2019-01-10", "3 days ago",
                                  ["status"])
    assert query == '(Extra part) and (type:("Phishing")) and (modified:>="2019-01-10T00:00:00") ' \
                    'and (modified:<"3 days ago") and (status:*)'


def test_get_incidents(mocker):
    mocker.patch.object(demisto, 'args', side_effect=get_args)
    size = 100
    query = 'query'

    def validate_args(command, args):
        assert len(args.get('from')) > 5
        assert args['size'] == size
        assert args['query'] == query
        return [{'Type': entryTypes['note'], 'Contents': {'data': []}}]

    mocker.patch.object(demisto, 'executeCommand', side_effect=validate_args)
    get_incidents(query, "created", size, "3 days ago")
    get_incidents(query, "created", size, "3 months ago")
    get_incidents(query, "created", size, "3 weeks ago")
    get_incidents(query, "created", size, "2020-02-16T17:45:53.179489")

    def validate_args_without_from(command, args):
        assert args.get('from') is None
        return [{'Type': entryTypes['note'], 'Contents': {'data': []}}]

    mocker.patch.object(demisto, 'executeCommand', side_effect=validate_args_without_from)

    get_incidents(query, "modified", size, "3 weeks ago")


def test_parse_relative_time():
    threshold = 2
    t1 = parse_relative_time("3 days ago")
    t2 = datetime.now() - timedelta(days=3)
    assert abs((t2 - t1)).total_seconds() < threshold

    t1 = parse_relative_time("3 minutes ago")
    t2 = datetime.now() - timedelta(minutes=3)
    assert abs((t2 - t1)).total_seconds() < threshold

    t1 = parse_relative_time("1 months ago")
    t2 = datetime.now() - timedelta(minutes=43800)
    assert abs((t2 - t1)).total_seconds() < threshold

    t1 = parse_relative_time("2 weeks ago")
    t2 = datetime.now() - timedelta(weeks=2)
    assert abs((t2 - t1)).total_seconds() < threshold

    t1 = parse_relative_time("2 years ago")
    t2 = datetime.now() - timedelta(days=365 * 2)
    assert abs((t2 - t1)).total_seconds() < threshold


def test_main(mocker):
    args = get_args()
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Type': entryTypes['note'],
                                                                  'Contents': {'data': [incident1, incident2]}}])
    entry = main()
    assert "Fetched 2 incidents successfully" in entry['HumanReadable']
    assert 'GetIncidentsByQuery' in entry['EntryContext']
    assert 'status' in entry['Contents'][0]
    assert 'context' not in entry['Contents'][0]
    assert 'testValue' == entry['Contents'][0]['testField']

    args['includeContext'] = 'true'
    entry = main()
    assert {} == entry['Contents'][0]['context']

    args['populateFields'] = 'testField,status'
    args['NonEmptyFields'] = 'severity'
    entry = main()
    assert set(entry['Contents'][0].keys()) == set(['testField', 'status', 'severity'])
    args.pop('fromDate')
    entry = main()
    assert set(entry['Contents'][0].keys()) == set(['testField', 'status', 'severity'])


def test_preprocess_incidents_fields_list():
    incidents_fields = ['incident.emailbody', ' incident.emailsbuject']
    assert preprocess_incidents_fields_list(incidents_fields) == ['emailbody', 'emailsbuject']
