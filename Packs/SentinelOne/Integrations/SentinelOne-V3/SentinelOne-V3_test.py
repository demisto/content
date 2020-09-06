import io
import json

import demistomock as demisto
from importlib import import_module

sentinelone_v3 = import_module('SentinelOne-V3')
fetch_incidents = sentinelone_v3.fetch_incidents
main = sentinelone_v3.main


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents_all_inclusive(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://usea1.sentinelone.net',
        'fetch_time': '3 years',
    })
    raw_threat_response = util_load_json('test_data/get_threats_raw_response.json')
    incidents_for_fetch = util_load_json('test_data/incidents.json')
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': 1558541949000})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    requests_mock.get('https://usea1.sentinelone.net/web/api/v2.1/threats', json=raw_threat_response)
    main()
    fetch_incidents()

    assert demisto.incidents.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    incidents = demisto.incidents.call_args[0][0]
    # with 'fetch_threat_rank' equal to 0 all 3 incidents from INCIDENTS_FOR_FETCH should be returned
    assert len(incidents) == 4
    threat_incident = incidents[0]
    assert threat_incident.get('occurred', '') == '2019-09-15T12:05:49.095889Z'
    threat_incident = incidents[1]
    assert threat_incident.get('occurred', '') == '2019-09-15T12:14:42.440985Z'
    threat_incident = incidents[2]
    assert threat_incident.get('occurred', '') == '2019-09-15T12:14:43.349807Z'
    threat_incident = incidents[3]
    assert threat_incident.get('occurred', '') == '2019-09-15T12:14:44.069617Z'
    assert incidents_for_fetch == incidents
