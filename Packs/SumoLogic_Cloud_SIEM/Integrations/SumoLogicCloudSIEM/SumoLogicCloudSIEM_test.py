"""Integration for Sumo Logic Cloud SIEM - Unit Tests file

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""
from CommonServerPython import *
from CommonServerUserPython import *

import json
import io

from datetime import datetime
from datetime import timezone

MOCK_URL = 'https://test.com/api'
RECORD_SUMMARY_FIELDS_DEFAULT = (
    'action,description,device_hostname,device_ip,dstDevice_hostname,dstDevice_ip,'
    'email_sender,file_basename,file_hash_md5,file_hash_sha1,file_hash_sha256,srcDevice_hostname,'
    'srcDevice_ip,threat_name,threat_category,threat_identifier,user_username,threat_url,listMatches')


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_insight_get_details(requests_mock):
    """Tests sumologic-sec-insight-get-details command function.
    """
    from SumoLogicCloudSIEM import Client, insight_get_details, insight_signal_to_readable, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/insight_details.json')
    insight_id = 'INSIGHT-220'
    insight = insight_signal_to_readable(mock_response.get('data'))

    requests_mock.get(
        '{}/sec/v1/insights/{}?exclude=signals.allRecords&recordSummaryFields=action%2C'
        'description%2Cdevice_hostname%2Cdevice_ip%2CdstDevice_hostname%2CdstDevice_ip%2Cemail_sender%2C'
        'file_basename%2Cfile_hash_md5%2Cfile_hash_sha1%2Cfile_hash_sha256%2CsrcDevice_hostname%2C'
        'srcDevice_ip%2Cthreat_name%2Cthreat_category%2Cthreat_identifier%2Cuser_username%2Cthreat_url%2ClistMatches'.format(
            MOCK_URL, insight_id),
        json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'insight_id': insight_id,
        'record_summary_fields': RECORD_SUMMARY_FIELDS_DEFAULT
    }

    response = insight_get_details(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.Insight'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == insight
    assert response.readable_output == tableToMarkdown(
        'Insight Details:', [insight],
        ['Id', 'ReadableId', 'Name', 'Action', 'Status', 'Assignee', 'Description', 'LastUpdated', 'LastUpdatedBy', 'Severity',
         'Closed', 'ClosedBy', 'Timestamp', 'Entity', 'Resolution'], headerTransform=pascalToSpace)


def test_insight_get_comments(requests_mock):
    """Tests sumologic-sec-insight-get-comments command function.
    """
    from SumoLogicCloudSIEM import Client, insight_get_comments, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/insight_comments.json')
    insight_id = 'INSIGHT-116'
    comments = mock_response['data']['comments']

    requests_mock.get('{}/sec/v1/insights/{}/comments'.format(MOCK_URL, insight_id), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'insight_id': insight_id
    }

    response = insight_get_comments(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.InsightComments'
    assert response.outputs_key_field == 'Id'
    assert response.outputs[0]['Id'] == comments[0]['id'] == '2'
    assert response.outputs[0]['Author'] == comments[0]['author']['username'] == 'obfuscated@email.com'
    assert response.outputs[0]['Body'] == comments[0]['body'] == 'This is an example comment'


def test_signal_get_details(requests_mock):
    """Tests sumologic-sec-signal-get-details command function.
    """
    from SumoLogicCloudSIEM import Client, signal_get_details, insight_signal_to_readable, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/signal_details.json')
    signal_id = '2b449e56-f6e8-5306-980a-447a8c026b77'
    signal = mock_response.get('data')
    del signal['allRecords']
    signal = insight_signal_to_readable(signal)

    requests_mock.get('{}/sec/v1/signals/{}'.format(MOCK_URL, signal_id), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'signal_id': signal_id
    }

    response = signal_get_details(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.Signal'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == signal


def test_entity_get_details(requests_mock):
    """Tests sumologic-sec-entity-get-details command function.
    """
    from SumoLogicCloudSIEM import Client, entity_get_details, entity_to_readable, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/entity_details.json')
    entity_id = '_hostname-win10--admin.b.test.com'
    entity = entity_to_readable(mock_response.get('data'))

    requests_mock.get('{}/sec/v1/entities/{}'.format(MOCK_URL, entity_id), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'entity_id': entity_id
    }

    response = entity_get_details(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.Entity'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == entity


def test_insight_search(requests_mock):
    """Tests sumologic-sec-insight-search command function.
    """
    from SumoLogicCloudSIEM import Client, insight_search, insight_signal_to_readable, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/insight_list.json')
    insights = []
    for insight in mock_response['data']['objects']:
        insights.append(insight_signal_to_readable(insight))

    requests_mock.get('{}/sec/v1/insights?limit=2'.format(MOCK_URL), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'limit': '2'
    }

    response = insight_search(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.InsightList'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == insights


def test_entity_search(requests_mock):
    """Tests sumologic-sec-entity-search command function.
    """
    from SumoLogicCloudSIEM import Client, entity_search, entity_to_readable, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/entity_list.json')
    entities = []
    for entity in mock_response['data']['objects']:
        entities.append(entity_to_readable(entity))

    requests_mock.get('{}/sec/v1/entities?q=hostname:matchesWildcard(\"*test*\")&limit=2'.format(MOCK_URL), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'query': 'hostname:matchesWildcard(\"*test*\")',
        'limit': '2'
    }

    response = entity_search(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.EntityList'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == entities


def test_signal_search(requests_mock):
    """Tests sumologic-sec-signal-search command function.
    """
    from SumoLogicCloudSIEM import Client, signal_search, insight_signal_to_readable, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/signal_list.json')
    signals = []
    for signal in mock_response['data']['objects']:
        del signal['allRecords']
        signals.append(insight_signal_to_readable(signal))

    requests_mock.get('{}/sec/v1/signals?q=contentType:\"ANOMALY\"&limit=2'.format(MOCK_URL), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'created': 'All time',
        'contentType': 'ANOMALY',
        'limit': '2'
    }

    response = signal_search(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.SignalList'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == signals


def test_insight_set_status(requests_mock):
    """Tests sumologic-sec-insight-set-status command function.
    """
    from SumoLogicCloudSIEM import Client, insight_set_status, insight_signal_to_readable, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/insight_status.json')
    insight_id = 'INSIGHT-221'
    for signal in mock_response['data']['signals']:
        del signal['allRecords']
    insight = insight_signal_to_readable(mock_response.get('data'))

    requests_mock.put('{}/sec/v1/insights/{}/status'.format(MOCK_URL, insight_id), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'insight_id': insight_id,
        'status': 'closed',
        'resolution': 'Resolved'
    }

    response = insight_set_status(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.Insight'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == insight


def test_match_list_get(requests_mock):
    """Tests sumologic-sec-match-list-get command function.
    """
    from SumoLogicCloudSIEM import Client, match_list_get, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/match_lists.json')
    match_lists = []
    for match_list in mock_response['data']['objects']:
        match_lists.append({(k[0].capitalize() + k[1:]): v for k, v in match_list.items()})

    requests_mock.get('{}/sec/v1/match-lists?limit=5'.format(MOCK_URL), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'limit': '5'
    }

    response = match_list_get(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.MatchLists'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == match_lists


def test_match_list_update(requests_mock):
    """Tests sumologic-sec-match-list-update command function.
    """
    from SumoLogicCloudSIEM import Client, match_list_update, get_update_result, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/update_result.json')
    match_list_id = '166'
    requests_mock.post('{}/sec/v1/match-lists/{}/items'.format(MOCK_URL, match_list_id), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'match_list_id': match_list_id,
        'description': 'My description',
        'expiration': '2021-05-30T22:36:10.925Z',
        'value': '10.20.30.40',
        'active': 'true'
    }

    response = match_list_update(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.UpdateResult'
    assert response.outputs == get_update_result(mock_response.get('data'))


def test_threat_intel_search_indicators(requests_mock):
    """Tests sumologic-sec-threat-intel-search-indicators command function.
    """
    from SumoLogicCloudSIEM import Client, threat_intel_search_indicators, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/threat_intel_indicators.json')
    threat_intel_indicators = []
    for threat_intel_indicator in mock_response['data']['objects']:
        threat_intel_indicators.append({(k[0].capitalize() + k[1:]): v for k, v in threat_intel_indicator.items()})

    requests_mock.get('{}/sec/v1/threat-intel-indicators?value=11.22.33.44&sourceIds=54'.format(MOCK_URL), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'value': '11.22.33.44',
        'sourceIds': '54',
    }

    response = threat_intel_search_indicators(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.ThreatIntelIndicators'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == threat_intel_indicators


def test_threat_intel_get_sources(requests_mock):
    """Tests sumologic-sec-threat-intel-get-sources command function.
    """
    from SumoLogicCloudSIEM import Client, threat_intel_get_sources, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/threat_intel_sources.json')
    threat_intel_sources = []
    for threat_intel_source in mock_response['data']['objects']:
        threat_intel_sources.append({(k[0].capitalize() + k[1:]): v for k, v in threat_intel_source.items()})

    requests_mock.get('{}/sec/v1/threat-intel-sources?limit=5'.format(MOCK_URL), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'limit': '5'
    }

    response = threat_intel_get_sources(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.ThreatIntelSources'
    assert response.outputs_key_field == 'Id'
    assert response.outputs == threat_intel_sources


def test_threat_intel_update_source(requests_mock):
    """Tests sumologic-sec-threat-intel-update-source command function.
    """
    from SumoLogicCloudSIEM import Client, threat_intel_update_source, get_update_result, DEFAULT_HEADERS

    mock_response = util_load_json('test_data/update_result.json')
    threat_intel_source_id = '54'
    requests_mock.post('{}/sec/v1/threat-intel-sources/{}/items'.format(MOCK_URL, threat_intel_source_id), json=mock_response)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    args = {
        'threat_intel_source_id': threat_intel_source_id,
        'description': 'My description',
        'expiration': '2021-05-30T22:36:10.925Z',
        'value': '10.20.30.40',
        'active': 'true'
    }

    response = threat_intel_update_source(client, args)

    assert response.outputs_prefix == 'SumoLogicSec.UpdateResult'
    assert response.outputs == get_update_result(mock_response.get('data'))


def test_fetch_incidents(requests_mock):
    """Tests fetch incidents.
    """
    from SumoLogicCloudSIEM import Client, fetch_incidents, DEFAULT_HEADERS

    mock_response1 = util_load_json('test_data/insight_list_page1.json')
    requests_mock.get(
        '{}/sec/v1/insights?q=created%3A%3E%3D2021-05-18T00%3A00%3A00.000000+status%3Ain%28%22new%22%2C+%22inprogress%22%29'
        '&limit=20&recordSummaryFields=action%2Cdescription%2Cdevice_hostname%2Cdevice_ip%2CdstDevice_hostname'
        '%2CdstDevice_ip%2Cemail_sender%2Cfile_basename%2Cfile_hash_md5%2Cfile_hash_sha1%2Cfile_hash_sha256'
        '%2CsrcDevice_hostname%2CsrcDevice_ip%2Cthreat_name%2Cthreat_category%2Cthreat_identifier%2Cuser_username'
        '%2Cthreat_url%2ClistMatches'.format(MOCK_URL),
        json=mock_response1)

    mock_response2 = util_load_json('test_data/insight_list_page2.json')
    requests_mock.get(
        '{}/sec/v1/insights?q=created%3A%3E%3D2021-05-18T00%3A00%3A00.000000+status%3Ain%28%22new%22%2C+%22inprogress%22%29'
        '&limit=20&recordSummaryFields=action%2Cdescription%2Cdevice_hostname%2Cdevice_ip%2CdstDevice_hostname'
        '%2CdstDevice_ip%2Cemail_sender%2Cfile_basename%2Cfile_hash_md5%2Cfile_hash_sha1%2Cfile_hash_sha256'
        '%2CsrcDevice_hostname%2CsrcDevice_ip%2Cthreat_name%2Cthreat_category%2Cthreat_identifier%2Cuser_username'
        '%2Cthreat_url%2ClistMatches&offset=1'.format(MOCK_URL),
        json=mock_response2)

    client = Client(
        base_url=MOCK_URL,
        verify=False,
        headers=DEFAULT_HEADERS,
        proxy=False,
        auth=('access_id', 'access_key'),
        ok_codes=[200])

    next_run, incidents = fetch_incidents(client, 20, {}, 1621296000, None, RECORD_SUMMARY_FIELDS_DEFAULT)

    assert incidents[0].get('name') == 'Defense Evasion with Persistence - 3fa0cee5-6658-31d4-bd66-32fe1739cf61'
    assert incidents[0].get('occurred') == '2021-05-18T14:46:46.000Z'
    assert incidents[1].get('name') == 'Defense Evasion with Persistence - 67134063-94a3-3374-9c5f-dcb40d7f172e'
    assert incidents[1].get('occurred') == '2021-05-18T14:46:47.000Z'
    latest_created_time = datetime.strptime(incidents[1].get('occurred'), '%Y-%m-%dT%H:%M:%S.%fZ')
    assert next_run.get('last_fetch') == int(latest_created_time.replace(tzinfo=timezone.utc).timestamp())


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
