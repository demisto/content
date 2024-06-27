import json

import demistomock as demisto
from PaloAltoNetworks_IoT import Client, iot_get_device, fetch_incidents, iot_list_devices, \
    iot_resolve_alert, iot_resolve_vuln, iot_get_device_by_ip


def test_iot_get_device(requests_mock):
    """
    Scenario: Get a device details from IoT Security Portal by device ID

    Given
    - A device ID provided

    When
    - Getting the device details from IoT security portal

    Then
    - Ensure the api URL is correct
    - Ensure the response is right
    """
    mock_response = json.loads('''{"hostname":"00:0a:e4:1c:62:26","ip_address":"10.10.65.96","profile_type":"Non_IoT"}''')
    requests_mock.get('https://test.com/pub/v4.0/device?customerid=foobar&deviceid=00:0a:e4:1c:62:26', json=mock_response)

    client = Client(base_url='https://test.com/pub/v4.0', tenant_id="foobar", verify=False)
    args = {
        'id': '00:0a:e4:1c:62:26'
    }
    outputs = iot_get_device(client, args).outputs

    assert outputs == mock_response


def test_fetch_incidents(requests_mock, monkeypatch):
    """
    Scenario: Fetch incidents normally

    Given
    - the lastRun with last_vulns_fetch=0 and no last_alerts_fetch

    When
    - Fetching alerts/vulnerabilities from IoT Security Portal

    Then
    - Ensure the api URL is correct with the parameters
    - Ensure the lastRun timestamps are updated correctly
    """
    monkeypatch.setattr(demisto, "params", lambda: {
        'url': 'https://test.com'
    })

    mock_alert_response = json.loads('''{"ver":"v4.0","api":"/alert/list","items":[{"date":"2020-01-15T05:06:50.540Z",
"name":"foo","description":"The baseline","zb_ticketid":"alert-Ob81iwWe"},{"date":"2020-01-15T05:06:50.540Z",
"name":"bar","description":"x","zb_ticketid":"alert-Lqy4ikEz"}]}''')
    requests_mock.get('https://test.com/pub/v4.0/alert/list?customerid=foobar&offset=0&pagelength=10&stime=-1'
                      '&type=policy_alert&resolved=no&sortfield=date&sortdirection=asc', json=mock_alert_response)

    mock_vuln_response = json.loads('''{"ver":"v4.0","api":"/vulnerability/list","items":[{"name":"HPD41936",
"ip":"10.55.132.114","deviceid":"a0:d3:c1:d4:19:36","detected_date":"2020-05-31T23:59:59.000Z",
"vulnerability_name":"SMB v1 Usage"},{"name":"HPD41936","ip":"10.55.132.114","deviceid":"a0:d3:c1:d4:19:36",
"detected_date":["2020-05-31T23:59:59.000Z"],"vulnerability_name":"SMB v1 Usage"}]}''')
    requests_mock.get('https://test.com/pub/v4.0/vulnerability/list?customerid=foobar&offset=0&pagelength=10'
                      '&stime=1970-01-01T00:00:00.001000Z&type=vulnerability&status=Confirmed&groupby=device',
                      json=mock_vuln_response)

    client = Client(base_url='https://test.com/pub/v4.0', tenant_id="foobar", verify=False)
    last_run = {
        'last_vulns_fetch': 0
    }
    next_run, incidents = fetch_incidents(client, last_run)
    assert next_run == {
        'last_alerts_fetch': 1579064810.54,
        'last_vulns_fetch': 1590969599.0
    }
    assert len(incidents) == 4
    for incident in incidents:
        assert (isinstance(incident.get('occurred'), str))


def test_fetch_incidents_special(requests_mock, monkeypatch):
    """
    Scenario: Fetch incidents corner cases due to the same timestamps

    Given
    - A few incidents with the same timestamps at the edge of the pagination

    When
    - Fetching alerts/vulnerabilities from IoT Security Portal

    Then
    - Ensure the correct number of alerts/vulnerabilities are fetched
    - Ensure the lastRun timestamps are updated correctly
    """
    monkeypatch.setattr(demisto, "params", lambda: {
        'url': 'https://test.com'
    })

    mock_alert_response = json.loads('''{"items": [
        {
            "name": "alert1",
            "date": "2019-11-07T23:11:30.509Z",
            "zb_ticketid": "zb_ticketid1",
            "deviceid": "zb_ticketid1"
        },
        {
            "name": "alert2",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid2"
        }
    ]}''')
    requests_mock.get('https://test.com/pub/v4.0/alert/list?customerid=foobar&offset=0&pagelength=2&stime=-1'
                      '&type=policy_alert&resolved=no&sortfield=date&sortdirection=asc', json=mock_alert_response)
    mock_alert_response = json.loads('''{"items": [
        {
            "name": "alert3",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid3"
        },
        {
            "name": "alert4",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid4"
        }
    ]}''')
    requests_mock.get('https://test.com/pub/v4.0/alert/list?customerid=foobar&offset=2&pagelength=2&stime=-1'
                      '&type=policy_alert&resolved=no&sortfield=date&sortdirection=asc', json=mock_alert_response)
    mock_alert_response = json.loads('''{"items": [
        {
            "name": "alert5",
            "date": "2019-11-07T23:11:31.509Z",
            "zb_ticketid": "zb_ticketid5"
        },
        {
            "name": "alert6",
            "date": "2019-12-07T12:01:32.509Z",
            "zb_ticketid": "zb_ticketid6"
        }
    ]}''')
    requests_mock.get('https://test.com/pub/v4.0/alert/list?customerid=foobar&offset=4&pagelength=2&stime=-1'
                      '&type=policy_alert&resolved=no&sortfield=date&sortdirection=asc', json=mock_alert_response)

    mock_vuln_response = json.loads('''{"items": [
        {
            "name": "vuln1",
            "detected_date": "2019-11-07T23:11:30.509Z",
            "ip": "ip1",
            "vulnerability_name": "vname1",
            "deviceid": "deviceid1"
        },
        {
            "name": "vuln2",
            "detected_date": "2019-11-07T23:11:31.509Z",
            "ip": "ip2",
            "vulnerability_name": "vname2",
            "deviceid": "deviceid2"
        }
    ]}''')
    requests_mock.get('https://test.com/pub/v4.0/vulnerability/list?customerid=foobar&offset=0&pagelength=2&stime=-1'
                      '&type=vulnerability&status=Confirmed&groupby=device', json=mock_vuln_response)
    mock_vuln_response = json.loads('''{"items": []}''')
    requests_mock.get('https://test.com/pub/v4.0/vulnerability/list?customerid=foobar&offset=2&pagelength=2&stime=-1'
                      '&type=vulnerability&status=Confirmed&groupby=device', json=mock_vuln_response)

    client = Client(base_url='https://test.com/pub/v4.0', max_fetch=2, tenant_id="foobar", verify=False)
    next_run, incidents = fetch_incidents(client, {})
    assert next_run == {
        'last_alerts_fetch': 1573168291.509,
        'last_vulns_fetch': 1573168291.509
    }
    assert len(incidents) == 7  # 5 alerts + 2 vulns


def test_iot_list_devices(requests_mock):
    """
    Scenario: Listing devices

    Given
    - offset and pagelength parameters

    When
    - Fetching devices list from IoT Security Portal

    Then
    - Ensure the api URL is correct with the right parameters
    """
    mock_response = json.loads('''{"devices":[{},{}],"total":2}''')
    requests_mock.get('https://test.com/pub/v4.0/device/list?customerid=foobar&filter_monitored=no&offset=1'
                      '&pagelength=2&detail=true&sortfield=MAC&sortdirection=asc', json=mock_response)

    client = Client(base_url='https://test.com/pub/v4.0', tenant_id="foobar", verify=False)
    args = {
        'offset': '1',
        'limit': '2'
    }
    outputs = iot_list_devices(client, args).outputs

    assert len(outputs) == 2


def test_iot_resolve_alert(requests_mock):
    """
    Scenario: resolving alerts

    Given
    - An alert ID, reason and reason type

    When
    - Resolving an alert in IoT Security Portal

    Then
    - Ensure the api URL is correct with the right parameters and payload
    """
    mock_response = json.loads('''{"api":"/pub/v4.0/alert/update","ver":"v0.3"}''')
    adapter = requests_mock.put('https://test.com/pub/v4.0/alert/update?customerid=foobar&id=123', json=mock_response)

    client = Client(base_url='https://test.com/pub/v4.0', tenant_id="foobar", verify=False)
    args = {
        'id': '123',
        'reason': 'test',
        'reason_type': 'Issue Mitigated'
    }
    outputs = iot_resolve_alert(client, args).readable_output

    assert adapter.call_count == 1
    assert adapter.called
    assert adapter.last_request.json() == {'reason': 'test', 'reason_type': ['Issue Mitigated'], 'resolved': 'yes'}
    assert outputs == 'Alert 123 was resolved successfully'


def test_iot_resolve_vuln(requests_mock):
    """
    Scenario: resolving vulnerabilities

    Given
    - A vulnerability ID, reason and full vulnerability name

    When
    - Resolving a vulnerability in IoT Security Portal

    Then
    - Ensure the api URL is correct with the right parameters and payload
    """
    mock_response = json.loads('''{"api":"/vulnerability/update","ver":"v4.0","updatedVulnerInstanceList":[{
"newScore":10,"newLevel":"Low","newAnomalyMap":{"application":0,"protocol":0,"payload":0,"external":0,"internal":0}}]}''')
    adapter = requests_mock.put('https://test.com/pub/v4.0/vulnerability/update?customerid=foobar', json=mock_response)

    client = Client(base_url='https://test.com/pub/v4.0', tenant_id="foobar", verify=False)
    args = {
        'id': '123',
        'full_name': 'vuln_full_name',
        'reason': 'test',
    }
    outputs = iot_resolve_vuln(client, args).readable_output

    assert adapter.call_count == 1
    assert adapter.called
    assert adapter.last_request.json() == {
        'reason': 'test',
        'ticketIdList': ['123'],
        'action': 'mitigate',
        'full_name': 'vuln_full_name'
    }
    assert outputs == 'Vulnerability 123 was resolved successfully'


def test_get_device_by_ip(requests_mock):
    """
    Scenario: Geting device by ip

    Given
    - ip

    When
    - Fetching device details with IP

    Then
    - Ensure the IP is correct and return the device values.
    """
    mock_response = json.loads('''{"devices":{"hostname":"00:0a:e4:1c:62:26","ip_address":"1.1.1.1","profile_type":"Non_IoT"}}''')
    requests_mock.get('https://test.com/pub/v4.0/device/ip', json=mock_response)

    client = Client(base_url='https://test.com/pub/v4.0', tenant_id="foobar", verify=False)
    args = {
        'ip': "1.1.1.1"
    }
    outputs = iot_get_device_by_ip(client, args).outputs

    assert outputs == {"hostname": "00:0a:e4:1c:62:26", "ip_address": "1.1.1.1", "profile_type": "Non_IoT"}
