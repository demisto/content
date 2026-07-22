import json


ALERTS = {
    "results": [
        {
            "closed_at": "2020-11-20T01:18:30.224654Z",
            "community_id": 8,
            "count": 0,
            "created_at": "2020-11-19T15:28:03.451476Z",
            "dest_geo_ip": {},
            "dest_ip": "8.8.8.8",
            "dest_port": 1122,
            "dest_subnet_id": None,
            "full_url": None,
            "id": 1,
            "indicator_id": "indicator_id",
            "indicator_loaded": None,
            "observable_id": 4563855,
            "protocol": "TCP",
            "sensor_id": 9185,
            "sensor_name": "Demisto Integration",
            "src_geo_ip": {
                "ip": "8.8.8.8",
                "latitude": 52.2394,
                "timezone": "Europe/Warsaw",
                "longitude": 21.0362,
                "coordinates": [21.0362, 52.2394],
                "country_name": "Poland",
                "country_code2": "PL",
                "country_code3": "PL",
                "continent_code": "EU",
            },
            "src_ip": "8.8.8.8",
            "src_port": 25845,
            "src_subnet_id": None,
            "status": 0,
            "status_updated_at": None,
            "team_id": 5394,
            "title": "ET POLICY MS Terminal Server Root login 1",
            "ts": "2020-11-19T15:25:42.576650+0000",
        },
        {
            "closed_at": "2020-11-18T20:05:58.969797Z",
            "community_id": 8,
            "count": 0,
            "created_at": "2020-11-18T03:14:25.451196Z",
            "dest_geo_ip": {},
            "dest_ip": "8.8.8.8",
            "dest_port": 3389,
            "dest_subnet_id": None,
            "full_url": None,
            "id": 2,
            "indicator_id": "EmergingThreats:Indicator-2012710",
            "indicator_loaded": None,
            "observable_id": 4552422,
            "protocol": "TCP",
            "sensor_id": 9185,
            "sensor_name": "Demisto Integration",
            "src_geo_ip": {
                "ip": "8.8.8.8",
                "latitude": 52.2394,
                "timezone": "Europe/Warsaw",
                "longitude": 21.0362,
                "coordinates": [21.0362, 52.2394],
                "country_name": "Poland",
                "country_code2": "PL",
                "country_code3": "PL",
                "continent_code": "EU",
            },
            "src_ip": "8.8.8.8",
            "src_port": 21364,
            "src_subnet_id": None,
            "status": 0,
            "status_updated_at": None,
            "team_id": 5394,
            "title": "ET POLICY MSS Terminal Server Root login 2",
            "ts": "2020-11-18T02:38:14.828625+0000",
        },
        {
            "closed_at": "2020-11-18T20:05:58.969797Z",
            "community_id": 8,
            "count": 0,
            "created_at": "2020-11-17T03:14:25.451196Z",
            "dest_geo_ip": {},
            "dest_ip": "8.8.8.8",
            "dest_port": 3389,
            "dest_subnet_id": None,
            "full_url": None,
            "id": 3,
            "indicator_id": "EmergingThreats:Indicator-2012710",
            "indicator_loaded": None,
            "observable_id": 4552422,
            "protocol": "TCP",
            "sensor_id": 9185,
            "sensor_name": "Demisto Integration",
            "src_geo_ip": {
                "ip": "8.8.8.8",
                "latitude": 52.2394,
                "timezone": "Europe/Warsaw",
                "longitude": 21.0362,
                "coordinates": [21.0362, 52.2394],
                "country_name": "Poland",
                "country_code2": "PL",
                "country_code3": "PL",
                "continent_code": "EU",
            },
            "src_ip": "8.8.8.8",
            "src_port": 21364,
            "src_subnet_id": None,
            "status": 2,
            "status_updated_at": None,
            "team_id": 5394,
            "title": "ET POLICY MSF Terminal Server Root login 3",
            "ts": "2020-11-18T02:38:14.828625+0000",
        },
    ]
}


def get_alerts_by_status(method, url, params=None, data=None, headers=None):
    """
    The function simulate the http_request method for the test_fetch_alerts_command_by_soc_status.
    The function got the params as the http_request got, and return from the json above only the incidents
    that are in the given status.
    """
    status = params["soc_status"]
    results = {"results": [alert for alert in ALERTS["results"] if int(status) == alert["status"]]}
    return results


def test_fetch_alerts_command_by_soc_status(requests_mock, mocker):
    """
    Given:
        - List of statuses to fetch
    When
        - Running fetch_incident
    Then
        - Verify the returned incidents is with the expected status
    """
    params = {
        "credentials": {"identifier": 1234, "password": 5678},
        "url": "https://api.perch.rocks",
        "soc_status": ["Not Reviewed"],
    }
    mocker.patch("demistomock.params", return_value=params)

    from Perch import fetch_alerts

    mocker.patch("Perch.http_request", side_effect=get_alerts_by_status)

    headers = {"Content-Type": "application/json"}
    last_run = {"time": 1561017202}

    _, incidents = fetch_alerts(last_run, headers)

    assert len(incidents) == 2

    assert incidents[0]["name"] == "Perch Incident: ET POLICY MSS Terminal Server Root login 2"
    assert incidents[1]["name"] == "Perch Incident: ET POLICY MS Terminal Server Root login 1"

    raw_json = json.loads(incidents[0]["rawJSON"])
    assert raw_json["status"] == 0

    raw_json = json.loads(incidents[1]["rawJSON"])
    assert raw_json["status"] == 0
