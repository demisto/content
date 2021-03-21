import pytest
import json
from Perch import fetch_alerts

STATUSES = {
    'Not Reviewed': '0',
    'Investigating': '1',
    'On hold': '2',
    'False Positive': '3',
    'Escalated': '4'
}

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
            "id": 3244985,
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
                "coordinates": [
                    21.0362,
                    52.2394
                ],
                "country_name": "Poland",
                "country_code2": "PL",
                "country_code3": "PL",
                "continent_code": "EU"
            },
            "src_ip": "8.8.8.8",
            "src_port": 25845,
            "src_subnet_id": None,
            "status": 0,
            "status_updated_at": None,
            "team_id": 5394,
            "title": "ET POLICY MS Terminal Server Root login",
            "ts": "2020-11-19T15:25:42.576650+0000"
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
            "id": 3235530,
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
                "coordinates": [
                    21.0362,
                    52.2394
                ],
                "country_name": "Poland",
                "country_code2": "PL",
                "country_code3": "PL",
                "continent_code": "EU"
            },
            "src_ip": "8.8.8.8",
            "src_port": 21364,
            "src_subnet_id": None,
            "status": 0,
            "status_updated_at": None,
            "team_id": 5394,
            "title": "ET POLICY MS Terminal Server Root login",
            "ts": "2020-11-18T02:38:14.828625+0000"
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
            "id": 3235530,
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
                "coordinates": [
                    21.0362,
                    52.2394
                ],
                "country_name": "Poland",
                "country_code2": "PL",
                "country_code3": "PL",
                "continent_code": "EU"
            },
            "src_ip": "8.8.8.8",
            "src_port": 21364,
            "src_subnet_id": None,
            "status": 2,
            "status_updated_at": None,
            "team_id": 5394,
            "title": "ET POLICY MS Terminal Server Root login",
            "ts": "2020-11-18T02:38:14.828625+0000"
        }
    ]
}

def test_fetch_alerts_command_by_soc_status(request_mock):
    request_mock.get('https://api.perch.rocks/v1/alerts', json=json.dumps(ALERTS))
    headers = {'Content-Type': 'application/json'}
    last_run = {'time': 1561017202}
    _, incidents = fetch_alerts(last_run, headers)
    assert len(incidents) == 2

