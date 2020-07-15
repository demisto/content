import iot_alert_post_processing
from iot_alert_post_processing import iot_resolve_alert

_INCIDENT = {
    'id': 28862,
    'labels': [
        {
            'type': 'id',
            'value': '5ed08587fe03d30d000016e8'
        }
    ]
}


def test_iot_resolve_alert(monkeypatch):
    monkeypatch.setattr(iot_alert_post_processing, "_get_incident", lambda: _INCIDENT)
    iot_resolve_alert()
