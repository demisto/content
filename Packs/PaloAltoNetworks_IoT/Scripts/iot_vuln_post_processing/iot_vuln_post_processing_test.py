import iot_vuln_post_processing
from iot_vuln_post_processing import iot_resolve_vuln

_INCIDENT = {
    'id': 28862,
    'labels': [
        {
            'type': 'zb_ticketid',
            'value': 'vuln-99124066'
        },
        {
            'type': 'vulnerability_name',
            'value': 'SMB v1 Usage'
        }
    ]
}


def test_iot_resolve_alert(monkeypatch):
    monkeypatch.setattr(iot_vuln_post_processing, "_get_incident", lambda: _INCIDENT)
    iot_resolve_vuln()
