import demistomock as demisto  # noqa

import ExpanseEnrichAttribution


CURRENT_IP = [
    {"ip": "1.1.1.1", "attr1": "value1"},
    {"ip": "8.8.8.8", "attr1": "value2"},
]

ENRICH_IP = [
    {"ipaddress": "1.1.1.1", "provider": "Cloudflare", "ignored": "ignored-right"},
    {"ipaddress": "8.8.8.4", "provider": "Google"}
]

RESULT_IP = [
    {"ip": "1.1.1.1", "attr1": "value1", "provider": "Cloudflare"},
    {"ip": "8.8.8.8", "attr1": "value2"},
]


CURRENT_DEVICE = [
    {"serial": "serialA", "attr1": "value1"},
    {"serial": "serialB", "attr1": "value2"},
]

ENRICH_DEVICE = [
    {"deviceSerial": "serialA", "location": "unknown", "owner": "lmori"},
    {"deviceSerial": "serialC", "location": "unknown"}
]

RESULT_DEVICE = [
    {"serial": "serialA", "attr1": "value1", "location": "unknown"},
    {"serial": "serialB", "attr1": "value2"},
]


CURRENT_USER = [
    {"username": "fvigo", "attr1": "value1"},
    {"username": "lmori", "attr1": "value2"},
]

ENRICH_USER = [
    {"user": "fvigo", "team": "DevRel", "manager": "unknown"},
    {"user": "ibojer", "team": "DevRel"}
]

RESULT_USER = [
    {"username": "fvigo", "attr1": "value1", "manager": "unknown"},
    {"username": "lmori", "attr1": "value2"},
]


def test_enrich_command():
    ip_result = ExpanseEnrichAttribution.enrich_command({
        'type': 'IP',
        'current': CURRENT_IP,
        'enrich': ENRICH_IP,
        'enrich_key': 'ipaddress',
        'enrich_fields': 'provider'
    })
    assert ip_result.outputs == RESULT_IP
    assert ip_result.outputs_key_field == "ip"
    assert ip_result.outputs_prefix == "Expanse.AttributionIP"

    device_result = ExpanseEnrichAttribution.enrich_command({
        'type': 'Device',
        'current': CURRENT_DEVICE,
        'enrich': ENRICH_DEVICE,
        'enrich_key': 'deviceSerial',
        'enrich_fields': 'location'
    })
    assert device_result.outputs == RESULT_DEVICE
    assert device_result.outputs_key_field == "serial"
    assert device_result.outputs_prefix == "Expanse.AttributionDevice"

    user_result = ExpanseEnrichAttribution.enrich_command({
        'type': 'User',
        'current': CURRENT_USER,
        'enrich': ENRICH_USER,
        'enrich_key': 'user',
        'enrich_fields': 'manager'
    })
    assert user_result.outputs == RESULT_USER
    assert user_result.outputs_key_field == "username"
    assert user_result.outputs_prefix == "Expanse.AttributionUser"
