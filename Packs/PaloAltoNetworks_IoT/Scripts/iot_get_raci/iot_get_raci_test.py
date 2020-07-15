import iot_get_raci
from iot_get_raci import get_raci


_CONFIG = {
    "devices": [
        {
            "device_id": "Audio Streaming|Profusion Media Player.*",
            "owner": "IT_AUDIO_VIDEO"
        },
        {
            "device_id": "Camera|Avigilon Camera.*",
            "owner": "WPR_SECURITY"
        },
        {
            "device_id": "category|profile|vendor|model",
            "owner": "IT_AUDIO_VIDEO"
        }
    ],
    "alerts": [
        {
            "iot_raw_type": "IoT Alert",
            "name_regex": [
                "DOUBLEPULSAR.+",
                "ETERNALBLUE.+",
                "ETERNALROMANCE.+",
                "Excessive domain lookup failures with DGA usage",
                ".+flagged Internet host detected",
                "NETBIOS SMB ADMIN.+",
                "NotPetya.+",
                "PII transmission anomaly",
                "Remote access.+Windows Security Account Manager.+",
                "SamSam Ransomware SMB.+",
                "Win.Ransomware.+"
            ],
            "raci": {
                "r": "SOC",
                "i": ["IOT_OWNER"]
            }
        },
        {
            "iot_raw_type": "IoT Alert",
            "name_regex": [
                "Excessive .+ server port range detected",
                ".+ external SMB port connections",
                "Inbound .+ connections from Internet",
                "Uncontrolled Internet access"
            ],
            "raci": {
                "r": "INFOSEC",
                "i": ["IOT_OWNER", "SOC"]
            }
        },
        {
            "iot_raw_type": "IoT Vulnerability",
            "raci": {
                "r": "IOT_OWNER",
                "i": ["INFOSEC", "SOC"]
            }
        }
    ],
    "groups": {
        "DEFAULT": {
            "email": "default@example.com"
        },
        "INFOSEC": {
            "email": "infosec@example.com"
        },
        "IT_AUDIO_VIDEO": {
            "email": "itav@example.com",
            "snow": {
                "table": "incident",
                "fields": {
                    "assignment_group": "itav_group_snow_id"
                },
                "custom_fields": {
                    "u_resolver_department": "IT",
                    "u_category_5": "iot_category_snow_id"
                }
            }
        },
        "SOC": {
            "email": "soc@example.com"
        },
        "WPR_SECURITY": {
            "email": "wpr_security@example.com"
        }
    }
}


def test_iot_get_raci_normal(monkeypatch):
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)

    outputs = get_raci({
        'alertName': 'DOUBLEPULSAR Backdoor traffic',
        'rawType': 'IoT Alert',
        'category': 'Audio Streaming',
        'profile': 'Profusion Media Player'
    }).outputs
    assert outputs == {
        'owner': 'IT_AUDIO_VIDEO',
        'r': 'SOC',
        'r_email': 'soc@example.com',
        'r_snow': None,
        'i': 'IT_AUDIO_VIDEO',
        'i_email': 'itav@example.com'
    }


def test_iot_get_raci_no_name_regex(monkeypatch):
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)

    outputs = get_raci({
        'alertName': 'FooBar',
        'rawType': 'IoT Vulnerability',
        'category': 'Foo'
    }).outputs
    assert outputs == {
        'owner': None,
        'r': None,
        'r_email': None,
        'r_snow': None,
        'i': 'INFOSEC, SOC',
        'i_email': 'infosec@example.com, soc@example.com'
    }

    outputs = get_raci({
        'alertName': 'FooBar',
        'rawType': 'IoT Vulnerability',
        'category': 'Camera',
        'profile': 'Avigilon Camera'
    }).outputs
    assert outputs == {
        'owner': 'WPR_SECURITY',
        'r': 'WPR_SECURITY',
        'r_email': 'wpr_security@example.com',
        'r_snow': None,
        'i': 'INFOSEC, SOC',
        'i_email': 'infosec@example.com, soc@example.com'
    }


def test_iot_snow(monkeypatch):
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)
    outputs = get_raci({
        'alertName': 'FooBar',
        'rawType': 'IoT Vulnerability',
        'category': 'Audio Streaming',
        'profile': 'Profusion Media Player'
    }).outputs
    assert outputs == {
        'owner': 'IT_AUDIO_VIDEO',
        'r': 'IT_AUDIO_VIDEO',
        'r_email': 'itav@example.com',
        'r_snow': {
            'custom_fields': 'u_resolver_department=IT;u_category_5=iot_category_snow_id',
            'fields': 'assignment_group=itav_group_snow_id',
            'table': 'incident'
        },
        'i': 'INFOSEC, SOC',
        'i_email': 'infosec@example.com, soc@example.com'
    }


def test_iot_get_raci_no_raci(monkeypatch):
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)
    outputs = get_raci({
        'alertName': 'FooBar',
        'rawType': 'IoT Alert',
        'category': 'Camera',
        'profile': 'Avigilon Camera'
    }).outputs
    assert outputs == {
        'owner': 'WPR_SECURITY',
        'r': None,
        'r_email': None,
        'r_snow': None,
        'i': None,
        'i_email': None
    }
