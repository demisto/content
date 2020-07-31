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

_CONFIG_WITHOUT_DEFAULT = {
    "devices": [
        {
            "device_id": "Audio Streaming|Profusion Media Player.*",
            "owner": "IT_AUDIO_VIDEO"
        }
    ],
    "alerts": [
        {
            "iot_raw_type": "IoT Vulnerability",
            "raci": {
                "r": "IOT_OWNER",
                "i": ["INFOSEC", "SOC"]
            }
        }
    ],
    "groups": {}
}

_CONFIG_WITH_DEFAULT = {
    "devices": [
        {
            "device_id": "Audio Streaming|Profusion Media Player.*",
            "owner": "IT_AUDIO_VIDEO"
        }
    ],
    "alerts": [
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
        }
    }
}


def test_iot_get_raci_normal(monkeypatch):
    """
    Scenario: getting the raci result in a normal case

    Given
    - A device with an IoT alert named "DOUBLEPULSAR Backdoor traffic"

    When
    - Calculating the RACI model result

    Then
    - Ensure the correct RACI model is calculated
    """
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)

    outputs = get_raci({
        'alert_name': 'DOUBLEPULSAR Backdoor traffic',
        'raw_type': 'IoT Alert',
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


def test_iot_get_raci_no_default_email(monkeypatch):
    """
    Scenario: checking the responsiblie email is None if a default email is missing in IOT_CONFIG

    Given
    - A device with an IoT Vulnerability

    When
    - Calculating the RACI model result

    Then
    - Ensure the r_email is None even though r is not None
    """
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG_WITHOUT_DEFAULT)

    outputs = get_raci({
        'alert_name': '',
        'raw_type': 'IoT Vulnerability',
        'category': 'Audio Streaming',
        'profile': 'Profusion Media Player'
    }).outputs
    assert outputs == {
        'owner': 'IT_AUDIO_VIDEO',
        'r': 'IT_AUDIO_VIDEO',
        'r_email': None,
        'r_snow': None,
        'i': 'INFOSEC, SOC',
        'i_email': None
    }


def test_iot_get_raci_default_email(monkeypatch):
    """
    Scenario: checking the responsiblie email is the default one specified in IOT_CONFIG

    Given
    - A device with an IoT Vulnerability

    When
    - Calculating the RACI model result

    Then
    - Ensure the r_email is the default email in IOT_CONFIG
    """
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG_WITH_DEFAULT)

    outputs = get_raci({
        'alert_name': '',
        'raw_type': 'IoT Vulnerability',
        'category': 'Audio Streaming',
        'profile': 'Profusion Media Player'
    }).outputs
    assert outputs == {
        'owner': 'IT_AUDIO_VIDEO',
        'r': 'IT_AUDIO_VIDEO',
        'r_email': 'default@example.com',
        'r_snow': None,
        'i': 'INFOSEC, SOC',
        'i_email': 'default@example.com, default@example.com'
    }


def test_iot_get_raci_no_name_regex(monkeypatch):
    """
    Scenario: checking the IOT_CONFIG is working without the name regex in the "alerts" section of the JSON

    Given
    - A device with an IoT Vulnerability

    When
    - Calculating the RACI model result

    Then
    - Ensure the r is correct
    """
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)

    outputs = get_raci({
        'alert_name': 'FooBar',
        'raw_type': 'IoT Vulnerability',
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
        'alert_name': 'FooBar',
        'raw_type': 'IoT Vulnerability',
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
    """
    Scenario: checking the ServiceNow config is returned from the IOT_CONFIG

    Given
    - A device with an IoT Vulnerability

    When
    - Calculating the RACI model result

    Then
    - Ensure the r_snow is returned
    """
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)
    outputs = get_raci({
        'alert_name': 'FooBar',
        'raw_type': 'IoT Vulnerability',
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
    """
    Scenario: checking the case of missing the group defined in IOT_CONFIG

    Given
    - A device with an owner WPR_SECURITY, and its email is not listed

    When
    - Calculating the RACI model result

    Then
    - Ensure the code is still returning the raci
    """
    monkeypatch.setattr(iot_get_raci, 'get_iot_config', lambda x: _CONFIG)
    outputs = get_raci({
        'alert_name': 'FooBar',
        'raw_type': 'IoT Alert',
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
