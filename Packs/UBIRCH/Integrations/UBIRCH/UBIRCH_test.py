from UBIRCH import AUTHENTICITY_TYPE, get_error_definition, create_incidents, AUTHENTICATION_TYPE, LOW_SEVERITY, \
    HIGH_SEVERITY, SEQUENCE_TYPE


def util_load_json(path: str) -> str:
    with open(path, encoding='utf-8') as f:
        return f.read()


def test_get_error_definition() -> None:
    """Test get_severity function.

    Checks the severity is the expected one.

    No mock is needed here.
    """
    incident_auth_1000 = {
        "errorCode": "1000",
        "microservice": "niomon-auth"
    }
    error_definition_auth_1000 = {
        "meaning": "Authentication error: request malformed. Possible missing header and parameters.",
        "severity": LOW_SEVERITY,
        "type": AUTHENTICATION_TYPE
    }
    incident_decoder_1300 = {
        "errorCode": "1300",
        "microservice": "niomon-decoder"
    }
    error_definition_decoder_1300 = {
        "meaning": "Invalid verification: signature verification failed. No public key or integrity is "
                   "compromised.",
        "severity": HIGH_SEVERITY,
        "type": AUTHENTICITY_TYPE
    }
    incident_enricher_0000 = {
        "errorCode": "0000",
        "microservice": "niomon-enricher"
    }
    error_definition_enricher_0000 = {
        "meaning": "Tenant error: the owner of the device does not exist or cannot be acquired (3rd Party).",
        "severity": HIGH_SEVERITY,
        "type": AUTHENTICITY_TYPE
    }
    incident_filter_0000 = {
        "errorCode": "0000",
        "microservice": "filter-service"
    }
    error_definition_filter_0000 = {
        "meaning": "Integrity violation: duplicate hash detected. Possible injection, reply attack, "
                   "or hash collision. ",
        "severity": HIGH_SEVERITY,
        "type": SEQUENCE_TYPE
    }
    error_definition_unknown = {}
    incident_unknown1 = {}
    incident_unknown2 = {
        "errorCode": "1000",
        "microservice": "niomon"
    }
    incident_unknown3 = {
        "errorCode": "5000",
        "microservice": "niomon-auth"
    }

    assert get_error_definition(incident_auth_1000) == error_definition_auth_1000
    assert get_error_definition(incident_decoder_1300) == error_definition_decoder_1300
    assert get_error_definition(incident_enricher_0000) == error_definition_enricher_0000
    assert get_error_definition(incident_filter_0000) == error_definition_filter_0000
    assert get_error_definition(incident_unknown1) == error_definition_unknown
    assert get_error_definition(incident_unknown2) == error_definition_unknown
    assert get_error_definition(incident_unknown3) == error_definition_unknown


def test_create_incidents() -> None:
    """Test create_incidents function.

    Checks the incidents is the expected one.

    No mock is needed here.
    """
    ERROR_MESSAGE = util_load_json('test_data/raw_json_error_message.json')
    incidents = create_incidents(ERROR_MESSAGE)
    assert incidents == INCIDENT_RESPONSE


INCIDENT_RESPONSE = [{
    'name': "Invalid verification: signature verification failed. No public key or integrity is "
            "compromised.",
    'type': "UBIRCH Authenticity",
    'labels': [
        {'type': "requestId", 'value': "ec15d266-5822-4fa5-ba82-64f1653d46a4"},
        {'type': "hwDeviceId", 'value': "ba70ad8b-a564-4e58-9a3b-224ac0f0153f"}
    ],
    'rawJSON': '{"requestId": "ec15d266-5822-4fa5-ba82-64f1653d46a4", "hwDeviceId": '
               '"ba70ad8b-a564-4e58-9a3b-224ac0f0153f", "errorCode": "1300", "error": "SignatureException: Invalid '
               'signature", "microservice": "niomon-decoder", "timestamp": "2021-01-07T18:47:52.025Z"}',
    'details': '{"requestId": "ec15d266-5822-4fa5-ba82-64f1653d46a4", "hwDeviceId": '
               '"ba70ad8b-a564-4e58-9a3b-224ac0f0153f", "errorCode": "1300", "error": "SignatureException: Invalid '
               'signature", "microservice": "niomon-decoder", "timestamp": "2021-01-07T18:47:52.025Z"}',
    'severity': HIGH_SEVERITY
}]
