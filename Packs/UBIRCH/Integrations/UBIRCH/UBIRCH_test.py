import io
from UBIRCH import create_incidents, HIGH_SEVERITY


def util_load_json(path: str) -> str:
    with io.open(path, mode='r', encoding='utf-8') as f:
        return f.read()


def test_create_incidents() -> None:
    """Test create_incidents function.

    Checks the output of the function with the expected output.

    No mock is needed here.
    """
    ERROR_MESSAGE = util_load_json('test_data/raw_json_error_message.json')
    incidents = create_incidents(ERROR_MESSAGE)
    assert incidents == INCIDENT_RESPONSE


INCIDENT_RESPONSE = [{
    'name': "SignatureException: Invalid signature",
    'type': "1300",
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
