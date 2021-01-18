from UBIRCH import create_incidents


def util_load_bin(path: str):
    with open(path, 'rb') as f:
        return f.read()


def test_create_incidents():
    """Test create_incidents function.

    Checks the output of the function with the expected output.

    No mock is needed here.
    """
    RAW_BINARY_MESSAGE = util_load_bin('test_data/raw_subscribe_message.bin')
    incidents = create_incidents(RAW_BINARY_MESSAGE)
    assert incidents == INCIDENT_RESPONSE


INCIDENT_RESPONSE = [{
    "name": "SignatureException: Invalid signature",
    "labels": [
        {"type": "requestId", "value": "ec15d266-5822-4fa5-ba82-64f1653d46a4"},
        {"type": "hwDeviceId", "value": "ba70ad8b-a564-4e58-9a3b-224ac0f0153f"}
    ],
    "rawJSON": '{"requestId": "ec15d266-5822-4fa5-ba82-64f1653d46a4", "hwDeviceId": '
               '"ba70ad8b-a564-4e58-9a3b-224ac0f0153f", "error": "SignatureException: Invalid signature", '
               '"microservice": "niomon-decoder", "timestamp": "2021-01-07T18:47:52.025Z"}',
    "details": '{"requestId": "ec15d266-5822-4fa5-ba82-64f1653d46a4", "hwDeviceId": '
               '"ba70ad8b-a564-4e58-9a3b-224ac0f0153f", "error": "SignatureException: Invalid signature", '
               '"microservice": "niomon-decoder", "timestamp": "2021-01-07T18:47:52.025Z"}'}]
