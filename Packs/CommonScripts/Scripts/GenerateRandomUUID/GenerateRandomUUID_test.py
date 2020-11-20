from GenerateRandomUUID import generate_random_uuid_command
import uuid

MOCK_UUID = 'dae756a4-304f-42ac-9287-a4546624b3ad'
MOCK_OUTPUTS = {
    "GeneratedUUID": MOCK_UUID
}


def test_generate_random_uuid(mocker):
    mocker.patch('uuid.uuid4', return_value=uuid.UUID(MOCK_UUID))

    result = generate_random_uuid_command()

    assert result.outputs == MOCK_OUTPUTS
