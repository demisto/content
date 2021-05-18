import pytest


def load_json_data(path):
    import json

    with open(path, 'r') as f:
        return json.load(f)


TEST_VECTORS = [
    ('test_data/ca.json', 'test_data/ca_result.json'),
    ('test_data/messy.json', 'test_data/messy_result.json'),
]


@pytest.mark.parametrize("input, expected", TEST_VECTORS)
def test_case(mocker, input, expected):
    def executeCommand(command, args):
        if command == 'CertificateExtract':
            return [{'EntryContext': load_json_data(input)}]

        elif command == 'findIndicators':
            return [{'Contents': [{'CustomFields': {'pem': 'fake-pem'}, 'value': 'fake-sha256'}]}]

        elif command == 'setIndicator':
            return None

        else:
            raise ValueError(f"Unknown command: {command}")

    ec_mock = mocker.patch('demistomock.executeCommand', side_effect=executeCommand)

    from CertificateReputation import certificate_reputation_command

    context = certificate_reputation_command({'input': 'fake-sha256'})
    expected_result, expected_checks = load_json_data(expected)

    assert context['EntryContext'] == expected_result
    for ec in expected_checks:
        ec_mock.assert_any_call(
            "setIndicator", {
                'certificatevalidationchecks': ec, 'value': 'fake-sha256', 'type': 'Certificate'})
