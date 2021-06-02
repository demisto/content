from AWSGuardDuty import get_members

RESPONSE = {
    'Members': [
        {},
        {
            'AccountId': 1,
            'DetectorId': 1,
            'MasterId': 1,
        }
    ]
}


class Client:
    @staticmethod
    def get_members(DetectorId, AccountIds):
        return RESPONSE


def test_get_members(mocker):
    client = Client
    mocker.patch('AWSGuardDuty.aws_session', return_value=client)
    members_res = get_members({})
    assert members_res['Contents'] == [{'AccountId': 1, 'DetectorId': 1, 'MasterId': 1}]
