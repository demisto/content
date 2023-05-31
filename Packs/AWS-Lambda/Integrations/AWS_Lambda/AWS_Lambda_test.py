import pytest
from AWS_Lambda import get_policy_command


class MockClient:
    def get_policy(self) -> None:
        return


@pytest.mark.parametrize(
    "test_data, excepted_data",
    [
        (
            {
                'Policy': '{"Version":"0000-00-00","Id":"dummy","Statement":[{"Sid":"dummy","Effect":"Allow","Principal":{"dummy":"dummy:dummy"},"Action":"lambda:InvokeFunction","Resource":"dummy:dummy:dummy:country:0000000:function:dummy-function:0"}]}',
                'RevisionId': '00000-00000-00000-00000-00000',
            },
            {
                'Policy': {"Version": "0000-00-00", "Id": "dummy", "Statement": [{"Sid": "dummy", "Effect": "Allow", "Principal": {"dummy": "dummy:dummy"}, "Action": "lambda:InvokeFunction", "Resource": "dummy:dummy:dummy:country:0000000:function:dummy-function:0"}]},
                'RevisionId': '00000-00000-00000-00000-00000',
            }
        )
    ]
)
def test_get_policy_command(mocker, test_data: dict, excepted_data: dict):
    client = MockClient()
    mocker.patch.object(client, "get_policy", return_value=test_data)

    res = get_policy_command(args={"functionName": "test"}, aws_client=client)
    assert res.outputs == excepted_data
