from mypy_boto3_ssm.client import SSMClient
from AWSSystemManager import add_tags_to_resource_command


class MockClient(SSMClient):
    def __init__(
        self,
    ):
        pass

    def add_tags_to_resource(self, **kwargs):
        pass


# def util_load_json(path):
#     with open(path, encoding="utf-8") as f:
#         return json.loads(f.read())


def test_add_tags_to_resource_command_success(mocker):
    args = {
        "resource_type": "test_type",
        "resource_id": "test_id",
        "tag_key": "test_key",
        "tag_value": "test_value",
    }
    mocker.patch.object(MockClient(), "add_tags_to_resource", return_value={})
    res = add_tags_to_resource_command(MockClient(), args)
    assert res.readable_output == "Tags added to resource test_id successfully."
