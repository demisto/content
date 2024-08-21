import json
from Netmiko import cmds_command


def get_test_data():
    with open('test_data/test_data.json') as f:
        return json.loads(f.read())


class MockClient():

    def __init__(self, args):
        self.platform = args["platform"]
        self.hostname = args["hostname"]
        self.username = args["username"]
        self.password = args["password"]
        self.port = args["port"]
        self.keys = args["sshkey"]
        self.net_connect = None

    def cmds(self, require_exit, exit_argument, commands, enable, isConfig):
        return {"Hostname": self.hostname, "DateTimeUTC": "1973-01-01T00:00:59+00:00",
                "Commands": commands, "Output": "root"}


def test_cmds_command():
    args = get_test_data()
    client = MockClient(args)

    result = cmds_command(client, args)

    assert result.outputs["Output"] == args["output"]
    assert result.outputs["Hostname"] == args["hostname"]
    assert result.outputs["Commands"][0] == args["cmds"]
