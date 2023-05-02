class MockClient:
    
    def cmds(self, **kwargs):
        return {"Hostname": "localhost", "DateTimeUTC": "1973-01-01T00:00:59+00:00",
                "Command": "who", "Output": "root"}

def test_cmds_command():
    client = MockClient()
    
    expected_results = {"Hostname": "localhost", "DateTimeUTC": "1973-01-01T00:00:59+00:00",
                "Command": "who", "Output": "root"}
    
    assert client.cmds() == {"Hostname": "localhost", "DateTimeUTC": "1973-01-01T00:00:59+00:00",
                "Command": "who", "Output": "root"}