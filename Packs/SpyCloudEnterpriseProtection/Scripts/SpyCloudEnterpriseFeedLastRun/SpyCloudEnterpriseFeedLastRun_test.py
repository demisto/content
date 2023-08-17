import SpyCloudEnterpriseFeedLastRun


def test_main(monkeypatch):
    def mock_executeCommand(command, args):
        return [
            {
                "Contents": [
                    {"Contents": {"data": [{"created": "2022-09-27T18:00:00.000"}]}}
                ]
            }
        ]

    monkeypatch.setattr(
        SpyCloudEnterpriseFeedLastRun.demisto, "executeCommand", mock_executeCommand
    )
    SpyCloudEnterpriseFeedLastRun.main()
