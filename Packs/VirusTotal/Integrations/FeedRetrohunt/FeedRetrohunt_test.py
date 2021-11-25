from FeedRetrohunt import Client, fetch_indicators_command

MOCK_VT_RESPONSE = [
    {
        "attributes": {
            "sha256": "80db033dfe2b4e966d46a4ceed36e20b98a13891ce364a1308b90da7ad694cf3",
            "tags": [
                "elf"
            ],
            "last_analysis_stats": {
                "harmless": 0,
                "type-unsupported": 15,
                "suspicious": 0,
                "confirmed-timeout": 0,
                "timeout": 0,
                "failure": 0,
                "malicious": 1,
                "undetected": 58
            },
            "unique_sources": 1,
            "first_submission_date": 1628390224,
            "meaningful_name": ".rodata",
            "last_submission_date": 1628390224,
            "type_tag": "elf",
            "ssdeep": "192:YRNBDSQzGNtEhwAowjDll4dFA/4OJaVw:wCQzGNtijowjD4jAQy",
            "times_submitted": 1,
            "size": 8316
        },
        "type": "file",
        "id": "80db033dfe2b4e966d46a4ceed36e20b98a13891ce364a1308b90da7ad694cf3",
        "links": {
            "self": "https://www.virustotal.com/ui/files/80db033dfe2b4e966d46a4ceed36e20b98a13891ce364a1308b90da7ad694cf3"
        },
        "context_attributes": {
            "rule_name": "elf_header_weirdness",
            "match_in_subfile": False
        }
    }
]


def test_fetch_indicators_command(mocker):
    client = Client('https://fake')
    mocker.patch.object(
        client,
        'list_job_matches',
        return_value=MOCK_VT_RESPONSE
    )

    indicators = fetch_indicators_command(client, None, [])

    fields = indicators[0]['fields']

    assert len(indicators) == 1
    assert fields['sha256'] == '80db033dfe2b4e966d46a4ceed36e20b98a13891ce364a1308b90da7ad694cf3'
    assert fields['ssdeep'] == '192:YRNBDSQzGNtEhwAowjDll4dFA/4OJaVw:wCQzGNtijowjD4jAQy'
