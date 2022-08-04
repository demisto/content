from FeedRetrohunt import Client, fetch_indicators_command, main
import demistomock as demisto
from unittest.mock import call


MOCK_VT_JOBS = {
    "data": [
        {
            "attributes": {
                "status": "finished",
                "finish_date": 1637921161,
                "rules": "lorem ipsum",
                "num_matches_outside_time_range": 0,
                "corpus": "main",
                "scanned_bytes": 101180105623515,
                "creation_date": 1637919938,
                "num_matches": 10000,
                "progress": 100,
                "notification_email": "",
                "start_date": 1637919943
            },
            "type": "retrohunt_job",
            "id": "Jobidhere-123456789",
            "links": {
                "self": "https://www.virustotal.com/ui/intelligence/retrohunt_jobs/Diviei-1637919938"
            }
        }
    ],
    "links": {
        "self": "https://www.virustotal.com/ui/users/Diviei/retrohunt_jobs?limit=10"
    },
    "meta": {
        "count": 1
    }
}

MOCK_VT_JOB_MATCHES = {
    "data": [
        {
            "attributes": {
                "sha256": "bd59949c6cbe8bd00ad114e2c1c8f4e2e79f90a818d4eddfbd76194e111c9ebb",
                "tags": [
                    "peexe",
                    "overlay",
                    "runtime-modules",
                    "checks-network-adapters",
                    "exploit",
                    "cve-2017-0147",
                    "direct-cpu-clock-access",
                    "detect-debug-environment",
                    "long-sleeps",
                    "checks-disk-space"
                ],
                "vhash": "026046651d6570b8z201cpz31zd025z",
                "last_analysis_stats": {
                    "harmless": 0,
                    "type-unsupported": 4,
                    "suspicious": 0,
                    "confirmed-timeout": 0,
                    "timeout": 2,
                    "failure": 0,
                    "malicious": 56,
                    "undetected": 9
                },
                "unique_sources": 1,
                "first_submission_date": 1637892429,
                "meaningful_name": "5b24a21f6f9f6955b0fbaacaefb8dc9b.virus",
                "last_submission_date": 1637892429,
                "type_tag": "peexe",
                "ssdeep": "49152:QnaMSPbcBVQej/1INRx+TSqTdX1HkQWRdhn:QaPoBhz1aRxcSUDkLdh",
                "times_submitted": 1,
                "size": 2281472
            },
            "type": "file",
            "id": "bd59949c6cbe8bd00ad114e2c1c8f4e2e79f90a818d4eddfbd76194e111c9ebb",
            "links": {
                "self": "https://www.virustotal.com/loremipsum"
            },
            "context_attributes": {
                "rule_name": "wannacry_2",
                "match_in_subfile": False
            }
        }
    ],
    "links": {
        "self": "https://www.virustotal.com/loremipsum",
        "next": "https://www.virustotal.com/loremipsum"
    },
    "meta": {
        "count": 1,
        "cursor": "STI1Ci4="
    }
}


def test_fetch_indicators_command(mocker):
    client = Client('https://fake')
    mocker.patch.object(
        client,
        'fetch_jobs',
        return_value=MOCK_VT_JOBS
    )
    mocker.patch.object(
        client,
        'fetch_job_matches',
        return_value=MOCK_VT_JOB_MATCHES
    )

    indicators = fetch_indicators_command(client, None, [], limit=1)
    fields = indicators[0]['fields']

    assert len(indicators) == 1
    assert fields['sha256'] == 'bd59949c6cbe8bd00ad114e2c1c8f4e2e79f90a818d4eddfbd76194e111c9ebb'
    assert fields['ssdeep'] == '49152:QnaMSPbcBVQej/1INRx+TSqTdX1HkQWRdhn:QaPoBhz1aRxcSUDkLdh'


def test_main_manual_command(mocker):
    params = {
        'tlp_color': None,
        'feedTags': [],
        'credentials': {'password': 'xxx'},
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='vt-retrohunt-get-indicators')
    list_jobs_mock = mocker.patch.object(Client, 'list_job_matches')

    main()

    assert list_jobs_mock.call_args == call(40, '')


def test_main_default_command(mocker):
    params = {
        'tlp_color': None,
        'feedTags': [],
        'credentials': {'password': 'xxx'},
        'limit': 7,
        'filter': 'Wannacry',
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    list_jobs_mock = mocker.patch.object(Client, 'list_job_matches')

    main()

    assert list_jobs_mock.call_args == call(40, '')


def test_main_test_command(mocker):
    params = {
        'credentials': {'password': 'xxx'}
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    list_jobs_mock = mocker.patch.object(Client, 'list_job_matches')

    main()

    assert list_jobs_mock.call_count == 1
