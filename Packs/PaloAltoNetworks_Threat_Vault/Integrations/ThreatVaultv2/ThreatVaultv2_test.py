from CommonServerPython import *
import pytest

from ThreatVaultv2 import (
    Client,
    threat_batch_search_command,
    release_note_get_command,
    threat_signature_get_command,
    threat_search_command,
    file_command,
    cve_command,
    pagination,
    parse_resp_by_type,
    resp_to_hr,
    parse_date,
    reputation_type_to_hr,
    ip_command
)


def _open_json_file(path):
    with open(path) as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "command, demisto_args, expected_results",
    [
        (
            threat_batch_search_command,
            {"id": "123", "md5": "52463745"},
            "Only one of the following can be used at a time: id, md5, sha256, name",
        ),
        (
            threat_batch_search_command,
            {},
            "Only one of the following can be used at a time: id, md5, sha256, name",
        ),
        (release_note_get_command, {}, "The version argument is required"),
        (
            threat_signature_get_command,
            {},
            "One of following arguments is required: signature_id, sha256, md5",
        ),
        (
            threat_search_command,
            {},
            (
                "One of following arguments is required: cve, vendor, signature-name, type,"
                " from-release-version, from-release-date, release-date, release-version"
            ),
        ),
        (
            threat_search_command,
            {"cve": "test", "from-release-date": "2000-09-09"},
            (
                "When using a release date range in a query, it must be used with the following two arguments: "
                "from-release-date, to-release-date"
            ),
        ),
        (
            threat_search_command,
            {"cve": "test", "from-release-version": "2000-09-09"},
            (
                "When using a release version range in a query, it must be used with the following two arguments: "
                "from-release-version, to-release-version"
            ),
        ),
        (
            threat_search_command,
            {"cve": "test", "release-date": "2000-09-09", "release-version": "test"},
            (
                "There can only be one argument from the following list in the command: "
                "release-date, release-version"
            ),
        ),
        (
            threat_search_command,
            {
                "cve": "test",
                "release-date": "2000-09-09",
                "from-release-date": "2000-09-09",
                "to-release-date": "2000-09-09",
            },
            (
                "When using a release version range or a release date range in a query"
                "it is not possible to use with the following arguments: release-date, release-version"
            ),
        ),
        (
            threat_search_command,
            {
                "cve": "test",
                "from-release-version": "test",
                "to-release-version": "test",
                "from-release-date": "2000-09-09",
                "to-release-date": "2000-09-09",
            },
            "from-release-version and from-release-date cannot be used together.",
        ),
    ],
)
def test_commands_failure(command, demisto_args, expected_results):

    client = ""

    with pytest.raises(Exception) as e:
        command(client, demisto_args)
    assert expected_results in str(e)


@pytest.mark.parametrize(
    "cmd, demisto_args, expected_readable_output, expected_indicator",
    [
        (
            file_command,
            {"file": "1234567890"},
            "Hash 1234567890 antivirus reputation is unknown to Threat Vault.",
            Common.File,
        ),
        (
            cve_command,
            {"cve": "1234567890"},
            "CVE 1234567890 vulnerability reputation is unknown to Threat Vault.",
            None,
        ),
        (
            threat_signature_get_command,
            {"signature_id": "123456"},
            "123456 reputation is unknown to Threat Vault.",
            None,
        ),
        (
            release_note_get_command,
            {"type": "123456", "version": "2222"},
            "Release note 2222 was not found.",
            None,
        ),
        (
            threat_search_command,
            {"cve": "123"},
            "There is no information for your search.",
            None,
        ),
        (
            threat_batch_search_command,
            {"id": "3333333333"},
            "There is no information about the ['3333333333']",
            None,
        ),
        (
            threat_batch_search_command,
            {"md5": "123,7564"},
            "There is no information about the ['123', '7564']",
            None,
        ),
    ],
)
def test_commands_with_not_found(
    mocker, cmd, demisto_args, expected_readable_output, expected_indicator
):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )

    class MockException:
        def __init__(self, status_code) -> None:
            self.status_code = status_code

    mocker.patch.object(
        client,
        "antivirus_signature_get_request",
        side_effect=DemistoException(message="test", res=MockException(404)),
    )
    mocker.patch.object(
        client,
        "release_notes_get_request",
        side_effect=DemistoException(message="test", res=MockException(404)),
    )
    mocker.patch.object(
        client,
        "threat_search_request",
        side_effect=DemistoException(message="test", res=MockException(404)),
    )
    mocker.patch.object(
        client,
        "threat_batch_search_request",
        side_effect=DemistoException(message="test", res=MockException(404)),
    )

    results = cmd(client, demisto_args)

    if expected_indicator:
        assert isinstance(results[0].indicator, expected_indicator)
    if isinstance(results, list):
        assert len(results) == 1
        assert results[0].readable_output == expected_readable_output
    else:
        assert results.readable_output == expected_readable_output


@pytest.mark.parametrize(
    "page, page_size, limit, expected_result",
    [(5, 100, None, (500, 100)), (None, None, 100, (0, 100))],
)
def test_pagination(page, page_size, limit, expected_result):

    results = pagination(page, page_size, limit)

    assert len(results) == 2
    assert results[0] == expected_result[0]
    assert results[1] == expected_result[1]


@pytest.mark.parametrize(
    "resp, expanded, expected_results",
    [
        (
            {
                "data": {
                    "vulnerability": [
                        {"id": "test", "name": "test", "description": "test"}
                    ]
                }
            },
            True,
            ["ThreatVault.Vulnerability"],
        ),
        (
            {
                "data": {
                    "antivirus": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                    "vulnerability": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                }
            },
            False,
            ["ThreatVault.Antivirus", "ThreatVault.Vulnerability"],
        ),
        (
            {
                "data": {
                    "antivirus": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                    "vulnerability": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                    "fileformat": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                    "spyware": [{"id": "test", "name": "test", "description": "test"}],
                }
            },
            False,
            [
                "ThreatVault.Antivirus",
                "ThreatVault.Spyware",
                "ThreatVault.Vulnerability",
                "ThreatVault.Fileformat",
            ],
        ),
        (
            {
                "data": {
                    "dns": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                    "rtdns": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                    "fileformat": [
                        {"id": "test", "name": "test", "description": "test"}
                    ],
                    "spywarec2": [{"id": "test", "name": "test", "description": "test"}],
                }
            },
            False,
            [
                "ThreatVault.Fileformat",
                "ThreatVault.DNS",
                "ThreatVault.RTDNS",
                "ThreatVault.SpywareC2",
            ],
        ),
    ],
)
def test_parse_resp_by_type(mocker, resp, expanded, expected_results):

    mocker.patch("ThreatVaultv2.resp_to_hr", return_value={})

    results = parse_resp_by_type(response=resp, expanded=expanded)
    for i in range(len(expected_results)):
        assert results[i].outputs_prefix == expected_results[i]


RESP_TO_HR_ARGS = [
    (
        {
            "id": "test",
            "name": "test",
            "description": "test",
        },
        "vulnerability",
        False,
        14,
        (("ThreatID", "test"), ("Description", "test"), ("Name", "test")),
    ),
    (
        {
            "id": "test",
            "name": "test",
            "description": "test",
        },
        "fileformat",
        False,
        13,
        (("ThreatID", "test"), ("Description", "test"), ("Name", "test")),
    ),
    (
        {
            "signatures": {"antivirus": [{"status": "test"}]},
            "filetype": "test",
            "size": "test",
        },
        "file",
        False,
        6,
        (("Status", "test"), ("FileType", "test"), ("Size", "test")),
    ),
    (
        {
            "signatures": {
                "antivirus": [
                    {
                        "id": "test",
                        "name": "test",
                        "description": "test",
                    }
                ]
            },
        },
        "file",
        True,
        15,
        (("SignatureId", "test"), ("Description", "test"), ("Signature Name", "test")),
    ),
    (
        {
            "id": "test",
            "name": "test",
            "description": "test",
        },
        "antivirus",
        False,
        9,
        (("ThreatID", "test"), ("Description", "test"), ("Name", "test")),
    ),
    (
        {
            "id": "test",
            "name": "test",
            "description": "test",
        },
        "spyware",
        False,
        12,
        (("ThreatID", "test"), ("Description", "test"), ("Name", "test")),
    ),
    (
        {
            "id": "test",
            "name": "test",
            "description": "test",
        },
        "dns",
        False,
        10,
        (("ThreatID", "test"), ("Description", "test"), ("Name", "test")),
    ),
    (
        {
            "id": "test",
            "name": "test",
            "description": "test",
        },
        "rtdns",
        False,
        10,
        (("ThreatID", "test"), ("Description", "test"), ("Name", "test")),
    ),
    (
        {
            "id": "test",
            "name": "test",
            "description": "test",
        },
        "spywarec2",
        False,
        10,
        (("ThreatID", "test"), ("Description", "test"), ("Name", "test")),
    ),
    (
        {
            "release_version": "test",
            "content_version": "test",
            "release_notes": {"spyware": {"disabled": "test"}},
        },
        "release_notes",
        False,
        14,
        (
            ("Release version", "test"),
            ("Content version", "test"),
            ("Disabled Spyware", "test"),
        ),
    ),
    (
        {
            "test": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        "test",
        False,
        0,
        (),
    ),
]


@pytest.mark.parametrize(
    "resp, type_, expanded, expected, expected_content", RESP_TO_HR_ARGS
)
def test_resp_to_hr(resp, type_, expanded, expected, expected_content):

    result = resp_to_hr(resp, type_, expanded)
    assert len(result.keys()) == expected
    for key, value in expected_content:
        assert key in result
        assert result[key] == value


@pytest.mark.parametrize(
    "args, response, expected_results",
    [
        pytest.param(
            {"ip": "8.8.8.8"},
            {
                "success": "true",
                "link": {
                    "next": "null",
                    "previous": "null",
                },
                "count": 1,
                "data": [
                    {
                        "ipaddr": "8.8.8.8",
                        "name": "null",
                        "status": "N/A",
                        "release": {},
                        "geo": "US (United States of America)",
                        "asn": "15169 (GOOGLE, US)",
                    }
                ],
                "message": "Successful",
            },
            _open_json_file("test_data/single_ip_result.json"),
            id="Single IP test",
        ),
        pytest.param(
            {"ip": "8.8.8.8, 9.9.9.9"},
            {
                "success": "true",
                "link": {"next": "null", "previous": "null"},
                "count": 2,
                "data": [
                    {
                        "ipaddr": "8.8.8.8",
                        "name": "null",
                        "status": "N/A",
                        "release": {},
                        "geo": "US (United States of America)",
                        "asn": "15169 (GOOGLE, US)",
                    },
                    {
                        "ipaddr": "9.9.9.9",
                        "name": "null",
                        "status": "N/A",
                        "release": {},
                        "geo": "CH (Switzerland)",
                        "asn": "19281 (QUAD9-AS-1, CH)",
                    },
                ],
                "message": "Successful",
            },
            _open_json_file("test_data/ip_batch_results.json"),
            id="IP Batch",
        ),
    ]
)
def test_ip_command(mocker, args, response, expected_results):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )

    mocker.patch.object(
        client, "ip_feed_get_request", return_value=response
    )

    mocker.patch.object(
        client, "ip_feed_batch_post_request", return_value=response
    )

    results = ip_command(client, args)
    results = [result.to_context() for result in results]

    assert results == expected_results


FILE_COMMAND_ARGS = [
    (
        {"file": "xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx"},
        [
            {
                "data": {
                    "fileinfo": [
                        {
                            "filetype": "test",
                            "sha256": "xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx",
                            "sha1": "test",
                            "md5": "test",
                            "size": "test",
                            "type": "test",
                            "family": "test",
                            "platform": "test",
                            "wildfire_verdict": "unknown",
                            "create_time": "test",
                            "signatures": {
                                "antivirus": [
                                    {
                                        "name": "test",
                                        "severity": "test",
                                        "type": "test",
                                        "subtype": "test",
                                        "description": "test",
                                        "action": "",
                                        "id": "test",
                                        "create_time": "test",
                                        "status": "test",
                                        "related_sha256_hashes": ["test"],
                                        "release": {
                                            "antivirus": {
                                                "first_release_version": "test",
                                                "first_release_time": "test",
                                                "last_release_version": "test",
                                                "last_release_time": "test",
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        ],
        {
            "sha256": [
                "xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx"
            ],
            "md5": ["test"],
            "readable_output": [
                "### Antivirus Reputation for hash: xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx"
            ],
        },
    ),
    (
        {"file": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        [
            {
                "data": {
                    "fileinfo": [
                        {
                            "filetype": "test",
                            "sha256": "test",
                            "sha1": "test",
                            "md5": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                            "size": "test",
                            "type": "test",
                            "family": "test",
                            "platform": "test",
                            "wildfire_verdict": "unknown",
                            "create_time": "test",
                            "signatures": {
                                "antivirus": [
                                    {
                                        "name": "test",
                                        "severity": "test",
                                        "type": "test",
                                        "subtype": "test",
                                        "description": "test",
                                        "action": "",
                                        "id": "test",
                                        "create_time": "test",
                                        "status": "test",
                                        "related_sha256_hashes": ["test"],
                                        "release": {
                                            "antivirus": {
                                                "first_release_version": "test",
                                                "first_release_time": "test",
                                                "last_release_version": "test",
                                                "last_release_time": "test",
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        ],
        {
            "sha256": ["test"],
            "md5": ["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
            "readable_output": [
                "### Antivirus Reputation for hash: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
            ],
        },
    ),
    (
        {
            "file": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx"
        },
        [
            {
                "data": {
                    "fileinfo": [
                        {
                            "filetype": "test",
                            "sha256": "test",
                            "sha1": "test",
                            "md5": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                            "size": "test",
                            "type": "test",
                            "family": "test",
                            "platform": "test",
                            "wildfire_verdict": "unknown",
                            "create_time": "test",
                            "signatures": {
                                "antivirus": [
                                    {
                                        "name": "test",
                                        "severity": "test",
                                        "type": "test",
                                        "subtype": "test",
                                        "description": "test",
                                        "action": "",
                                        "id": "test",
                                        "create_time": "test",
                                        "status": "test",
                                        "related_sha256_hashes": ["test"],
                                        "release": {
                                            "antivirus": {
                                                "first_release_version": "test",
                                                "first_release_time": "test",
                                                "last_release_version": "test",
                                                "last_release_time": "test",
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
            {
                "data": {
                    "fileinfo": [
                        {
                            "filetype": "test",
                            "sha256": "xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx",
                            "sha1": "test",
                            "md5": "test",
                            "size": "test",
                            "type": "test",
                            "family": "test",
                            "platform": "test",
                            "wildfire_verdict": "unknown",
                            "create_time": "test",
                            "signatures": {
                                "antivirus": [
                                    {
                                        "name": "test",
                                        "severity": "test",
                                        "type": "test",
                                        "subtype": "test",
                                        "description": "test",
                                        "action": "",
                                        "id": "test",
                                        "create_time": "test",
                                        "status": "test",
                                        "related_sha256_hashes": ["test"],
                                        "release": {
                                            "antivirus": {
                                                "first_release_version": "test",
                                                "first_release_time": "test",
                                                "last_release_version": "test",
                                                "last_release_time": "test",
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        ],
        {
            "sha256": [
                "test",
                "xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx",
            ],
            "md5": ["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "test"],
            "readable_output": [
                "### Antivirus Reputation for hash: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "### Antivirus Reputation for hash: xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx",
            ],
        },
    ),
]


@pytest.mark.parametrize("args, resp, expected_results", FILE_COMMAND_ARGS)
def test_file_command(mocker, args, resp, expected_results):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )
    mocker.patch.object(client, "antivirus_signature_get_request", side_effect=resp)
    results = file_command(client, args)

    for i in range(len(results)):
        assert results[i].indicator.sha256 == expected_results["sha256"][i]
        assert results[i].indicator.md5 == expected_results["md5"][i]
        assert expected_results["readable_output"][i] in results[i].readable_output


CVE_COMMAND_ARGS = [
    (
        {"cve": "CVE-2011-1272"},
        [
            {
                "data": {
                    "vulnerability": [
                        {
                            "id": "test",
                            "name": "test",
                            "description": "test",
                            "category": "test",
                            "min_version": "test",
                            "max_version": "",
                            "severity": "test",
                            "default_action": "test",
                            "cve": ["CVE-2011-1272"],
                            "vendor": ["test"],
                            "reference": ["test"],
                            "status": "test",
                            "details": {"change_data": "test"},
                            "ori_release_version": "test",
                            "latest_release_version": "test",
                            "ori_release_time": "test",
                            "latest_release_time": "test",
                        }
                    ]
                }
            }
        ],
        {
            "id": ["CVE-2011-1272"],
            "readable_output": ["CVE Vulnerability Reputation: CVE-2011-1272"],
        },
    ),
    (
        {"cve": "CVE-2011-1272,CVE-2011-1272"},
        [
            {
                "data": {
                    "vulnerability": [
                        {
                            "id": "test",
                            "name": "test",
                            "description": "test",
                            "category": "test",
                            "min_version": "test",
                            "max_version": "",
                            "severity": "test",
                            "default_action": "test",
                            "cve": ["CVE-2011-1272"],
                            "vendor": ["test"],
                            "reference": ["test"],
                            "status": "test",
                            "details": {"change_data": "test"},
                            "ori_release_version": "test",
                            "latest_release_version": "test",
                            "ori_release_time": "test",
                            "latest_release_time": "test",
                        }
                    ]
                }
            },
            {
                "data": {
                    "vulnerability": [
                        {
                            "id": "test",
                            "name": "test",
                            "description": "test",
                            "category": "test",
                            "min_version": "test",
                            "max_version": "",
                            "severity": "test",
                            "default_action": "test",
                            "cve": ["CVE-2011-1272"],
                            "vendor": ["test"],
                            "reference": ["test"],
                            "status": "test",
                            "details": {"change_data": "test"},
                            "ori_release_version": "test",
                            "latest_release_version": "test",
                            "ori_release_time": "test",
                            "latest_release_time": "test",
                        }
                    ]
                }
            },
        ],
        {
            "id": ["CVE-2011-1272", "CVE-2011-1272"],
            "readable_output": [
                "CVE Vulnerability Reputation: CVE-2011-1272",
                "CVE Vulnerability Reputation: CVE-2011-1272",
            ],
        },
    ),
]


@pytest.mark.parametrize("args, resp, expected_results", CVE_COMMAND_ARGS)
def test_cve_command(mocker, args, resp, expected_results):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )
    mocker.patch.object(client, "antivirus_signature_get_request", side_effect=resp)
    results = cve_command(client, args)

    for i in range(len(results)):
        assert results[i].indicator.id == expected_results["id"][i]
        assert expected_results["readable_output"][i] in results[i].readable_output


@pytest.mark.parametrize(
    "args, expected_results",
    [
        (
            {"sha256": "test"},
            {
                "result": "file",
                "call_hashes_command": 1,
                "call_ids_command": 0,
                "args": {"file": "test", "sha256": "test", "expanded": True},
            },
        ),
        (
            {"md5": "test"},
            {
                "result": "file",
                "call_hashes_command": 1,
                "call_ids_command": 0,
                "args": {"file": "test", "md5": "test", "expanded": True},
            },
        ),
        (
            {"sha256": "test,test1", "md5": "test2"},
            {
                "result": "file",
                "call_hashes_command": 1,
                "call_ids_command": 0,
                "args": {
                    "file": "test,test1,test2",
                    "sha256": "test,test1",
                    "md5": "test2",
                    "expanded": True,
                },
            },
        ),
        (
            {"signature_id": "test,test1"},
            {
                "result": "ids",
                "call_hashes_command": 0,
                "call_ids_command": 2,
                "args": {"signature_id": "test,test1", "file": "", "expanded": True},
            },
        ),
    ],
)
def test_threat_signature_get_command(mocker, args, expected_results):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )
    call_hashes_command = mocker.patch(
        "ThreatVaultv2.file_command", return_value=["file"]
    )
    call_ids_command = mocker.patch.object(
        client, "antivirus_signature_get_request", return_value="ids"
    )
    mocker.patch("ThreatVaultv2.parse_resp_by_type", return_value=["ids"])
    results = threat_signature_get_command(client, args)

    assert results[0] == expected_results["result"]
    assert call_hashes_command.call_count == expected_results["call_hashes_command"]
    assert call_ids_command.call_count == expected_results["call_ids_command"]
    assert args == expected_results["args"]


@pytest.mark.parametrize(
    "args, expected_results",
    [
        (
            {"type": "test", "version": "test"},
            {"prefix": "ThreatVault.ReleaseNote", "readable_output": "Release notes:"},
        )
    ],
)
def test_release_note_get_command(mocker, args, expected_results):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )

    mocker.patch.object(
        client, "release_notes_get_request", return_value={"data": [[]]}
    )
    mocker.patch("ThreatVaultv2.resp_to_hr", return_value={"release_notes": "test"})
    results = release_note_get_command(client, args)

    assert results.outputs_prefix == expected_results["prefix"]
    assert expected_results["readable_output"] in results.readable_output


@pytest.mark.parametrize(
    "args, mocking, expected_args, expected_results",
    [({"id": "123"}, ["ids"], {"value": "123", "type": "id"}, "ids")],
)
def test_threat_batch_search_command(
    mocker, args, mocking, expected_args, expected_results
):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )

    call_request = mocker.patch.object(
        client, "threat_batch_search_request", return_value="test"
    )
    mocker.patch("ThreatVaultv2.parse_resp_by_type", return_value=mocking)
    results = threat_batch_search_command(client, args)

    assert results[0] == expected_results
    assert expected_args["value"] in call_request.call_args_list[0][1]["value"]
    assert expected_args["type"] in call_request.call_args_list[0][1]["arg"]


@pytest.mark.parametrize(
    "args, expected_results",
    [
        ({"cve": "123"}, {"cve": "123", "offset": 0, "limit": 50}),
        (
            {"cve": "123", "release-date": "2000-09-09"},
            {"cve": "123", "offset": 0, "releaseDate": "2000-09-09", "limit": 50},
        ),
        (
            {
                "cve": "123",
                "from-release-date": "2000-09-09",
                "to-release-date": "2000-09-09",
            },
            {
                "cve": "123",
                "offset": 0,
                "fromReleaseDate": "2000-09-09",
                "toReleaseDate": "2000-09-09",
                "limit": 50,
            },
        ),
        (
            {"signature-name": "123", "page": "2", "page_size": "100"},
            {"name": "123", "offset": 200, "limit": 100},
        ),
    ],
)
def test_threat_search_command(mocker, args, expected_results):

    client = Client(
        base_url="test",
        api_key="test",
        verify=False,
        proxy=False,
        reliability="E - Unreliable",
    )

    call_request = mocker.patch.object(
        client, "threat_search_request", return_value={"data": []}
    )
    mocker.patch("ThreatVaultv2.parse_resp_by_type", return_value=["test"])
    threat_search_command(client, args)

    assert call_request.call_args_list[0][1]["args"] == expected_results


@pytest.mark.parametrize("date, expected_result", [("2022-09-03", "2022-09-03")])
def test_parse_date(date, expected_result):

    res = parse_date(date)
    assert res == expected_result


@pytest.mark.parametrize(
    'reputation_type, expected_results',
    [
        (
            'spyware',
            'Spyware'
        ),
        (
            'vulnerability',
            'Vulnerability'
        ),
        (
            'antivirus',
            'Antivirus'
        ),
        (
            'fileformat',
            'Fileformat'
        ),
        (
            'spywarec2',
            'SpywareC2'
        ),
        (
            'dns',
            'DNS'
        ),
        (
            'rtdns',
            'RTDNS'
        )
    ]
)
def test_reputation_type_to_hr(reputation_type, expected_results):

    assert reputation_type_to_hr(reputation_type) == expected_results
