import pytest
from SetThreatVaultIncidentMarkdownRepresentation import json_to_md, read_context_from_threat_vault_incident


@pytest.mark.parametrize(
    'incident_fields, expected_results',
    [
        (
            {
                'Spyware': [
                    {
                        "severity": "medium",
                        "pan_id": 22144,
                        "attack_name": "WebCompanion Adware Traffic Detection",
                        "category": "spyware",
                        "action": "alert",
                        "change_data": "new coverage",
                        "min_version": "8.1.0",
                        "max_version": ""
                    },
                    {
                        "severity": "medium",
                        "pan_id": 22145,
                        "attack_name": "AdLoad Adware Traffic Detection",
                        "category": "spyware",
                        "action": "alert",
                        "change_data": "new coverage",
                        "min_version": "8.1.0",
                        "max_version": ""
                    }
                ],
                'Vulnerability': [
                    {
                        "severity": "high",
                        "pan_id": 93000,
                        "attack_name": "Ignite Realtime Openfire Cross-Site Request Forgery Vulnerability",
                        "cve": "CVE-2015-6973",
                        "vendor": "",
                        "category": "code-execution",
                        "action": "reset-server",
                        "change_data": "improved detection logic to cover a new exploit",
                        "min_version": "8.1.0",
                        "max_version": ""
                    },
                    {
                        "severity": "high",
                        "pan_id": 93056,
                        "attack_name": "Microsoft Internet Explorer Memory Corruption Vulnerability",
                        "cve": "CVE-2013-3882",
                        "vendor": "MS13-080",
                        "category": "code-execution",
                        "action": "reset-both",
                        "change_data": "improved detection logic to cover a new exploit",
                        "min_version": "8.1.0",
                        "max_version": ""
                    }
                ]
            },
            '### Spyware\n'
            '|action|attack_name|category|change_data|max_version|min_version|pan_id|severity|\n'
            '|---|---|---|---|---|---|---|---|\n'
            '| alert | WebCompanion Adware Traffic Detection | spyware | new coverage |  | 8.1.0 | 22144 | medium |\n'
            '| alert | AdLoad Adware Traffic Detection | spyware | new coverage |  | 8.1.0 | 22145 | medium |\n\n\n\n'
            '### Vulnerability\n'
            '|action|attack_name|category|change_data|cve|max_version|min_version|pan_id|severity|vendor|\n'
            '|---|---|---|---|---|---|---|---|---|---|\n'
            '| reset-server | Ignite Realtime Openfire Cross-Site Request Forgery Vulnerability | code-execution |'
            ' improved detection logic to cover a new exploit | CVE-2015-6973 |  | 8.1.0 | 93000 | high |  |\n'
            '| reset-both | Microsoft Internet Explorer Memory Corruption Vulnerability | code-execution |'
            ' improved detection logic to cover a new exploit | CVE-2013-3882 |  | 8.1.0 | 93056 | high | MS13-080 |\n\n\n\n'
        ),
        (
            {},
            ''
        )
    ]

)
def test_json_to_md(incident_fields, expected_results):

    results = json_to_md(incident_fields)
    assert results == expected_results


@pytest.mark.parametrize(
    'incident, expected_results',
    [
        (
            {'CustomFields': {1: 'test', 2: 'test'}},
            {}
        ),
        (
            {'CustomFields':
                {
                    'threatvaultbypaloaltonetworksspyware': 'test',
                    'threatvaultbypaloaltonetworksfiletype': 'test',
                    'some_key': 'test'
                }
             },
            {'File type': 'test',
             'Spyware': 'test'}
        )
    ]
)
def test_read_context_from_threat_vault_incident(mocker, incident, expected_results):

    mocker.patch('SetThreatVaultIncidentMarkdownRepresentation.demisto.incident', return_value=incident)

    results = read_context_from_threat_vault_incident()
    assert results == expected_results
