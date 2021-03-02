import demistomock as demisto  # noqa

import ExpanseEvidenceDynamicSection


INCIDENT = {
    'CustomFields': {
        'expanselatestevidence': """
{
    "certificate": null,
    "cipherSuite": null,
    "configuration": {
        "_type": "NetBiosNameServerConfiguration",
        "nodeNames": [
            {
                "lastNameByte": 0,
                "name": "FOOBAR"
            },
            {
                "lastNameByte": 0,
                "name": "CORTEXLAB"
            },
            {
                "lastNameByte": 32,
                "name": "FOOBAR"
            }
        ]
    },
    "discoveryType": "Direct",
    "domain": null,
    "evidenceType": "ScanEvidence",
    "exposureId": "1a485fb6-dedb-3b54-afb4-5f3978fbea38",
    "exposureType": "NET_BIOS_NAME_SERVER",
    "geolocation": {
        "city": "MUNICH",
        "countryCode": "DE",
        "latitude": 48.15,
        "longitude": 11.58,
        "regionCode": "BY",
        "timeZone": null
    },
    "ip": "95.114.16.51",
    "portNumber": 137,
    "portProtocol": "UDP",
    "serviceId": "8c3c1f11-62fd-34e9-9a31-c019630b2a0a",
    "serviceProperties": {
        "serviceProperties": []
    },
    "timestamp": "2020-05-04T00:00:00Z",
    "tlsVersion": null
}
"""
    }
}

RESULT = """
### Evidence
|Field|Value|
|---|---|
|certificate|*empty*|
|cipherSuite|*empty*|
|configuration|See below, *Evidence / configuration*|
|discoveryType|Direct|
|domain|*empty*|
|evidenceType|ScanEvidence|
|exposureId|1a485fb6-dedb-3b54-afb4-5f3978fbea38|
|exposureType|NET_BIOS_NAME_SERVER|
|geolocation|See below, *Evidence / geolocation*|
|ip|95.114.16.51|
|portNumber|137|
|portProtocol|UDP|
|serviceId|8c3c1f11-62fd-34e9-9a31-c019630b2a0a|
|serviceProperties|See below, *Evidence / serviceProperties*|
|timestamp|2020-05-04T00:00:00Z|
|tlsVersion|*empty*|
### Evidence / configuration
|Field|Value|
|---|---|
|_type|NetBiosNameServerConfiguration|
|nodeNames|See below, *Evidence / configuration / nodeNames*|
### Evidence / geolocation
|Field|Value|
|---|---|
|city|MUNICH|
|countryCode|DE|
|latitude|48.15|
|longitude|11.58|
|regionCode|BY|
|timeZone|*empty*|
### Evidence / serviceProperties
|Field|Value|
|---|---|
|serviceProperties|*empty list*|
### Evidence / configuration / nodeNames
|Field|Value|
|---|---|
|FOOBAR|0|
|CORTEXLAB|0|
|FOOBAR|32|
"""


def test_evidence_dynamic_section(mocker):
    """
    Given:
        - an incident with expanse latest evidence in json format
    When
        - Showing Expanse evidence dynamic section ins Incident layout
    Then
        - Evidence Data is transformed into a markdown document with hierarchical tables
    """
    mocker.patch.object(demisto, 'incidents', return_value=[INCIDENT])

    result = ExpanseEvidenceDynamicSection.evidence_dynamic_section({})

    assert result.readable_output.strip() == RESULT.strip()
