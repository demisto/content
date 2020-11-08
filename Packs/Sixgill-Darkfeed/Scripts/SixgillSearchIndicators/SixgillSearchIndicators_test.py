import json

import demistomock as demisto
from SixgillSearchIndicators import search_indicators


json_raw_data = '''[
    {
        "Contents": [
            {
                "CustomFields": {
                    "actor": "random",
                    "description": "Malware available for download from file-sharing sites",
                    "firstseenbysource": "2020-05-14T05:43:32.629Z",
                    "name": "malware_download_urls",
                    "sixgillactor": "random",
                    "sixgilldescription": "Malware available for download from file-sharing sites",
                    "sixgillfeedid": "darkfeed_010",
                    "sixgillfeedname": "malware_download_urls",
                    "sixgillindicatorid": "indicator--31a397b6-38c6-458b-85af-5bca582522de",
                    "sixgilllanguage": "en",
                    "sixgillmitreattcktactic": "Build Capabilities",
                    "sixgillmitreattcktechnique": "Obtain/re-use payloads",
                    "sixgillpostreference": "https://portal.cybersixgill.com/#/search?q=_id:bbeb1570bc604531c6",
                    "sixgillposttitle": "rand [FULL]",
                    "sixgillsource": "forum_rand",
                    "sixgillvirustotaldetectionrate": null,
                    "sixgillvirustotalurl": null,
                    "tags": [
                        "malicious-activity",
                        "malware",
                        "Build Capabilities",
                        "Obtain/re-use payloads"
                    ]
                },
                "account": "",
                "aggregatedReliability": "B - Usually reliable",
                "calculatedTime": "2020-07-20T12:41:09.540651579Z",
                "comment": "",
                "comments": [
                    {
                        "category": "Sighting",
                        "content": "Created",
                        "created": "2020-07-20T12:41:09.530934698Z",
                        "entryId": "",
                        "id": "6b33d935-3cbf-4faa-8380-670efb6c7495",
                        "modified": "0001-01-01T00:00:00Z",
                        "sortValues": null,
                        "source": "Sixgill_Darkfeed.Sixgill_Darkfeed_instance_1",
                        "type": "IndicatorCommentTimeLine",
                        "user": "@DBot",
                        "version": 0
                    }
                ],
                "deletedFeedFetchTime": "0001-01-01T00:00:00Z",
                "expiration": "2020-08-19T12:41:09.501322894Z",
                "expirationSource": {
                    "brand": "Sixgill_Darkfeed",
                    "expirationInterval": 43200,
                    "expirationPolicy": "indicatorType",
                    "instance": "Sixgill_Darkfeed_instance_1",
                    "moduleId": "4cb666de-dbd1-4022-8c56-953caba90cde",
                    "setTime": "2020-07-20T12:41:09.501322894Z",
                    "source": "indicatorType",
                    "user": ""
                },
                "expirationStatus": "active",
                "firstSeen": "0001-01-01T00:00:00Z",
                "firstSeenEntryID": "API",
                "id": "300755",
                "indicator_type": "URL",
                "insightCache": null,
                "investigationIDs": [],
                "isShared": false,
                "lastReputationRun": "0001-01-01T00:00:00Z",
                "lastSeen": "0001-01-01T00:00:00Z",
                "lastSeenEntryID": "API",
                "manualExpirationTime": "0001-01-01T00:00:00Z",
                "manualScore": false,
                "manualSetTime": "0001-01-01T00:00:00Z",
                "manuallyEditedFields": null,
                "modified": "2020-07-20T12:41:09.540652783Z",
                "modifiedTime": "2020-07-20T12:41:07Z",
                "moduleToFeedMap": {
                    "4cb666de-dbd1-4022-8c56-953caba90cde": {
                        "ExpirationSource": {
                            "brand": "Sixgill_Darkfeed",
                            "expirationInterval": 43200,
                            "expirationPolicy": "indicatorType",
                            "instance": "Sixgill_Darkfeed_instance_1",
                            "moduleId": "4cb666de-dbd1-4022-8c56-953caba90cde",
                            "setTime": "2020-07-20T12:41:09.501322894Z",
                            "source": "indicatorType",
                            "user": ""
                        },
                        "bypassExclusionList": false,
                        "classifierVersion": 1,
                        "expirationInterval": 20160,
                        "expirationPolicy": "indicatorType",
                        "fetchTime": "2020-07-20T12:41:07Z",
                        "fields": {
                            "actor": "random",
                            "description": "Malware available for download from file-sharing sites",
                            "firstseenbysource": "2020-05-14T05:43:32.629Z",
                            "name": "malware_download_urls",
                            "sixgillactor": "random",
                            "sixgilldescription": "Malware available for download from file-sharing sites",
                            "sixgillfeedid": "darkfeed_010",
                            "sixgillfeedname": "malware_download_urls",
                            "sixgillindicatorid": "indicator--31a397b6-38c6-458b-85af-5bca582522de",
                            "sixgilllanguage": "en",
                            "sixgillmitreattcktactic": "Build Capabilities",
                            "sixgillmitreattcktechnique": "Obtain/re-use payloads",
                            "sixgillpostreference": "https://portal.cybersixgill.com/#/search?q=_id:bbeb1570bc604531c6",
                            "sixgillposttitle": "rand [FULL]",
                            "sixgillsource": "forum_rand",
                            "sixgillvirustotaldetectionrate": null,
                            "sixgillvirustotalurl": null,
                            "tags": [
                                "malicious-activity",
                                "malware",
                                "Build Capabilities",
                                "Obtain/re-use payloads"
                            ]
                        },
                        "isEnrichment": false,
                        "modifiedTime": "2020-07-20T12:41:07Z",
                        "moduleId": "4cb666de-dbd1-4022-8c56-953caba90cde",
                        "rawJSON": null,
                        "reliability": "B - Usually reliable",
                        "score": 3,
                        "sourceBrand": "Sixgill_Darkfeed",
                        "sourceInstance": "Sixgill_Darkfeed_instance_1",
                        "timestamp": "0001-01-01T00:00:00Z",
                        "type": "URL",
                        "value": "https://random.txt"
                    }
                },
                "relatedIncCount": 0,
                "score": 3,
                "sortValues": null,
                "sourceBrands": [
                    "Sixgill_Darkfeed"
                ],
                "sourceInstances": [
                    "Sixgill_Darkfeed_instance_1"
                ],
                "timestamp": "2020-07-20T12:41:09.540651579Z",
                "value": "https://random.txt",
                "version": 1
            }
        ]
    }
]'''


def execute_command(command, args=None):
    if command == 'findIndicators':
        return json.loads(json_raw_data)
    else:
        return []


def test_search_indicators(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    args = {
        'query': "sourceBrands:Sixgill_Darkfeed and sixgillactor:\"random\"",
        'size': 50
    }

    response = search_indicators(args)

    expected_res = [{
        'CustomFields': {'actor': 'random', 'description': 'Malware available for download from file-sharing sites',
                         'firstseenbysource': '2020-05-14T05:43:32.629Z', 'name': 'malware_download_urls',
                         'sixgillactor': 'random',
                         'sixgilldescription': 'Malware available for download from file-sharing sites',
                         'sixgillfeedid': 'darkfeed_010', 'sixgillfeedname': 'malware_download_urls',
                         'sixgillindicatorid': 'indicator--31a397b6-38c6-458b-85af-5bca582522de',
                         'sixgilllanguage': 'en', 'sixgillmitreattcktactic': 'Build Capabilities',
                         'sixgillmitreattcktechnique': 'Obtain/re-use payloads',
                         'sixgillpostreference': 'https://portal.cybersixgill.com/#/search?q=_id:bbeb1570bc604531c6',
                         'sixgillposttitle': 'rand [FULL]', 'sixgillsource': 'forum_rand',
                         'sixgillvirustotaldetectionrate': None, 'sixgillvirustotalurl': None,
                         'tags': ['malicious-activity', 'malware', 'Build Capabilities', 'Obtain/re-use payloads']},
        'expiration': '2020-08-19T12:41:09.501322894Z', 'expirationStatus': 'active',
        'firstSeen': '0001-01-01T00:00:00Z', 'id': '300755', 'lastSeen': '0001-01-01T00:00:00Z', 'score': 3,
        'sourceBrands': ['Sixgill_Darkfeed'], 'sourceInstances': ['Sixgill_Darkfeed_instance_1'],
        'value': 'https://random.txt'}]

    assert response.outputs == expected_res
