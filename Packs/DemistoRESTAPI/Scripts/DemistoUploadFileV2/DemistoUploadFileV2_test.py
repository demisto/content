import pytest
from DemistoUploadFileV2 import upload_file_command

RAW_RESPONSE = [
    {
        "Brand": "Demisto REST API",
        "Category": "Utilities",
        "Contents": {
            "response": {
                "ShardID": 0,
                "category": "",
                "childs": None,
                "closed": "0001-01-01T00:00:00Z",
                "created": "2020-07-08T11:30:14.386972+03:00",
                "creatingUserId": "admin",
                "dbotCreatedBy": "admin",
                "details": "",
                "entries": [
                    {
                        "IndicatorTimeline": None,
                        "ShardID": 0,
                        "brand": "none",
                        "category": "artifact",
                        "contents": "",
                        "contentsSize": 0,
                        "created": "2020-07-13T10:57:32.956671+03:00",
                        "cronView": False,
                        "dbotCreatedBy": "admin",
                        "endingDate": "0001-01-01T00:00:00Z",
                        "entryTask": None,
                        "errorSource": "",
                        "file": "test_name.pdf",
                        "fileID": "94b6eed9-fd5d-412e-87dc-5e2a7cdc8457",
                        "fileMetadata": {
                            "info": "PDF document, version 1.3",
                            "isMediaFile": False,
                            "md5": "be357a5a72c1236a42590ea894866884",
                            "sha1": "29f4d33b0895aa46a1dad97b54096d4e68e3d91a",
                            "sha256": "6577fb6b9a5f4779f835fec594d21267aedf3c7f3ee183c4bc2fd3f9fca52df4",
                            "sha512": "174c4574cbe429bb646e19ed1973b2ccfc314bc951f251684591105d1d0f5fe8aa9f67beae0d742"
                                      "0becec61bcfd51e17d270683242b77dc552e58b2f95a0625b",
                            "size": 250301,
                            "ssdeep": "6144:IwUbC/ok4IeyUvtRCRvhp2h8C+GYPcX6PorXMido+vWap81:z7ok4XjtIaxrKArXBoqw",
                            "type": "application/pdf"
                        },
                        "format": "",
                        "hasRole": False,
                        "id": "121@899",
                        "investigationId": "899",
                        "isTodo": False,
                        "mirrored": False,
                        "modified": "2020-07-13T10:57:33.011106+03:00",
                        "note": False,
                        "parentContent": None,
                        "parentEntryTruncated": False,
                        "parentId": "",
                        "pinned": False,
                        "playbookId": "",
                        "previousRoles": None,
                        "recurrent": False,
                        "reputationSize": 0,
                        "reputations": None,
                        "retryTime": "0001-01-01T00:00:00Z",
                        "roles": None,
                        "scheduled": False,
                        "sortValues": None,
                        "startDate": "0001-01-01T00:00:00Z",
                        "system": "",
                        "tags": [],
                        "tagsRaw": [],
                        "taskId": "",
                        "times": 0,
                        "timezoneOffset": 0,
                        "type": 3,
                        "user": "admin",
                        "version": 2
                    }
                ],
                "entryUsers": [
                    "admin"
                ],
                "hasRole": False,
                "highPriority": False,
                "id": "899",
                "invContext": None,
                "lastOpen": "0001-01-01T00:00:00Z",
                "mirrorAutoClose": None,
                "mirrorTypes": None,
                "modified": "2020-07-08T11:31:30.594058+03:00",
                "name": "office365_Feed",
                "previousRoles": None,
                "rawCategory": "",
                "reason": None,
                "roles": None,
                "runStatus": "completed",
                "slackMirrorAutoClose": False,
                "slackMirrorType": "",
                "sortValues": None,
                "status": 0,
                "systems": None,
                "tags": [
                    "Automation"
                ],
                "totalEntries": 0,
                "type": 0,
                "users": [
                    "admin",
                    "analyst"
                ],
                "version": 8
            }
        },
        "ContentsFormat": "json",
        "EntryContext": None,
        "Evidence": False,
        "EvidenceID": "",
        "File": "",
        "FileID": "",
        "FileMetadata": None,
        "HumanReadable": None,
        "ID": "",
        "IgnoreAutoExtract": False,
        "ImportantEntryContext": None,
        "IndicatorTimeline": None,
        "Metadata": {
            "IndicatorTimeline": None,
            "ShardID": 0,
            "brand": "Demisto REST API",
            "category": "",
            "contents": "",
            "contentsSize": 0,
            "created": "2020-07-13T10:57:33.044787+03:00",
            "cronView": False,
            "dbotCreatedBy": "",
            "endingDate": "0001-01-01T00:00:00Z",
            "entryTask": None,
            "errorSource": "",
            "file": "",
            "fileID": "",
            "fileMetadata": None,
            "format": "json",
            "hasRole": False,
            "id": "",
            "instance": "Demisto REST API_instance_1",
            "investigationId": "737",
            "isTodo": False,
            "mirrored": False,
            "modified": "0001-01-01T00:00:00Z",
            "note": False,
            "parentContent": "!demisto-api-multipart uri=\"entry/upload/899\" entryID=\"722@737\" body=\"test_bark\"",
            "parentEntryTruncated": False,
            "parentId": "726@737",
            "pinned": False,
            "playbookId": "",
            "previousRoles": None,
            "recurrent": False,
            "reputationSize": 0,
            "reputations": None,
            "retryTime": "0001-01-01T00:00:00Z",
            "roles": None,
            "scheduled": False,
            "sortValues": None,
            "startDate": "0001-01-01T00:00:00Z",
            "system": "",
            "tags": None,
            "tagsRaw": None,
            "taskId": "",
            "times": 0,
            "timezoneOffset": 0,
            "type": 1,
            "user": "",
            "version": 0
        },
        "ModuleName": "Demisto REST API_instance_1",
        "Note": False,
        "ReadableContentsFormat": "",
        "System": "",
        "Tags": None,
        "Type": 1,
        "Version": 0
    }
]


def test_demisto_upload_file(mocker):
    """Unit test
    Given
    - upload_file_command command
    - command args
    When
    - mock the raw response.
    Then
    - run the upload_file
    Validate the content of the HumanReadable.
    """
    mocker.patch('DemistoUploadFileV2.upload_file', return_value=RAW_RESPONSE)
    readable, _ = upload_file_command({'incidentId': '1', 'entryID': '12@12', 'body': "test_bark"})
    assert "test_bark" in readable


RAW_RESPONSE_ERROR = [
    {
        "Brand": "Demisto REST API",
        "Category": "Utilities",
        "Contents": {
            "response": {
                "ShardID": 0,
                "category": "",
                "childs": None,
                "closed": "0001-01-01T00:00:00Z",
                "created": "2020-07-08T11:30:14.386972+03:00",
                "creatingUserId": "admin",
                "dbotCreatedBy": "admin",
                "details": "",
                "entries": [
                    {
                        "IndicatorTimeline": None,
                        "ShardID": 0,
                        "brand": "none",
                        "category": "artifact",
                        "contents": "",
                        "contentsSize": 0,
                        "created": "2020-07-13T10:57:32.956671+03:00",
                        "cronView": False,
                        "dbotCreatedBy": "admin",
                        "endingDate": "0001-01-01T00:00:00Z",
                        "entryTask": None,
                        "errorSource": "",
                        "file": "test_name.pdf",
                        "fileID": "94b6eed9-fd5d-412e-87dc-5e2a7cdc8457",
                        "fileMetadata": {
                            "info": "PDF document, version 1.3",
                            "isMediaFile": False,
                            "md5": "be357a5a72c1236a42590ea894866884",
                            "sha1": "29f4d33b0895aa46a1dad97b54096d4e68e3d91a",
                            "sha256": "6577fb6b9a5f4779f835fec594d21267aedf3c7f3ee183c4bc2fd3f9fca52df4",
                            "sha512": "174c4574cbe429bb646e19ed1973b2ccfc314bc951f251684591105d1d0f5fe8aa9f67beae0d7420"
                                      "becec61bcfd51e17d270683242b77dc552e58b2f95a0625b",
                            "size": 250301,
                            "ssdeep": "6144:IwUbC/ok4IeyUvtRCRvhp2h8C+GYPcX6PorXMido+vWap81:z7ok4XjtIaxrKArXBoqw",
                            "type": "application/pdf"
                        },
                        "format": "",
                        "hasRole": False,
                        "id": "121@899",
                        "investigationId": "899",
                        "isTodo": False,
                        "mirrored": False,
                        "modified": "2020-07-13T10:57:33.011106+03:00",
                        "note": False,
                        "parentContent": None,
                        "parentEntryTruncated": False,
                        "parentId": "",
                        "pinned": False,
                        "playbookId": "",
                        "previousRoles": None,
                        "recurrent": False,
                        "reputationSize": 0,
                        "reputations": None,
                        "retryTime": "0001-01-01T00:00:00Z",
                        "roles": None,
                        "scheduled": False,
                        "sortValues": None,
                        "startDate": "0001-01-01T00:00:00Z",
                        "system": "",
                        "tags": [],
                        "tagsRaw": [],
                        "taskId": "",
                        "times": 0,
                        "timezoneOffset": 0,
                        "type": 3,
                        "user": "admin",
                        "version": 2
                    }
                ],
                "entryUsers": [
                    "admin"
                ],
                "hasRole": False,
                "highPriority": False,
                "id": "899",
                "invContext": None,
                "lastOpen": "0001-01-01T00:00:00Z",
                "mirrorAutoClose": None,
                "mirrorTypes": None,
                "modified": "2020-07-08T11:31:30.594058+03:00",
                "name": "office365_Feed",
                "previousRoles": None,
                "rawCategory": "",
                "reason": None,
                "roles": None,
                "runStatus": "completed",
                "slackMirrorAutoClose": False,
                "slackMirrorType": "",
                "sortValues": None,
                "status": 0,
                "systems": None,
                "tags": [
                    "Automation"
                ],
                "totalEntries": 0,
                "type": 0,
                "users": [
                    "admin",
                    "analyst"
                ],
                "version": 8
            }
        },
        "ContentsFormat": "json",
        "EntryContext": None,
        "Evidence": False,
        "EvidenceID": "",
        "File": "",
        "FileID": "",
        "FileMetadata": None,
        "HumanReadable": None,
        "ID": "",
        "IgnoreAutoExtract": False,
        "ImportantEntryContext": None,
        "IndicatorTimeline": None,
        "Metadata": {
            "IndicatorTimeline": None,
            "ShardID": 0,
            "brand": "Demisto REST API",
            "category": "",
            "contents": "",
            "contentsSize": 0,
            "created": "2020-07-13T10:57:33.044787+03:00",
            "cronView": False,
            "dbotCreatedBy": "",
            "endingDate": "0001-01-01T00:00:00Z",
            "entryTask": None,
            "errorSource": "",
            "file": "",
            "fileID": "",
            "fileMetadata": None,
            "format": "json",
            "hasRole": False,
            "id": "",
            "instance": "Demisto REST API_instance_1",
            "investigationId": "737",
            "isTodo": False,
            "mirrored": False,
            "modified": "0001-01-01T00:00:00Z",
            "note": False,
            "parentContent": "!demisto-api-multipart uri=\"entry/upload/899\" entryID=\"722@737\" body=\"test_bark\"",
            "parentEntryTruncated": False,
            "parentId": "726@737",
            "pinned": False,
            "playbookId": "",
            "previousRoles": None,
            "recurrent": False,
            "reputationSize": 0,
            "reputations": None,
            "retryTime": "0001-01-01T00:00:00Z",
            "roles": None,
            "scheduled": False,
            "sortValues": None,
            "startDate": "0001-01-01T00:00:00Z",
            "system": "",
            "tags": None,
            "tagsRaw": None,
            "taskId": "",
            "times": 0,
            "timezoneOffset": 0,
            "type": 1,
            "user": "",
            "version": 0
        },
        "ModuleName": "Demisto REST API_instance_1",
        "Note": False,
        "ReadableContentsFormat": "",
        "System": "",
        "Tags": None,
        "Type": 4,
        "Version": 0
    }
]


def test_demisto_upload_file_error(mocker):
    """Unit test
    Given
    - upload_file_command command
    - command args
    When
    - mock the raw response as error
    - mock the Client's send_request.
    Then
    - run the upload_file
    Validate that the correct error was raised
    """
    mocker.patch('DemistoUploadFileV2.upload_file', return_value=RAW_RESPONSE_ERROR)

    with pytest.raises(Exception,
                       match="There was an issue uploading the file. Check your API key and input argument."):
        upload_file_command({'incidentId': '1', 'entryID': '12@12', 'body': "test_bark"})
