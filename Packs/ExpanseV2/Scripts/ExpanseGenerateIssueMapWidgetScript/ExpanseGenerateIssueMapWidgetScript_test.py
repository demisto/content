import demistomock as demisto  # noqa

from typing import Tuple, List
from math import floor
from functools import reduce

import ExpanseGenerateIssueMapWidgetScript


# taken from demistomock with only the relevant
# fields changed
EXAMPLE_INCIDENT = [
    {
        "Brand": "Builtin",
        "Category": "Builtin",
        "Contents": {
            "data": [
                {
                    "CustomFields": {
                        "expansegeolocation": [
                            {"latitude": 3.14, "longitude": 14.3}
                        ]
                    },
                    "account": "",
                    "activated": "0001-01-01T00:00:00Z",
                    "attachment": None,
                    "autime": 1550670443962164000,
                    "canvases": None,
                    "category": "",
                    "closeNotes": "",
                    "closeReason": "",
                    "closed": "0001-01-01T00:00:00Z",
                    "closingUserId": "",
                    "created": "2019-02-20T15:47:23.962164+02:00",
                    "details": "",
                    "droppedCount": 0,
                    "dueDate": "2019-03-02T15:47:23.962164+02:00",
                    "hasRole": False,
                    "id": "1",
                    "investigationId": "1",
                    "isPlayground": False,
                    "labels": [
                        {"type": "Instance", "value": "test"},
                        {"type": "Brand", "value": "Manual"},
                    ],
                    "lastOpen": "0001-01-01T00:00:00Z",
                    "linkedCount": 0,
                    "linkedIncidents": None,
                    "modified": "2019-02-20T15:47:27.158969+02:00",
                    "name": "1",
                    "notifyTime": "2019-02-20T15:47:27.156966+02:00",
                    "occurred": "2019-02-20T15:47:23.962163+02:00",
                    "openDuration": 0,
                    "owner": "analyst",
                    "parent": "",
                    "phase": "",
                    "playbookId": "playbook0",
                    "previousRoles": None,
                    "rawCategory": "",
                    "rawCloseReason": "",
                    "rawJSON": "",
                    "rawName": "1",
                    "rawPhase": "",
                    "rawType": "Unclassified",
                    "reason": "",
                    "reminder": "0001-01-01T00:00:00Z",
                    "roles": None,
                    "runStatus": "waiting",
                    "severity": 0,
                    "sla": 0,
                    "sourceBrand": "Manual",
                    "sourceInstance": "amichay",
                    "status": 1,
                    "type": "Unclassified",
                    "version": 6,
                }
            ],
            "total": 1,
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
        "Metadata": {
            "brand": "Builtin",
            "category": "",
            "contents": "",
            "contentsSize": 0,
            "created": "2019-02-24T09:44:51.992682+02:00",
            "cronView": False,
            "endingDate": "0001-01-01T00:00:00Z",
            "entryTask": None,
            "errorSource": "",
            "file": "",
            "fileID": "",
            "fileMetadata": None,
            "format": "json",
            "hasRole": False,
            "id": "",
            "instance": "Builtin",
            "investigationId": "7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "modified": "0001-01-01T00:00:00Z",
            "note": False,
            "parentContent": '!getIncidents query="id:1"',
            "parentEntryTruncated": False,
            "parentId": "111@7ab2ac46-4142-4af8-8cbe-538efb4e63d6",
            "pinned": False,
            "playbookId": "",
            "previousRoles": None,
            "recurrent": False,
            "reputationSize": 0,
            "reputations": None,
            "roles": None,
            "scheduled": False,
            "startDate": "0001-01-01T00:00:00Z",
            "system": "",
            "tags": None,
            "tagsRaw": None,
            "taskId": "",
            "times": 0,
            "timezoneOffset": 0,
            "type": 1,
            "user": "",
            "version": 0,
        },
        "ModuleName": "InnerServicesModule",
        "Note": False,
        "ReadableContentsFormat": "",
        "System": "",
        "Tags": None,
        "Type": 1,
        "Version": 0,
    }
]


def test_latlon_to_yx():
    """
    Given:
        - coordinates (lat, lon)
    When
        - translating lon/lat into image x/y
    Then
        - x/y coordinates are calculated
    """
    from ExpanseGenerateIssueMapWidgetScript import lat_to_y, lon_to_x, RESULT_IMAGE_X, RESULT_IMAGE_Y

    assert lat_to_y(90) is None
    assert lat_to_y(-90) is None

    tests: List[Tuple[Tuple[int, int], Tuple[int, int]]] = [
        ((85, -180), (0, 0)),
        ((85, 180), (0, RESULT_IMAGE_X)),
        ((-85, -180), (RESULT_IMAGE_Y, 0)),
        ((-85, 180), (RESULT_IMAGE_Y, RESULT_IMAGE_X)),
        ((0, 0), (floor(RESULT_IMAGE_Y / 2), floor(RESULT_IMAGE_X / 2)))
    ]

    for (lat, lon), (y, x) in tests:
        ry = lat_to_y(lat)
        rx = lon_to_x(lon)

        assert rx >= x - 1
        assert rx <= x + 1
        assert ry >= y - 1
        assert ry <= y + 1


def test_calc_clusters(mocker):
    """
    Given:
        - list of issue coordinates
    When
        - calculating grouping of points in clusters
    Then
        - points are grouped in clusters
    """
    mocker.patch('ExpanseGenerateIssueMapWidgetScript.lat_to_y', side_effect=lambda y: y)
    mocker.patch('ExpanseGenerateIssueMapWidgetScript.lon_to_x', side_effect=lambda x: x)

    points = [(0, 0), (4, 4), (300, 300), (320, 320), (280, 280)]
    clusters = reduce(ExpanseGenerateIssueMapWidgetScript.calc_clusters, points, [])

    assert clusters == [[(0, 0), (4, 4)], [(300, 300), (320, 320), (280, 280)]]


def test_extract_geolocation(mocker):
    """
    Given:
        - none
    When
        - extracting coordinate from list of incidents
    Then
        - demisto.getIncidents is invoked
        - coordinates are extracted
    """
    def executeCommand(name, args=None):
        if name != 'getIncidents':
            raise ValueError(f'Unimplemented command called: {name}')

        if args['page'] > 0:
            # empty results
            return [{
                'Type': 1,
                'Contents': {
                    'data': []
                }
            }]

        return EXAMPLE_INCIDENT

    mocker.patch('ExpanseGenerateIssueMapWidgetScript.lat_to_y', side_effect=lambda y: y)
    mocker.patch('ExpanseGenerateIssueMapWidgetScript.lon_to_x', side_effect=lambda x: x)

    ec_mock = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)  # this keeps mypy happy
    result = ExpanseGenerateIssueMapWidgetScript.extract_geolocation("from-date", "to-date")

    assert result == [(3.14, 14.3)]
    assert ec_mock.call_args[0][0] == "getIncidents"
    assert ec_mock.call_args[0][1]['fromdate'] == "from-date"
    assert ec_mock.call_args[0][1]['todate'] == "to-date"


def test_generate_map_command(mocker):
    """
    Given:
        - none
    When
        - generating a world map image with issues
    Then
        - commands returns with no errors
        - markdown document is generated
    """
    eg_mock = mocker.patch('ExpanseGenerateIssueMapWidgetScript.extract_geolocation', return_value=[])

    result = ExpanseGenerateIssueMapWidgetScript.generate_map_command({'from': "fake-from", "to": "fake-to"})

    assert eg_mock.call_args[0][0] == "fake-from"
    assert eg_mock.call_args[0][1] == "fake-to"
    assert result.startswith('### Map of Open Incidents On Prem')
