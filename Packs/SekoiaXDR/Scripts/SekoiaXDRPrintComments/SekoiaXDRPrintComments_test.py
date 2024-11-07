import demistomock as demisto
from SekoiaXDRPrintComments import create_comment_object, get_comments, main  # type: ignore


def test_create_comment_object(mocker):
    comments = [
        {
            "date": "2021-07-27T15:00:00Z",
            "content": "comment",
            "user": "user",
            "field_1": "value_1",
            "field_2": "value_2",
            "field_3": "value_3",
            "field_4": "value_4",
        },
        {
            "date": "2021-07-27T15:00:00Z",
            "content": "comment1",
            "user": "user1",
            "field_1": "value_1",
            "field_2": "value_2",
            "field_3": "value_3",
            "field_4": "value_4",
        },
    ]
    expected = [
        {
            "date": "2021-07-27T15:00:00Z",
            "comment": "comment",
            "user": "user",
        },
        {
            "date": "2021-07-27T15:00:00Z",
            "comment": "comment1",
            "user": "user1",
        },
    ]
    assert create_comment_object(comments) == expected


def test_get_comments(mocker):
    comments_output = [
        {
            "date": "2021-07-27T15:00:00Z",
            "content": "comment",
            "user": "user",
            "field_1": "value_1",
            "field_2": "value_2",
            "field_3": "value_3",
            "field_4": "value_4",
        },
        {
            "date": "2021-07-27T15:00:00Z",
            "content": "comment1",
            "user": "user1",
            "field_1": "value_1",
            "field_2": "value_2",
            "field_3": "value_3",
            "field_4": "value_4",
        },
    ]
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": 3, "Contents": comments_output}],
    )
    assert "user" in get_comments("alert_id")
    assert "user1" in get_comments("alert_id")
    assert "comment" in get_comments("alert_id")
    assert "comment1" in get_comments("alert_id")


def test_get_comments_no_comments(mocker):
    comments_output = []
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": 3, "Contents": comments_output}],
    )
    assert "There is no comments in this alert" in get_comments("alert_id")


def test_main(mocker):
    mocker.patch.object(
        demisto, "incident", return_value={"CustomFields": {"alertid": "alert_id"}}
    )
    mocker.patch(
        "SekoiaXDRPrintComments.get_comments", return_value="Comments: testcomment"
    )
    mocker.patch.object(demisto, "results")

    main()
    assert demisto.results.call_args[0][0]["HumanReadable"] == "Comments: testcomment"
