CONTEXT_RESULTS = (
    ([{
        "description": "",
        "isTempPath": False,
        "name": "dummy_attachment_content.txt",
        "path": "ee0a79b1-0714-462c-8c54-4aff51da3265",
        "showMediaFile": False,
        "type": ""
    },
        {
        "description": "",
        "isTempPath": False,
        "name": "dummy_mirrored_from_xsoar.pdf",
        "path": "8692b825-5f43-4954-bd30-8f2d5aa033e9",
        "showMediaFile": False,
        "type": ""
    }]))

EXPECTED_TABLE = ('|Name|\n|---|\n| dummy_attachment_content.txt |\n| dummy_mirrored_from_xsoar.pdf |\n')


def test_convert_to_table():
    """
    Given:
        - A list of attachments of a Jira issue
    When:
        - Calling convert_to_table function
    Then:
        - Validate the table is created correctly
    """
    from JiraV3ConvertAttachmentsToTable import convert_to_table
    result = convert_to_table(CONTEXT_RESULTS)

    assert result.readable_output == EXPECTED_TABLE
