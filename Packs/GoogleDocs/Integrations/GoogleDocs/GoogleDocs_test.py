import GoogleDocs
import demistomock as demisto


document = {
    "title": "'test'",
    "body": {
        "content": [
            {
                "endIndex": 1,
                "sectionBreak": {
                    "sectionStyle": {
                        "columnSeparatorStyle": "NONE",
                        "contentDirection": "LEFT_TO_RIGHT",
                        "sectionType": "CONTINUOUS",
                    }
                },
            },
            {
                "startIndex": 1,
                "endIndex": 8,
                "paragraph": {
                    "elements": [
                        {
                            "startIndex": 1,
                            "endIndex": 8,
                            "textRun": {"content": "heyhey\n", "textStyle": {}},
                        }
                    ],
                    "paragraphStyle": {
                        "namedStyleType": "NORMAL_TEXT",
                        "direction": "LEFT_TO_RIGHT",
                    },
                },
            },
        ]
    },
    "documentStyle": {
        "background": {"color": {}},
        "pageNumberStart": 1,
        "marginTop": {"magnitude": 72, "unit": "PT"},
        "marginBottom": {"magnitude": 72, "unit": "PT"},
        "marginRight": {"magnitude": 72, "unit": "PT"},
        "marginLeft": {"magnitude": 72, "unit": "PT"},
        "pageSize": {
            "height": {"magnitude": 792, "unit": "PT"},
            "width": {"magnitude": 612, "unit": "PT"},
        },
        "marginHeader": {"magnitude": 36, "unit": "PT"},
        "marginFooter": {"magnitude": 36, "unit": "PT"},
        "useCustomHeaderFooterMargins": True,
    },
    "namedStyles": {
        "styles": [
            {
                "namedStyleType": "NORMAL_TEXT",
                "textStyle": {
                    "bold": False,
                    "italic": False,
                    "underline": False,
                    "strikethrough": False,
                    "smallCaps": False,
                    "backgroundColor": {},
                    "foregroundColor": {"color": {"rgbColor": {}}},
                    "fontSize": {"magnitude": 11, "unit": "PT"},
                    "weightedFontFamily": {"fontFamily": "Arial", "weight": 400},
                    "baselineOffset": "NONE",
                },
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "alignment": "START",
                    "lineSpacing": 115,
                    "direction": "LEFT_TO_RIGHT",
                    "spacingMode": "COLLAPSE_LISTS",
                    "spaceAbove": {"unit": "PT"},
                    "spaceBelow": {"unit": "PT"},
                    "borderBetween": {
                        "color": {},
                        "width": {"unit": "PT"},
                        "padding": {"unit": "PT"},
                        "dashStyle": "SOLID",
                    },
                    "borderTop": {
                        "color": {},
                        "width": {"unit": "PT"},
                        "padding": {"unit": "PT"},
                        "dashStyle": "SOLID",
                    },
                    "borderBottom": {
                        "color": {},
                        "width": {"unit": "PT"},
                        "padding": {"unit": "PT"},
                        "dashStyle": "SOLID",
                    },
                    "borderLeft": {
                        "color": {},
                        "width": {"unit": "PT"},
                        "padding": {"unit": "PT"},
                        "dashStyle": "SOLID",
                    },
                    "borderRight": {
                        "color": {},
                        "width": {"unit": "PT"},
                        "padding": {"unit": "PT"},
                        "dashStyle": "SOLID",
                    },
                    "indentFirstLine": {"unit": "PT"},
                    "indentStart": {"unit": "PT"},
                    "indentEnd": {"unit": "PT"},
                    "keepLinesTogether": False,
                    "keepWithNext": False,
                    "avoidWidowAndOrphan": True,
                    "shading": {"backgroundColor": {}},
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "HEADING_1",
                "textStyle": {"fontSize": {"magnitude": 20, "unit": "PT"}},
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"magnitude": 20, "unit": "PT"},
                    "spaceBelow": {"magnitude": 6, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "HEADING_2",
                "textStyle": {
                    "bold": False,
                    "fontSize": {"magnitude": 16, "unit": "PT"},
                },
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"magnitude": 18, "unit": "PT"},
                    "spaceBelow": {"magnitude": 6, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "HEADING_3",
                "textStyle": {
                    "bold": False,
                    "foregroundColor": {
                        "color": {
                            "rgbColor": {
                                "red": 0.2627451,
                                "green": 0.2627451,
                                "blue": 0.2627451,
                            }
                        }
                    },
                    "fontSize": {"magnitude": 14, "unit": "PT"},
                },
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"magnitude": 16, "unit": "PT"},
                    "spaceBelow": {"magnitude": 4, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "HEADING_4",
                "textStyle": {
                    "foregroundColor": {
                        "color": {"rgbColor": {"red": 0.4, "green": 0.4, "blue": 0.4}}
                    },
                    "fontSize": {"magnitude": 12, "unit": "PT"},
                },
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"magnitude": 14, "unit": "PT"},
                    "spaceBelow": {"magnitude": 4, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "HEADING_5",
                "textStyle": {
                    "foregroundColor": {
                        "color": {"rgbColor": {"red": 0.4, "green": 0.4, "blue": 0.4}}
                    },
                    "fontSize": {"magnitude": 11, "unit": "PT"},
                },
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"magnitude": 12, "unit": "PT"},
                    "spaceBelow": {"magnitude": 4, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "HEADING_6",
                "textStyle": {
                    "italic": True,
                    "foregroundColor": {
                        "color": {"rgbColor": {"red": 0.4, "green": 0.4, "blue": 0.4}}
                    },
                    "fontSize": {"magnitude": 11, "unit": "PT"},
                },
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"magnitude": 12, "unit": "PT"},
                    "spaceBelow": {"magnitude": 4, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "TITLE",
                "textStyle": {"fontSize": {"magnitude": 26, "unit": "PT"}},
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"unit": "PT"},
                    "spaceBelow": {"magnitude": 3, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
            {
                "namedStyleType": "SUBTITLE",
                "textStyle": {
                    "italic": False,
                    "foregroundColor": {
                        "color": {"rgbColor": {"red": 0.4, "green": 0.4, "blue": 0.4}}
                    },
                    "fontSize": {"magnitude": 15, "unit": "PT"},
                    "weightedFontFamily": {"fontFamily": "Arial", "weight": 400},
                },
                "paragraphStyle": {
                    "namedStyleType": "NORMAL_TEXT",
                    "direction": "LEFT_TO_RIGHT",
                    "spaceAbove": {"unit": "PT"},
                    "spaceBelow": {"magnitude": 16, "unit": "PT"},
                    "keepLinesTogether": True,
                    "keepWithNext": True,
                    "pageBreakBefore": False,
                },
            },
        ]
    },
    "revisionId": "456",
    "suggestionsViewMode": "SUGGESTIONS_INLINE",
    "documentId": "123",
}


def test_batch_update_document_command(mocker):
    """Given:
    - a valid document id and actions argeuments

    When:
    - running batch_update_document_command

    Then:
    - validate the results are as expected
    """
    from GoogleDocs import batch_update_document_command

    args = {
        "actions": "action1{param1,param2};action2{param1,param2}",
        "document_id": "123",
    }
    excepted_result = {
        "human_readable": "### The document with the title 'test' and actions action1{param1,param2};action2{param1,param2}"
        + " was updated. the results are:\n|DocumentId|RevisionId|Title|\n|---|---|---|\n| 123 | 456 | 'test' |\n"
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(GoogleDocs, "batch_update_document", return_value=document)
    result = batch_update_document_command({})
    assert result.get("HumanReadable") == excepted_result.get("human_readable")


def test_create_document_command(mocker):
    """Given:
    - a valid document title

    When:
    - running create_document_command

    Then:
    - validate the results are as expected
    """
    from GoogleDocs import create_document_command

    args = {"title": "test"}
    excepted_result = {
        "human_readable": "### The document with the title test was created."
        + " The results are:\n|DocumentId|RevisionId|Title|\n|---|---|---|\n| 123 | 456 | 'test' |\n"
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(GoogleDocs, "create_document", return_value=document)
    result = create_document_command({})
    assert result.get("HumanReadable") == excepted_result.get("human_readable")


def test_get_document_command(mocker):
    """Given:
    - a valid document id of an existing document

    When:
    - running get_document_command

    Then:
    - validate the results are as expected
    """
    from GoogleDocs import get_document_command

    args = {"document_id": "123"}
    excepted_result = {
        "human_readable": "### The document with the title 'test' was returned."
        + " The results are:\n|DocumentId|RevisionId|Title|\n|---|---|---|\n| 123 | 456 | 'test' |\n"
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(GoogleDocs, "get_document", return_value=document)
    result = get_document_command({})
    assert result.get("HumanReadable") == excepted_result.get("human_readable")


def test_parse_actions():
    """Given:
    - a valid actions string argument string

    When:
    - running parse_actions

    Then:
    - the actions string is parsed to a dictionary
    """
    from GoogleDocs import parse_actions

    assert parse_actions("action1{param1,param2};action2{param1,param2}") == {
        "action1": ["param1", "param2"],
        "action2": ["param1", "param2"],
    }
