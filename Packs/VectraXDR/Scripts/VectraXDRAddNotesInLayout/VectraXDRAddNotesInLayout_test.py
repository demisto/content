import demistomock as demisto
from CommonServerPython import *
import VectraXDRAddNotesInLayout
from VectraXDRAddNotesInLayout import main  # Import the main function from the script file


def test_vectra_xdr_add_notes_with_empty_notes(mocker):
    """
    Given:
    - A mocked incident object with an empty 'vectraxdrentitynotes' field.

    When:
    - Calling the 'main' function of the VectraXDRAddNotesInLayout integration script.

    Then:
    - Assert that the 'return_results' function is called once with the correct parameters for the empty notes list.
    """

    # Mock the demisto.incident() function to return an incident with an empty 'vectraxdrentitynotes' field
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {"vectraxdrentitynotes": []}})

    # Mock the return_results() function to capture the output
    mocker.patch("VectraXDRAddNotesInLayout.return_results")

    # Call the main function
    main()

    # Assert that return_results() was called once with the correct parameters for the empty notes list
    VectraXDRAddNotesInLayout.return_results.assert_called_with(
        {"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": "", "Note": False}
    )


def test_vectra_xdr_add_notes_with_notes(mocker):
    """
    Given:
    - A mocked incident object with 'vectraxdrentitynotes' field containing notes.

    When:
    - Calling the 'main' function of the VectraXDRAddNotesInLayout integration script.

    Then:
    - Assert that the 'return_results' function is called twice with the correct parameters, once for each note.
    - Assert that the 'Contents' parameter in the returned results contains the correct note content.
    - Assert that the 'Note' parameter in the returned results is set to True.
    """

    # Mock the demisto.incident() function to return an incident with 'vectraxdrentitynotes' containing notes
    notes_response = [
        {
            "id": 328,
            "date_created": "2023-07-27T05:46:26Z",
            "date_modified": "2023-07-27T05:47:06Z",
            "created_by": "api_client",
            "modified_by": "api_client",
            "note": "check_1",
        },
        {
            "id": 328,
            "date_created": "2023-07-27T05:46:26Z",
            "date_modified": "2023-07-27T05:47:06Z",
            "created_by": "api_client",
            "modified_by": "api_client",
            "note": "check_2",
        },
    ]
    mocker.patch.object(
        demisto,
        "incident",
        return_value={"CustomFields": {"vectraxdrentitynotes": [json.dumps(note) for note in notes_response]}},
    )

    # Mock the return_results() function to capture the output
    mocker.patch("VectraXDRAddNotesInLayout.return_results")

    # Call the main function
    main()

    # Assert that return_results() was called twice with the correct parameters
    assert VectraXDRAddNotesInLayout.return_results.call_count == 2

    VectraXDRAddNotesInLayout.return_results.assert_any_call(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": "[Fetched From Vectra]\n"
            + f"Added By: {notes_response[0].get('created_by')}\n"
            + f"Added At: {notes_response[0].get('date_created')} UTC\n"
            + f"Note Content:{notes_response[0].get('note')}",
            "Note": True,
        }
    )

    VectraXDRAddNotesInLayout.return_results.assert_any_call(
        {
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "Contents": "[Fetched From Vectra]\n"
            + f"Added By: {notes_response[1].get('created_by')}\n"
            + f"Added At: {notes_response[1].get('date_created')} UTC\n"
            + f"Note Content:{notes_response[1].get('note')}",
            "Note": True,
        }
    )
