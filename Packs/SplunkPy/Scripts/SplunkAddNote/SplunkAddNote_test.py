def test_add_splunk_note_as_war_room_note():
    """Test if the correct arguments are given to the CommandResults object when
    adding a note as a war room note.
    """
    from SplunkAddNote import add_note

    result = add_note({"note": "New note", "tags": "note tag to splunk"})

    assert result.readable_output == "New note"
    assert result.tags == ["note tag to splunk"]
    assert result.mark_as_note
