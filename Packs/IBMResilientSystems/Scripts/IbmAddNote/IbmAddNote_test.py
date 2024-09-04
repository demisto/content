def test_add_comment_as_note():
    """Test if the correct arguments are given to the CommandResults object when
    adding a comment as a note.
    """
    from IbmAddNote import add_note
    result = add_note({'note': 'New Note', 'tags': 'comment tag to IBM'})

    assert result.readable_output == 'New Note'
    assert result.tags == ['comment tag to IBM']
    assert result.mark_as_note
