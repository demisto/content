def test_add_comment_as_note():
    """Test if the correct arguments are given to the CommandResults object when
    adding a comment as a note.
    """
    from JiraAddComment import add_comment
    result = add_comment({'comment': 'New comment', 'tags': 'comment tag to Jira'})

    assert result.readable_output == 'New comment'
    assert result.tags == ['comment tag to Jira']
    assert result.mark_as_note
