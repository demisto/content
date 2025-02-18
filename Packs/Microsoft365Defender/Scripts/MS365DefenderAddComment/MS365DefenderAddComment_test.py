def test_add_comment(mocker):
    from MS365DefenderAddComment import add_comment, demisto
    mocker.patch.object(demisto, 'executeCommand')
    add_comment({'id': '1', 'comment': 'test'})
    assert demisto.executeCommand.call_count == 1
    assert demisto.executeCommand.call_args[0][0] == 'microsoft-365-defender-incident-update'
    assert demisto.executeCommand.call_args[0][1]['id'] == '1'
    assert demisto.executeCommand.call_args[0][1]['comment'] == 'test'
