def test_update_comment_or_worknote(mocker):
    # test update_comment_or_worknote function
    from ServiceNowAddComment import update_comment_or_worknote, demisto
    import ServiceNowAddComment
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'result': {'sys_id': '1',
                                                                                          'sys_updated_on': '2',
                                                                                          'sys_updated_by': '3',
                                                                                          'number': '4',
                                                                                          'sys_class_name': '5',
                                                                                          'sys_created_by': '6',
                                                                                          'sys_created_on': '7'}}}])
    mocker.patch.object(ServiceNowAddComment, 'isError', return_value=False)
    update_comment_or_worknote({'ticket_id': '1', 'note': 'test'})
    assert demisto.executeCommand.call_count == 1
    assert demisto.executeCommand.call_args[0][0] == 'servicenow-update-ticket'
    assert demisto.executeCommand.call_args[0][1]['id'] == '1'
    assert demisto.executeCommand.call_args[0][1]['work_notes'] == 'test'
