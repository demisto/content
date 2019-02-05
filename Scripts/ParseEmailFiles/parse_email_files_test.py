from ParseEmailFiles import MsOxMessage


def test_msg_html_with_attachments():
    msg = MsOxMessage('test_data/html_attachment.msg')
    assert msg is not None
    msg_dict = msg.as_dict()
    assert 'This is an html email' in msg_dict['Text']
    attachments_list = msg.get_all_attachments()
    assert len(attachments_list) == 1
    attach = attachments_list[0]
    assert attach.AttachFilename == 'dummy-attachment.txt'
    assert attach.AttachMimeTag == 'text/plain'
    assert attach.data == 'This is a text attachment'


def test_msg_utf_encoded_subject():
    msg = MsOxMessage('test_data/utf_subject.msg')
    assert msg is not None
    msg_dict = msg.as_dict()
    # we test that subject which has utf-8 encoding (in the middle) is actually decoded
    assert '?utf-8' in msg_dict['HeadersMap']['Subject']
    subj = msg_dict['Subject']
    assert 'TESTING' in subj and '?utf-8' not in subj
