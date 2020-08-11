def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def test_set_email_reply():
    from PreprocessEmail import set_email_reply
    expected_result = util_open_file('test_data/email_reply.txt')
    result = set_email_reply('06/21/2020 16:36:04', 'test@gmail.com', '["test1@gmail.com"]', 'test2@gmail.com', 'test')
    assert result in expected_result
