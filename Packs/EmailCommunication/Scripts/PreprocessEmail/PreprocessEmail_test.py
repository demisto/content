def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def test_set_email_reply():
    """Unit test
        Given
        - email author, email recipients and email cc.
        When
        - setting the email reply.
        Then
        - validate that the email reply is in the correct format.
        """
    from PreprocessEmail import set_email_reply
    expected_result = util_open_file('test_data/email_reply.txt')
    result = set_email_reply('test@gmail.com', '["test1@gmail.com"]', 'test2@gmail.com', 'test')
    assert result in expected_result
