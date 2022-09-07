from CheckSender import get_sender_from_text


def test_get_sender_from_text():
    """
    Given:
        - Text with email address.
    When:
        - Running the get_sender_from_text function.
    Then:
        - Validating the sender email is correct.
    """
    sender = get_sender_from_text('from: test1@gmail.com')
    assert sender == 'test1@gmail.com'
