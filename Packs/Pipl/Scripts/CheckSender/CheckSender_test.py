from CheckSender import get_sender_from_text, format_data


def test_get_sender_from_text():
    """
    Given:
        - Text with email address.
    When:
        - Running the get_sender_from_text function.
    Then:
        - Validating the sender email is correct.
    """
    sender = get_sender_from_text("from: test1@gmail.com")
    assert sender == "test1@gmail.com"


def test_get_sender_from_text_no_address_found():
    """
    Given:
        - Text without email address.
    When:
        - Running the get_sender_from_text function.
    Then:
        - Validating the sender email is empty.
    """
    sender = get_sender_from_text("from: test1gmail.com")
    assert sender == ""


def test_format_data():
    """
    Given:
        - data output from pipl-search command.
    When:
        - Running the format_data function.
    Then:
        - Validating the outputs as expected.
    """
    data = format_data([{"Account": {"IDs": "1,2,3", "Addresses": ["test1@gmail.com", "test2@gmail.com"]}}])
    assert data == [{"Account": "IDs: 1,2,3\nAddresses: test1@gmail.com,\ntest2@gmail.com"}]
