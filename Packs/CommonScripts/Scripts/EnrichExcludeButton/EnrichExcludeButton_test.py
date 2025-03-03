from EnrichExcludeButton import main

from unittest.mock import patch


@patch('EnrichExcludeButton.return_error')  # Mock the return_error function in the script module
def test_main(mock_return_error):
    # Call the main function
    main()

    # Assert return_error was called once with the correct message
    mock_return_error.assert_called_once_with("\nThis indicator is enrich excluded")
