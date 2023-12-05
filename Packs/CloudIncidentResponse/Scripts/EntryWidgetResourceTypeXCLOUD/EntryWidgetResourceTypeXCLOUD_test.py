import unittest
from unittest.mock import patch, MagicMock
from EntryWidgetResourceTypeXCLOUD import main

class TestYourSecondScript(unittest.TestCase):

    @patch('demistomock.context')
    @patch('CommonServerPython.return_results')
    def test_main_success(self, mock_return_results, mock_context):
        # Mocking context() to return a sample alert
        mock_context.return_value.get.return_value = {
            'Core': {
                'OriginalAlert': {
                    'event': {'resource_type_orig': 'TestResourceType'}
                }
            }
        }

        # Calling the main function
        main()

        # Assertions
        mock_return_results.assert_called_once_with({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': "<h1 style='color:#555555;text-align:center;font-size:200%;'>TestResourceType</h1>",
        })

    @patch('demistomock.context')
    @patch('CommonServerPython.return_error')
    def test_main_error(self, mock_return_error, mock_context):
        # Mocking context() to raise an exception
        mock_context.return_value.get.side_effect = Exception('TestError')

        # Calling the main function
        main()

        # Assertions
        mock_return_error.assert_called_once_with("An error occurred: TestError")


if __name__ == '__main__':
    unittest.main()
