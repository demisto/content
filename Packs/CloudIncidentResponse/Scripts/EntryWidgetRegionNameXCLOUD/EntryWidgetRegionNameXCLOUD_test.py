import unittest
from unittest.mock import patch
from EntryWidgetRegionNameXCLOUD import main
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

CASES =[({
            'Core': {
                'OriginalAlert': {
                    'event': {'region': 'TestRegion'}
                }
            }
        }),({
            'Core': {
                'OriginalAlert': [{
                    'event': {'region': 'TestRegion'}
                }]
            }
        })]


class TestYourScript(unittest.TestCase):


    @patch('demistomock.context')
    @patch('CommonServerPython.return_results')
    @pytest.mark.parametrize('input', CASES)
    def test_main_success(self, mock_return_results, mock_context, input):
        # Mocking context() to return a sample alert
        mock_context.return_value.get.return_value = input

        # Calling the main function
        main()

        # Assertions
        mock_return_results.assert_called_once_with({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': "<h1 style='color:#555555;text-align:center;font-size:200%;'>TestRegion</h1>",
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
