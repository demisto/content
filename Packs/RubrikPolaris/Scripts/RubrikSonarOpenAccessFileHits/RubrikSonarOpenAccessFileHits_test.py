import unittest
from unittest.mock import patch

from RubrikSonarOpenAccessFileHits import entryTypes, formats, main


class TestMain(unittest.TestCase):

    @patch('demistomock.context')
    @patch('demistomock.results')
    def test_main_with_no_radar_open_access_files(self, mock_results, mock_context):
        # Test case: When there are no radar open access files
        mock_context.return_value = {"Rubrik": {"Sonar": {"openAccessFilesWithHits": None}}}

        # Call the main function
        main()

        # Assert the results
        mock_results.assert_called_with({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': ('<div style=display:block;text-align:center;><h1 style=color:#00CD33;'
                         'font-size:275%;>None</h1></div>')
        })

    @patch('demistomock.context')
    @patch('demistomock.results')
    def test_main_with_radar_open_access_files(self, mock_results, mock_context):
        # Test case: When there are radar open access files
        mock_context.return_value = {"Rubrik": {"Sonar": {"openAccessFilesWithHits": 1}}}

        # Call the main function
        main()

        # Assert the results
        mock_results.assert_called_with({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': ('<div style=display:block;text-align:center;><h1 style=color:#FF1744;'
                         'font-size:275%;>1</h1></div>')
        })

    @patch('demistomock.context')
    @patch('demistomock.results')
    def test_main_with_key_error(self, mock_results, mock_context):
        # Test case: When the necessary information is not found in the demisto context
        mock_context.side_effect = KeyError

        # Call the main function
        main()

        # Assert the results
        mock_results.assert_called_with({
            'ContentsFormat': formats['html'],
            'Type': entryTypes['note'],
            'Contents': ('<div style=display:block;text-align:center;><h1 style=color:#FF9000;'
                         'font-size:250%;>No Results Found</h1></div>')
        })


if __name__ == '__main__':
    unittest.main()
