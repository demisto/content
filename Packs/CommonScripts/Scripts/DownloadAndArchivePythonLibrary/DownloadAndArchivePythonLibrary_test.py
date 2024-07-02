import unittest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
from tempfile import mkdtemp
import zipfile
import os
import subprocess

# Import the functions from the script
from DownloadAndArchivePythonLibrary import installLibrary, main  # Replace 'DownloadAndArchivePythonLibrary' with the actual script name

class TestInstallLibrary(unittest.TestCase):
    @patch('DownloadAndArchivePythonLibrary.subprocess.Popen')
    @patch('DownloadAndArchivePythonLibrary.Path.mkdir')
    @patch('DownloadAndArchivePythonLibrary.zipfile.ZipFile')
    @patch('DownloadAndArchivePythonLibrary.open', new_callable=mock_open, read_data=b'test data')
    @patch('DownloadAndArchivePythonLibrary.mkdtemp')
    def test_installLibrary(self, mock_mkdtemp, mock_open, mock_zipfile, mock_mkdir, mock_popen):
        # Prepare
        mock_dir_path = Path('/fake/dir')
        mock_mkdtemp.return_value = mock_dir_path

        mock_popen_instance = MagicMock()
        mock_popen_instance.communicate.return_value = (b'success', b'')
        mock_popen_instance.returncode = 0
        mock_popen.return_value = mock_popen_instance

        mock_zipfile_instance = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_zipfile_instance

        # Run
        result = installLibrary(mock_dir_path, 'fake_library')

        # Check
        # Ensure subprocess was called with the correct command
        mock_popen.assert_called_once_with(
            ['python3', '-m', 'pip', 'install', '--target', str(mock_dir_path), 'fake_library'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Ensure zipfile was created with the correct path and mode
        mock_zipfile.assert_called_once_with(mock_dir_path / 'fake_library.zip', 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9)

        # Ensure file was opened with the correct path and mode
        mock_open.assert_called_once_with(mock_dir_path / 'fake_library.zip', 'rb')

        # Ensure the correct result is returned
        self.assertEqual(result, ('fake_library.zip', b'test data'))

    @patch('DownloadAndArchivePythonLibrary.installLibrary')
    @patch('DownloadAndArchivePythonLibrary.demisto.args')
    @patch('DownloadAndArchivePythonLibrary.return_results')
    @patch('DownloadAndArchivePythonLibrary.return_error')
    @patch('DownloadAndArchivePythonLibrary.Path')
    @patch('DownloadAndArchivePythonLibrary.mkdtemp')
    def test_main_success(self, mock_mkdtemp, mock_path, mock_return_error, mock_return_results, mock_args, mock_installLibrary):
        # Prepare
        mock_args.return_value = {'library_name': 'fake_library'}
        mock_dir_path = Path('/fake/dir')
        mock_mkdtemp.return_value = mock_dir_path

        mock_result = 'fake_result'
        mock_installLibrary.return_value = mock_result

        # Run
        main()

        # Check
        mock_return_results.assert_called_once_with(mock_result)
        mock_return_error.assert_not_called()

    @patch('DownloadAndArchivePythonLibrary.installLibrary')
    @patch('DownloadAndArchivePythonLibrary.demisto.args')
    @patch('DownloadAndArchivePythonLibrary.return_results')
    @patch('DownloadAndArchivePythonLibrary.return_error')
    @patch('DownloadAndArchivePythonLibrary.Path')
    @patch('DownloadAndArchivePythonLibrary.mkdtemp')
    def test_main_failure(self, mock_mkdtemp, mock_path, mock_return_error, mock_return_results, mock_args, mock_installLibrary):
        # Prepare
        mock_args.return_value = {'library_name': 'fake_library'}
        mock_dir_path = Path('/fake/dir')
        mock_mkdtemp.return_value = mock_dir_path

        mock_installLibrary.side_effect = Exception('Test Exception')

        # Run
        main()

        # Check
        mock_return_error.assert_called_once_with('An error occurred: Test Exception')
        mock_return_results.assert_not_called()

if __name__ == '__main__':
    unittest.main()
