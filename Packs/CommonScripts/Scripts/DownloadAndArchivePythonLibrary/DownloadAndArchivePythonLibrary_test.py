import unittest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import shlex
import subprocess
from tempfile import mkdtemp
from DownloadAndArchivePythonLibrary import installLibrary, main, DemistoException


class TestDownloadAndArchivePythonLibrary(unittest.TestCase):

    @patch('DownloadAndArchivePythonLibrary.subprocess.Popen')
    @patch('DownloadAndArchivePythonLibrary.zipfile.ZipFile')
    @patch('DownloadAndArchivePythonLibrary.os.walk')
    @patch('builtins.open', new_callable=mock_open)
    def test_install_library_success(self, mock_open, mock_os_walk, mock_zipfile, mock_popen):
        # Set up mock for subprocess.Popen
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'stdout', b'stderr')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        # Set up mock for os.walk
        mock_os_walk.return_value = [('/path/to/dir', ['subdir'], ['file1.py', 'file2.py'])]

        # Set up mock for zipfile.ZipFile
        mock_zip = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip

        # Set up mock for open
        mock_file = MagicMock()
        mock_open.return_value = mock_file

        dir_path = Path('/path/to/dir')
        library_name = 'kubernetes'

        # Call the function to test
        result = installLibrary(dir_path, library_name)

        # Asserts
        mock_popen.assert_called_once_with(shlex.split(f'python3 -m pip install --target {dir_path} kubernetes'),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        mock_os_walk.assert_called_once_with(dir_path)
        mock_zipfile.assert_called_once_with(dir_path / (library_name + '.zip'), 'w', compression=zipfile.ZIP_DEFLATED,
                                             compresslevel=9)
        mock_open.assert_called_once_with(dir_path / (library_name + '.zip'), 'rb')
        self.assertTrue(result.endswith('.zip'))

    @patch('DownloadAndArchivePythonLibrary.subprocess.Popen')
    def test_install_library_failure(self, mock_popen):
        # Set up mock for subprocess.Popen
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'stdout', b'error')
        mock_process.returncode = 1
        mock_popen.return_value = mock_process

        with self.assertRaises(DemistoException):
            installLibrary(Path('/path/to/dir'), 'library_name')

    @patch('DownloadAndArchivePythonLibrary.os.walk')
    @patch('DownloadAndArchivePythonLibrary.zipfile.ZipFile')
    @patch('builtins.open', new_callable=mock_open)
    def test_install_library_no_files(self, mock_open, mock_zipfile, mock_os_walk):
        # Set up mock for os.walk with no files
        mock_os_walk.return_value = []

        # Set up mock for zipfile.ZipFile
        mock_zip = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip

        dir_path = Path('/path/to/dir')
        library_name = 'library_name'

        # Call the function to test
        result = installLibrary(dir_path, library_name)

        # Asserts
        mock_os_walk.assert_called_once_with(dir_path)
        mock_zipfile.assert_called_once_with(dir_path / (library_name + '.zip'), 'w', compression=zipfile.ZIP_DEFLATED,
                                             compresslevel=9)
        mock_open.assert_called_once_with(dir_path / (library_name + '.zip'), 'rb')
        self.assertTrue(result.endswith('.zip'))

    @patch('DownloadAndArchivePythonLibrary.mkdtemp')
    @patch('DownloadAndArchivePythonLibrary.installLibrary')
    @patch('DownloadAndArchivePythonLibrary.return_results')
    @patch('DownloadAndArchivePythonLibrary.return_error')
    def test_main_success(self, mock_return_error, mock_return_results, mock_installLibrary, mock_mkdtemp):
        # Set up mock for mkdtemp
        mock_mkdtemp.return_value = '/path/to/dir'

        # Set up mock for installLibrary
        mock_result = MagicMock()
        mock_installLibrary.return_value = mock_result

        # Set up mock for demisto.args()
        with patch('DownloadAndArchivePythonLibrary.demisto.args', return_value={'library_name': 'library_name'}):
            main()

        # Asserts
        mock_mkdtemp.assert_called_once_with(prefix='python')
        mock_installLibrary.assert_called_once_with(Path('/path/to/dir'), 'library_name')
        mock_return_results.assert_called_once_with(mock_result)
        mock_return_error.assert_not_called()

    @patch('DownloadAndArchivePythonLibrary.mkdtemp')
    @patch('DownloadAndArchivePythonLibrary.installLibrary')
    @patch('DownloadAndArchivePythonLibrary.return_results')
    @patch('DownloadAndArchivePythonLibrary.return_error')
    def test_main_failure(self, mock_return_error, mock_return_results, mock_installLibrary, mock_mkdtemp):
        # Set up mock for mkdtemp
        mock_mkdtemp.return_value = '/path/to/dir'

        # Set up mock for installLibrary to raise exception
        mock_installLibrary.side_effect = Exception("Test exception")

        # Set up mock for demisto.args()
        with patch('DownloadAndArchivePythonLibrary.demisto.args', return_value={'library_name': 'library_name'}):
            main()

        # Asserts
        mock_mkdtemp.assert_called_once_with(prefix='python')
        mock_installLibrary.assert_called_once_with(Path('/path/to/dir'), 'library_name')
        mock_return_error.assert_called_once_with("An error occurred: Test exception")
        mock_return_results.assert_not_called()


if __name__ == '__main__':
    unittest.main()
