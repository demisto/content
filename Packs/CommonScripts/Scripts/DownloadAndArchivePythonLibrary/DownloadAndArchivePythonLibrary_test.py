import unittest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import zipfile
import subprocess

# Import the functions from the script
from DownloadAndArchivePythonLibrary import installLibrary, main


class TestInstallLibrary(unittest.TestCase):
    @patch('DownloadAndArchivePythonLibrary.subprocess.Popen')
    @patch('DownloadAndArchivePythonLibrary.zipfile.ZipFile')
    @patch('DownloadAndArchivePythonLibrary.os.walk')
    @patch('DownloadAndArchivePythonLibrary.mkdtemp')
    @patch('DownloadAndArchivePythonLibrary.open', new_callable=mock_open, read_data=b'test data')
    @patch('DownloadAndArchivePythonLibrary.fileResult')
    def test_installLibrary(self, mock_fileResult, mock_open, mock_mkdtemp, mock_os_walk, mock_zipfile, mock_popen):
        # Prepare
        mock_dir_path = Path('/fake/dir')
        mock_mkdtemp.return_value = mock_dir_path

        mock_popen_instance = MagicMock()
        mock_popen_instance.communicate.return_value = (b'success', b'')
        mock_popen_instance.returncode = 0
        mock_popen.return_value = mock_popen_instance

        mock_zipfile_instance = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_zipfile_instance

        mock_os_walk.return_value = [('/fake/dir', ('subdir',), ('file1.py', 'file2.py'))]

        expected_result = {
            'Type': 3,
            'File': 'fake_library.zip',
            'FileID': 'fake_library.zip',
            'Contents': b'test data',
            'ContentsFormat': 'text'
        }
        mock_fileResult.return_value = expected_result

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
        mock_zipfile.assert_called_once_with(mock_dir_path / 'fake_library.zip', 'w',
                                             compression=zipfile.ZIP_DEFLATED, compresslevel=9)

        # Ensure files were added to the zip archive
        expected_arcnames = [Path('python') / 'file1.py', Path('python') / 'file2.py']
        mock_zipfile_instance.write.assert_any_call(Path('/fake/dir/file1.py'), arcname=expected_arcnames[0])
        mock_zipfile_instance.write.assert_any_call(Path('/fake/dir/file2.py'), arcname=expected_arcnames[1])

        # Ensure the correct result is returned
        assert result == expected_result

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

        expected_result = {
            'Type': 3,
            'File': 'fake_library.zip',
            'FileID': 'fake_library.zip',
            'Contents': b'test data',
            'ContentsFormat': 'text'
        }
        mock_installLibrary.return_value = expected_result

        # Run
        main()

        # Check
        mock_return_results.assert_called_once_with(expected_result)
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
