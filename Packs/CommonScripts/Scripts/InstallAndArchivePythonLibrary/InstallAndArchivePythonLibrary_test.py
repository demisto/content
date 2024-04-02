import unittest
from unittest.mock import patch, MagicMock
from InstallAndArchivePythonLibrary import installLibrary  # Replace 'InstallAndArchivePythonLibrary' with the name of your Python file

class TestInstallAndArchivePythonLibrary(unittest.TestCase):

    @patch('InstallAndArchivePythonLibrary.subprocess.Popen')
    @patch('InstallAndArchivePythonLibrary.zipfile.ZipFile')
    @patch('InstallAndArchivePythonLibrary.os.walk')
    @patch('InstallAndArchivePythonLibrary.open')
    def test_install_library(self, mock_open, mock_os_walk, mock_zipfile, mock_popen):
        # Set up mock for subprocess.Popen
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'stdout', b'stderr')
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        # Set up mock for os.walk
        mock_os_walk.return_value = [('/path/to/dir', ['subdir'], ['file1.py', 'file2.py'])]

        # Set up mock for zipfile.ZipFile
        mock_zip = MagicMock()
        mock_zipfile.return_value = mock_zip

        # Set up mock for open
        mock_file = MagicMock()
        mock_open.return_value = mock_file

        # Call the function to test
        result = installLibrary('/path/to/dir', 'library_name')

        # Asserts
        mock_popen.assert_called_once_with(['python3', '-m', 'pip', 'install', '--target', '/path/to/dir', 'library_name'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        mock_os_walk.assert_called_once_with('/path/to/dir')
        mock_zipfile.assert_called_once_with('library_name.zip', 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9)
        mock_open.assert_called_once_with('library_name.zip', 'rb')
        self.assertEqual(result, 'fileResult content')  # Replace 'fileResult content' with the expected result

if __name__ == '__main__':
    unittest.main()
