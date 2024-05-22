import unittest
from unittest.mock import patch, mock_open, MagicMock, call
from pathlib import Path
from script import installLibrary, main

class TestScript(unittest.TestCase):

    @patch('demistomock.args')
    @patch('demistomock.return_results')
    @patch('demistomock.return_error')
    def setUp(self, mock_args, mock_return_results, mock_return_error):
        self.mock_args = mock_args
        self.mock_return_results = mock_return_results
        self.mock_return_error = mock_return_error

    @patch('subprocess.Popen')
    @patch('os.walk')
    @patch('zipfile.ZipFile')
    @patch('builtins.open', new_callable=mock_open)
    def test_install_library_success(self, mock_file, mock_zipfile, mock_os_walk, mock_popen):
        mock_popen.return_value.communicate.return_value = (b'success', b'')
        mock_popen.return_value.returncode = 0

        mock_os_walk.return_value = [('/path', ('dir',), ('file.py',))]

        dir_path = Path('/mock/path')
        library_name = 'testlib'

        result = installLibrary(dir_path, library_name)

        # Check
        mock_popen.assert_called_once_with(shlex.split(f'python3 -m pip install --target {dir_path} {library_name}'),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        mock_popen.return_value.communicate.assert_called_once()
        mock_zipfile.assert_called_once_with(dir_path / (library_name + '.zip'), 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9)
        mock_file.assert_called_once_with(dir_path / (library_name + '.zip'), 'rb')
        self.assertEqual(result['File'], f'{library_name}.zip')

    @patch('subprocess.Popen')
    def test_install_library_failure(self, mock_popen):
        mock_popen.return_value.communicate.return_value = (b'', b'error')
        mock_popen.return_value.returncode = 1

        dir_path = Path('/mock/path')
        library_name = 'testlib'

        with self.assertRaises(Exception) as context:
            installLibrary(dir_path, library_name)

        # Check
        self.assertIn("Failed to install the testlib library", str(context.exception))

    @patch('demistomock.args')
    @patch('demistomock.return_results')
    @patch('demistomock.return_error')
    @patch('subprocess.Popen')
    @patch('os.walk')
    @patch('zipfile.ZipFile')
    @patch('builtins.open', new_callable=mock_open)
    def test_main_success(self, mock_file, mock_zipfile, mock_os_walk, mock_popen, mock_return_error, mock_return_results, mock_args):
        mock_args.return_value = {'library_name': 'testlib'}
        mock_popen.return_value.communicate.return_value = (b'success', b'')
        mock_popen.return_value.returncode = 0
        mock_os_walk.return_value = [('/path', ('dir',), ('file.py',))]

        main()

        # Check
        mock_return_results.assert_called_once()
        mock_return_error.assert_not_called()

    @patch('demistomock.args')
    @patch('demistomock.return_results')
    @patch('demistomock.return_error')
    @patch('subprocess.Popen')
    def test_main_failure(self, mock_popen, mock_return_error, mock_return_results, mock_args):
        mock_args.return_value = {'library_name': 'testlib'}
        mock_popen.return_value.communicate.return_value = (b'', b'error')
        mock_popen.return_value.returncode = 1

        main()

        # Check
        mock_return_results.assert_not_called()
        mock_return_error.assert_called_once()

if __name__ == '__main__':
    unittest.main()
