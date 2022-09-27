from OletoolsScript import *
from test_data.commands_outputs import oleid_output, oleobj_output, olevba_otuput, oleid_decrypted_output
import pytest


def read_file(file_path):
    with open(file_path) as f:
        file_data = f.read()
        return file_data


def test_oleid(caplog):
    ole_client = OleClient({
        'path': 'test_data/ActiveBarcode-Demo-Bind-Text.docm',
        'name': 'ActiveBarcode-Demo-Bind-Text.docm'}, 'oleid')
    caplog.clear()
    cr = ole_client.run()
    assert cr.outputs == oleid_output
    assert cr.readable_output == read_file('test_data/oleid_readable.md')


def test_oleobj():
    ole_client = OleClient({
        'path': 'test_data/ActiveBarcode-Demo-Bind-Text.docm',
        'name': 'ActiveBarcode-Demo-Bind-Text.docm'}, 'oleobj')
    cr = ole_client.run()
    assert cr.outputs == oleobj_output
    assert cr.readable_output == read_file('test_data/oleobj_readable.md')


def test_olevba(caplog):
    ole_client = OleClient({
        'path': 'test_data/ActiveBarcode-Demo-Bind-Text.docm',
        'name': 'ActiveBarcode-Demo-Bind-Text.docm'}, 'olevba')
    caplog.clear()
    cr = ole_client.run()
    assert cr.outputs == olevba_otuput
    assert cr.readable_output == read_file('test_data/olevba_readable.md')


def test_oleid_decrypted(caplog):
    ole_client = OleClient({
        'path': 'test_data/protected.docm',
        'name': 'ActiveBarcode-Demo-Bind-Text.docm'}, 'oleid', '123123')
    caplog.clear()
    cr = ole_client.run()
    assert cr.outputs == oleid_decrypted_output
    assert cr.readable_output == read_file('test_data/oleid_decrypted_readable.md')


@pytest.mark.parametrize('password, non_secret_password, returned_password',
                         [('123', '', '123'),
                          ('', '666', '666'),
                          ('', '', ''),
                          pytest.param('123', '123', False, marks=pytest.mark.xfail)])
def test_handle_password(password, non_secret_password, returned_password):
    assert returned_password == handle_password(password=password, non_secret_password=non_secret_password)
