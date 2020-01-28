import shutil

from UnzipFile import *
import os
import pytest


data_test_extract = [
    ('testZip.yml', None),
    ('ScanSummary.txt', None),
    ('item.png', None),
    ('fix_unzip.png', 'demisto'),
]


@pytest.mark.parametrize('file_name, password', data_test_extract)
def test_extract(file_name, password):
    main_dir = '/'.join(__file__.split('/')[0:-1])
    _dir = mkdtemp()
    path = os.path.join(main_dir + '/data_test', file_name)
    extract(path + '.zip', _dir, password)
    with open(_dir + '/' + file_name, 'rb') as f:
        extract_file = f.read()
    with open(path, 'rb') as f:
        _file = f.read()
    assert _file == extract_file
    shutil.rmtree(_dir)
