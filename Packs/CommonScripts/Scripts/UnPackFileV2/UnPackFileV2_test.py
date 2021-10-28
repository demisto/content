import rarfile


def test_extract(tmpdir):
    from UnPackFileV2 import extract
    rf = rarfile.RarFile('./test_data/rar3-archive-example.rar')
    res, files = extract(rf, tmpdir)
    assert set(res.outputs) == {'long fn.txt', 'file2.txt', 'file1.txt', 'file.txt'}
