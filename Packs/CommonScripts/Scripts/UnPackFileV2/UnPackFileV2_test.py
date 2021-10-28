import rarfile


def test_extract(tmpdir):
    from UnPackFileV2 import extract
    rf = rarfile.RarFile('./test_data/rar3-archive-example.rar')
    res, files = extract(rf, tmpdir)
    assert res.outputs == ['file2.txt', 'long fn.txt', 'file.txt', 'file1.txt']
    assert len(files) == 4
