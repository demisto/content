import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from DecodeMimeHeader import decode


def test_decode():
    s = "=?iso-8859-1?q?p=F6stal?="
    res = decode(s)
    assert res == "pöstal"
