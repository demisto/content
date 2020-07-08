import pytest
import demistomock as demisto
from PyDT import py_dt


def test_string():
    x = py_dt('x = "This is a string"')
    assert x == None


if __name__ == '__main__':
    test_string()
