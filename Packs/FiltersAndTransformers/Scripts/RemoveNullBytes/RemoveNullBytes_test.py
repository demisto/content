import pytest
import base64
from RemoveNullBytes import removenullbytes

"""
First base64 encoded data when decoded contains null bytes
"""


@pytest.mark.parametrize(
    "value, expected_result",
    [
        ("cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlAA==", "powershell.exe"),
        ("Y21kLmV4ZQ==", "cmd.exe"),
    ],
)
def test_removenullbytes(value, expected_result):
    base64decoded = base64.b64decode(value).decode("latin1")
    value = removenullbytes(base64decoded)
    assert value == expected_result
