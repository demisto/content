from NetskopeBuildProtocolsJson import build_protocols_json


def test_build_protocols_json_single_port():
    """
    Given:
        - A single port and protocol type.
    When:
        - Running build_protocols_json.
    Then:
        - A JSON array with one {type, port} object is returned.
    """
    result = build_protocols_json(["443"], "tcp")
    assert result == '[{"type": "tcp", "port": "443"}]'


def test_build_protocols_json_multiple_ports():
    """
    Given:
        - Multiple ports and a protocol type.
    When:
        - Running build_protocols_json.
    Then:
        - A JSON array with one object per port, all sharing the same type, is returned.
    """
    result = build_protocols_json(["443", "8080", "22"], "tcp")
    assert result == '[{"type": "tcp", "port": "443"}, {"type": "tcp", "port": "8080"}, {"type": "tcp", "port": "22"}]'


def test_build_protocols_json_no_ports():
    """
    Given:
        - No ports.
    When:
        - Running build_protocols_json.
    Then:
        - An empty string is returned (leaves "protocols" unset rather than an empty array).
    """
    assert build_protocols_json([], "tcp") == ""
