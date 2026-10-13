import NetskopeBuildProtocolsJson
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


def test_main_builds_protocols_json(mocker):
    """
    Given:
        - Ports containing whitespace and an uppercase protocol type.
    When:
        - Running the automation entry point.
    Then:
        - The arguments are normalized and the generated JSON is returned in context.
    """
    mocker.patch.object(
        NetskopeBuildProtocolsJson.demisto,
        "args",
        return_value={"ports": "443, 8080", "protocol_type": "TCP"},
    )
    return_results = mocker.patch.object(NetskopeBuildProtocolsJson, "return_results")

    NetskopeBuildProtocolsJson.main()

    command_results = return_results.call_args.args[0]
    assert command_results.outputs == {"ProtocolsJson": '[{"type": "tcp", "port": "443"}, {"type": "tcp", "port": "8080"}]'}
    assert "2 port(s)" in command_results.readable_output


def test_main_without_ports_returns_empty_output(mocker):
    """
    Given:
        - No ports and no protocol type.
    When:
        - Running the automation entry point.
    Then:
        - The automation returns an empty ProtocolsJson value without failing.
    """
    mocker.patch.object(NetskopeBuildProtocolsJson.demisto, "args", return_value={})
    return_results = mocker.patch.object(NetskopeBuildProtocolsJson, "return_results")

    NetskopeBuildProtocolsJson.main()

    command_results = return_results.call_args.args[0]
    assert command_results.outputs == {"ProtocolsJson": ""}
    assert "No ports provided" in command_results.readable_output
