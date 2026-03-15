from anyrun.connectors.sandbox.operation_systems import WindowsConnector, LinuxConnector, AndroidConnector
from AnyRunSandbox import get_authentication, build_context_path


def test_get_authentication_add_a_valid_prefix():
    params = {"credentials": {"password": "asdAD13SADm1"}}
    assert get_authentication(params) == "API-KEY asdAD13SADm1"


def test_build_context_path_returns_a_valid_path_according_to_the_connector_instance():
    assert build_context_path("file", WindowsConnector(api_key="test")) == "ANYRUN_DetonateFileWindows.TaskID"
    assert build_context_path("file", LinuxConnector(api_key="test")) == "ANYRUN_DetonateFileLinux.TaskID"
    assert build_context_path("file", AndroidConnector(api_key="test")) == "ANYRUN_DetonateFileAndroid.TaskID"

    assert build_context_path("url", WindowsConnector(api_key="test")) == "ANYRUN_DetonateUrlWindows.TaskID"
    assert build_context_path("url", LinuxConnector(api_key="test")) == "ANYRUN_DetonateUrlLinux.TaskID"
    assert build_context_path("url", AndroidConnector(api_key="test")) == "ANYRUN_DetonateUrlAndroid.TaskID"
