import json
import os
import subprocess
import sys
import textwrap
from io import BytesIO
from unittest import mock

import demistomock as demisto
from ValidateContent import (
    HOOK_ID_TO_PATTERN,
    ValidationResult,
    extract_hook_id,
    get_pack_name,
    parse_pre_commit_output,
    read_validate_results,
    resolve_entity_type,
    strip_ansi_codes,
)


def create_mock_zip_file_with_metadata(metadata_content):
    """
    Helper function to create a mock zip file with metadata.json

    Args:
        metadata_content:

    Returns:
        mock_zip: a mock zip file with metadata.json containing metadata_content.
    """

    mock_zip = mock.MagicMock()
    mock_metadata_file = BytesIO(json.dumps(metadata_content).encode("utf-8"))

    def mock_open(name, *args, **kwargs):
        if name == "metadata.json":
            return mock_metadata_file
        raise KeyError(f"No such file: {name}")

    mock_zip.open = mock_open
    return mock_zip


def test_strip_ansi_codes():
    ansi_text = "\033[31mRed text\033[0m"
    assert strip_ansi_codes(ansi_text) == "Red text"


def test_extract_hook_id():
    output = "Running hook: check-ast\n- hook id: check-ast\nAn error occurred"
    assert extract_hook_id(output) == "check-ast"
    assert extract_hook_id("No hook id") == ""


def test_parse_pre_commit_output_check_ast():
    output = """check python ast.........................................................Failed
- hook id: check-ast
- exit code: 1

Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py: failed parsing with CPython 3.11.10:

 Traceback (most recent call last):
 File "/root/.cache/pre-commit/repopc0svvoh/py_env-python3.11/lib/python3.11/site-packages/pre_commit_hooks/check_ast.py",
  line 21, in main
 ast.parse(f.read(), filename=filename)
 File "/usr/local/lib/python3.11/ast.py", line 50, in parse
 return compile(source, filename, mode, flags,
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 File "Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py", line 1413
 elif command == 'hello
 ^
 SyntaxError: unterminated string literal (detected at line 1413)"""

    pattern_obj = HOOK_ID_TO_PATTERN["check-ast"]
    result = parse_pre_commit_output(output, pattern_obj)
    assert result == [{"file": "Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py", "line": "1413"}]


def test_parse_pre_commit_output_mypy():
    output = """mypy-py3.11..............................................................Failed
- hook id: mypy
- exit code: 1

Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py:791: error: Name
"greet" is not defined  [name-defined]
        greet(inp)
        ^
Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py:791: error: Name
"inp" is not defined  [name-defined]
        greet(inp)
              ^
Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py:794: error: Name
"by" is not defined  [name-defined]
        by({'arrrr': 'rrrrra', 'rrrraa': 'rapapapu'})
        ^
Found 3 errors in 1 file (checked 1 source file)"""
    pattern_obj = HOOK_ID_TO_PATTERN["mypy"]
    result = parse_pre_commit_output(output, pattern_obj)
    assert result == [
        {
            "file": "Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py",
            "line": "791",
            "details": """Name
"greet" is not defined  [name-defined]
        greet(inp)
        ^""",
        },
        {
            "file": "Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py",
            "line": "791",
            "details": """Name
"inp" is not defined  [name-defined]
        greet(inp)
              ^""",
        },
        {
            "file": "Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py",
            "line": "794",
            "details": """Name
"by" is not defined  [name-defined]
        by({'arrrr': 'rrrrra', 'rrrraa': 'rapapapu'})
        ^""",
        },
    ]


def test_resolve_entity_type():
    assert resolve_entity_type("Packs/SomePack/Integrations/SomeIntegration") == "integration"
    assert resolve_entity_type("Packs/SomePack/Scripts/SomeScript") == "script"
    assert resolve_entity_type("Packs/SomePack/Playbooks/SomePlaybook") == "playbook"
    assert resolve_entity_type("Packs/SomePack/TestPlaybooks/SomeTestPlaybook") == "testplaybook"
    assert resolve_entity_type("Packs/SomePack/") == "contentpack"


def test_get_pack_name_success(mocker):
    """
    Given:
        A valid zip file path with a metadata.json file containing a pack name.
    When:
        Calling get_pack_name with the zip file path.
    Then:
        The function should return the correct pack name from the metadata.json file.
    """
    mock_metadata = {"name": "TestPack"}
    mock_metadata_json = json.dumps(mock_metadata)

    mock_zipfile = mocker.MagicMock()
    mock_metadata_file = mocker.MagicMock()
    mock_metadata_file.read.return_value = mock_metadata_json
    # Simulate behaviour of nested context managers.
    mock_zipfile.__enter__.return_value.open.return_value.__enter__.return_value = mock_metadata_file

    mocker.patch("zipfile.ZipFile", return_value=mock_zipfile)

    result = get_pack_name("test_pack.zip")

    assert result == "TestPack"


def test_get_pack_name_no_name(mocker):
    """
    Given:
        A valid zip file path with a metadata.json file that doesn't contain a pack name.
    When:
        Calling get_pack_name with the zip file path.
    Then:
        The function should return 'TmpPack' as the default pack name.
    """
    mock_metadata = {}
    mock_metadata_json = json.dumps(mock_metadata)

    mock_zipfile = mocker.MagicMock()
    mock_metadata_file = mocker.MagicMock()
    mock_metadata_file.read.return_value = mock_metadata_json
    mock_zipfile.__enter__.return_value.open.return_value.__enter__.return_value = mock_metadata_file

    mocker.patch("zipfile.ZipFile", return_value=mock_zipfile)
    mock_error = mocker.patch.object(demisto, "error")

    result = get_pack_name("test_pack.zip")
    assert result == "TmpPack"
    mock_error.assert_called_with("Could not find pack name in metadata.json")


def test_read_validate_results(tmp_path):
    """
    Given:
        A temporary JSON file with validation results.
    When:
        Calling read_validate_results with the path to this file.
    Then:
        The function should return a list of ValidationResult objects.
    """
    json_file = tmp_path / "validation_results.json"
    json_file.write_text(
        json.dumps(
            [
                {
                    "validations": [
                        {
                            "file path": "Packs/TestPack/Scripts/TestScript/TestScript.yml",
                            "error code": "ST001",
                            "message": "Test error message",
                        }
                    ]
                }
            ]
        )
    )

    results = read_validate_results(json_file)

    assert len(results) == 1
    assert isinstance(results[0], ValidationResult)
    assert results[0].filePath.endswith("Packs/TestPack/Scripts/TestScript/TestScript.yml")
    assert results[0].errorCode == "ST001"
    assert results[0].message == "Test error message"


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _run_in_subprocess(body: str) -> subprocess.CompletedProcess:
    """
    Execute `body` in a fresh interpreter that imports ValidateContent.

    A subprocess is required because the stdout firewall manipulates the
    OS-level file descriptor 1 at import time. Doing that in-process would
    hijack pytest's own stdout for the remainder of the session.
    """
    program = textwrap.dedent(body)
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        cwd=SCRIPT_DIR,
        timeout=60,
        check=False,
    )


def test_stdout_firewall_blocks_library_output_from_reaching_stdout():
    """
    Given: A third-party library writing plain text to stdout, both via Python's
           `print` and directly to the OS-level file descriptor 1 (as
           demisto-sdk's rich consoles and subprocesses do).
     When: The module-level stdout firewall of ValidateContent is armed.
     Then: None of that text reaches the real stdout, so the JSON entry XSOAR
           reads stays parsable. This reproduces the server-side failure
           "invalid character 'P' looking for beginning of value".
    """
    result = _run_in_subprocess(
        """
        import json, os, sys
        import ValidateContent as vc

        # Python-level print (e.g. demisto-sdk progress output).
        print("Preparing content packs for validation")
        # Direct fd-1 write, which contextlib.redirect_stdout cannot intercept.
        os.write(1, b"Packs/HelloWorld/Integrations leaked from a rich console\\n")

        vc.restore_real_stdout()
        # Only this JSON entry may appear on the real stdout.
        sys.stdout.write(json.dumps({"Type": 1, "Contents": "ok"}))
        """
    )

    assert result.returncode == 0, result.stderr
    # The whole stdout must be exactly one JSON document - the entry.
    assert json.loads(result.stdout) == {"Type": 1, "Contents": "ok"}
    assert "Preparing" not in result.stdout
    assert "Packs/HelloWorld" not in result.stdout


def test_captured_stdout_is_preserved_for_debugging():
    """
    Given: Library output that the firewall diverted away from stdout.
     When: `read_captured_stdout` is called.
     Then: The text is still retrievable, so suppressing it does not destroy
           debugging information.
    """
    result = _run_in_subprocess(
        """
        import json, os, sys
        import ValidateContent as vc

        print("Preparing content packs for validation")
        os.write(1, b"direct fd write\\n")

        captured = vc.read_captured_stdout()
        vc.restore_real_stdout()
        sys.stdout.write(json.dumps(captured))
        """
    )

    assert result.returncode == 0, result.stderr
    captured = json.loads(result.stdout)
    assert "Preparing content packs for validation" in captured
    assert "direct fd write" in captured


def test_real_stdout_context_manager_rearms_the_firewall():
    """
    Given: A `demisto.*` IPC call that needs the real stdout channel.
     When: It runs inside the `real_stdout` context manager.
     Then: Its output reaches stdout, and the firewall is re-armed afterwards so
           subsequent library noise is still suppressed.
    """
    result = _run_in_subprocess(
        """
        import json, os, sys
        import ValidateContent as vc

        with vc.real_stdout():
            sys.stdout.write(json.dumps({"ipc": "call"}) + "\\n")
            sys.stdout.flush()

        # Firewall must be armed again - this must NOT reach stdout.
        os.write(1, b"leak after the ipc call\\n")

        vc.restore_real_stdout()
        """
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip()) == {"ipc": "call"}
    assert "leak" not in result.stdout


def test_wrap_demisto_ipc_routes_calls_to_real_stdout():
    """
    Given: `demisto.debug` / `demisto.getFilePath`, which in the XSOAR runtime
           write to stdout and (for getFilePath) block on a reply.
     When: `_wrap_demisto_ipc` has wrapped them.
     Then: They execute against the real stdout rather than the capture file,
           which is what prevents swallowed logs and a deadlocked file lookup.
    """
    result = _run_in_subprocess(
        """
        import json, os, sys
        import demistomock as demisto
        import ValidateContent as vc

        # Stand in for the runtime implementations, which talk over stdout.
        def fake_debug(msg):
            sys.stdout.write(json.dumps({"debug": msg}) + "\\n")

        def fake_get_file_path(entry_id):
            sys.stdout.write(json.dumps({"getFilePath": entry_id}) + "\\n")
            return {"path": "/tmp/f"}

        demisto.debug = fake_debug
        demisto.getFilePath = fake_get_file_path

        vc._wrap_demisto_ipc()

        demisto.debug("hello")
        # The wrapper must preserve the return value - setup_content_dir relies on it.
        assert demisto.getFilePath("entry-1") == {"path": "/tmp/f"}

        # Library noise in between must still be swallowed.
        os.write(1, b"Packs/Leaked\\n")
        vc.restore_real_stdout()
        """
    )

    assert result.returncode == 0, result.stderr
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert {"debug": "hello"} in lines
    assert {"getFilePath": "entry-1"} in lines
    assert "Packs/Leaked" not in result.stdout


def test_suspended_ipc_prevents_concurrent_library_output_from_escaping():
    """
    Given: `validate_content` runs demisto-sdk on worker threads that write to
           fd 1 at arbitrary moments, while our own code logs via `demisto.*`.
     When: That work runs inside `suspended_ipc`, as it does in `main`.
     Then: Nothing at all reaches stdout. A lock alone is insufficient here - it
           only serializes our code, so any window where fd 1 points at the IPC
           channel could be filled by a library thread, which is precisely the
           corruption this module prevents. Suspending IPC removes the window.
    """
    result = _run_in_subprocess(
        """
        import json, os, sys, threading
        import demistomock as demisto
        import ValidateContent as vc

        def fake_debug(msg):
            sys.stdout.write(json.dumps({"debug": msg}) + "\\n")
            sys.stdout.flush()

        demisto.debug = fake_debug
        vc._wrap_demisto_ipc()

        def logger():
            for i in range(200):
                demisto.debug(i)

        def noisemaker():
            for _ in range(200):
                os.write(1, b"Packs/Noise from a library\\n")

        # Mirrors how main() invokes validate_content().
        with vc.suspended_ipc():
            threads = [threading.Thread(target=logger), threading.Thread(target=noisemaker)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        captured = vc.read_captured_stdout()
        vc.restore_real_stdout()
        # Neither the logs nor the noise may have escaped; both are captured.
        sys.stdout.write(json.dumps({
            "logged": '{"debug": 199}' in captured,
            "noise_captured": "Packs/Noise" in captured,
        }))
        """
    )

    assert result.returncode == 0, result.stderr
    # Exactly one JSON document on stdout - no leaked lines before it.
    summary = json.loads(result.stdout)
    assert summary == {"logged": True, "noise_captured": True}


def test_ipc_is_restored_after_suspension_ends():
    """
    Given: IPC was suspended for the threaded validation run.
     When: The suspension block exits.
     Then: `demisto.*` calls reach the real stdout again, so the final entry can
           still be emitted.
    """
    result = _run_in_subprocess(
        """
        import json, sys
        import demistomock as demisto
        import ValidateContent as vc

        def fake_debug(msg):
            sys.stdout.write(json.dumps({"debug": msg}) + "\\n")

        demisto.debug = fake_debug
        vc._wrap_demisto_ipc()

        with vc.suspended_ipc():
            demisto.debug("suppressed")

        demisto.debug("emitted")
        vc.restore_real_stdout()
        """
    )

    assert result.returncode == 0, result.stderr
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert lines == [{"debug": "emitted"}]


def test_restore_real_stdout_is_idempotent():
    """
    Given: `restore_real_stdout` is called in a `finally` block and may also run
           on the success path.
     When: It is invoked more than once.
     Then: It does not raise or corrupt stdout (a second os.close on the same fd
           would otherwise risk closing an unrelated descriptor).
    """
    result = _run_in_subprocess(
        """
        import json, sys
        import ValidateContent as vc

        vc.restore_real_stdout()
        vc.restore_real_stdout()
        vc.restore_real_stdout()
        sys.stdout.write(json.dumps({"still": "usable"}))
        """
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"still": "usable"}
