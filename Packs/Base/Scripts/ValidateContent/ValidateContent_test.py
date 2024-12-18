import json
import os
import tempfile
import zipfile
import git
import pytest

from ValidateContent import CONTENT_REPO_URL, HOOK_ID_TO_PATTERN, get_extracted_code_filepath, get_file_name_and_contents, get_pack_name, read_json_results, read_pre_commit_results, read_validate_results, run_validate, setup_content_dir, setup_content_repo, strip_ansi_codes, extract_hook_id, parse_pre_commit_output, get_skipped_hooks, DEFAULT_ERROR_PATTERN


def test_strip_ansi_codes():
    ansi_text = "\033[31mRed text\033[0m"
    assert strip_ansi_codes(ansi_text) == "Red text"

def test_extract_hook_id():
    output = "Running hook: check-ast\n- hook id: check-ast\nAn error occurred"
    assert extract_hook_id(output) == "check-ast"
    assert extract_hook_id("No hook id") is None

def test_parse_pre_commit_output_check_ast():
    output = """check python ast.........................................................Failed
- hook id: check-ast
- exit code: 1

Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py: failed parsing with CPython 3.11.10:

 Traceback (most recent call last):
 File "/root/.cache/pre-commit/repopc0svvoh/py_env-python3.11/lib/python3.11/site-packages/pre_commit_hooks/check_ast.py", line 21, in main
 ast.parse(f.read(), filename=filename)
 File "/usr/local/lib/python3.11/ast.py", line 50, in parse
 return compile(source, filename, mode, flags,
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 File "Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py", line 1413
 elif command == 'hello
 ^
 SyntaxError: unterminated string literal (detected at line 1413)"""
 
    pattern_obj = HOOK_ID_TO_PATTERN['check-ast']
    result = parse_pre_commit_output(output, pattern_obj)
    assert result == [{'file': 'Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py', 'line': '1413'}]

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
    pattern_obj = HOOK_ID_TO_PATTERN['mypy']
    result = parse_pre_commit_output(output, pattern_obj)
    assert result == [
        {
            'file': 'Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py',
            'line': '791',
            'details': '''Name
"greet" is not defined  [name-defined]
        greet(inp)
        ^'''
        },
        {
            'file': 'Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py',
            'line': '791',
            'details': '''Name
"inp" is not defined  [name-defined]
        greet(inp)
              ^'''
        },
        {
            'file': 'Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py',
            'line': '794',
            'details': '''Name
"by" is not defined  [name-defined]
        by({'arrrr': 'rrrrra', 'rrrraa': 'rapapapu'})
        ^'''
        }
    ]


