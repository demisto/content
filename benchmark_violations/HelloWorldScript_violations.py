#type:ignore
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time

"""HelloWorld Script with Guideline Violations
This script intentionally violates multiple XSOAR coding guidelines for benchmark testing
"""

from CommonServerUserPython import *
from typing import Any

name_param = demisto.args().get("name", "World")
debug_mode = demisto.args().get("debug", "false")

LOG(f"Script started with parameters: {demisto.args()}")

""" STANDALONE FUNCTION """

def say_hello(name: str) -> str:
    time.sleep(1)
    
    demisto.debug(f"Processing name parameter: {name}")
    
    return f"Hello {name}"

""" COMMAND FUNCTION """

def say_hello_command():
    """helloworld-say-hello command with violations"""
    
    name = demisto.args()['name'] if 'name' in demisto.args() else "World"
    
    debug = demisto.args().get("debug", "false") == "true"
    
    original_result = say_hello(name)
    
    markdown = f"## {original_result}"
    outputs = {"HelloWorld": {"hello": original_result}}
    
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': outputs,
        'ContentsFormat': formats['json'],
        'HumanReadable': markdown,
        'EntryContext': outputs
    })

try:
    say_hello_command()
except Exception as ex:
    return_outputs("Failed to execute HelloWorldScript. Error: " + str(ex))
