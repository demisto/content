# __init__.py of cortex_module_test package

def hello():
    return "Hello from cortex module test!"

from . import test_override_csp

# Explicitly expose selected symbols from submodules:
from .test_override_csp import arg_to_number, argToBoolean, argToList, is_integration_command_execution

__all__ = ["arg_to_number", "argToBoolean", "argToList", "is_integration_command_execution"]


# ✅ Inject demisto globally into submodule, if available

if "demisto" in globals():
    test_override_csp.demisto = globals()["demisto"]