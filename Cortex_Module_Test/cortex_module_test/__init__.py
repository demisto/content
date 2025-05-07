def hello():
    return "Hello from cortex module test!"


# cortex-module-test imports:
from .test_override_csp import arg_to_number


__all__ = ["arg_to_number"]