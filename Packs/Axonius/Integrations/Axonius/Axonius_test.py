"""Axonius Integration for Cortex XSOAR - Unit Tests file."""
import inspect

import axonius_api_client as axonapi


def test_client_exists():
    """Pass."""
    assert inspect.isclass(axonapi.connect.Connect)
