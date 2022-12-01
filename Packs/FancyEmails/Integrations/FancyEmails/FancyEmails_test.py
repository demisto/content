import json
import io
import pytest
import FancyEmails


def check_module():
    return FancyEmails.main() == 'ok'


def fail_this_module():
    raise Exception('TEST FAILURE')

