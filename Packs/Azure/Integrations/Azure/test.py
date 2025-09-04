#!/usr/bin/env python3

import inspect

def get_caller_name():
    frame = inspect.currentframe()
    try:
        return frame.f_back.f_code.co_name
    finally:
        del frame

def another_function():
    caller = get_caller_name()
    print(f"Caller is: {caller}")

# Test it
another_function()