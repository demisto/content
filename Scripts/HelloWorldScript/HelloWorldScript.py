import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def say_hello(name):
    return "Hello {}".format(name)


def say_hello_command(args):
    name = args.get("name")

    original_result = say_hello(name)

    markdown = "## {}".format(original_result)
    outputs = {
        "HelloWorld": {
            "hello": original_result
        }
    }

    return (
        markdown,
        outputs,
        original_result
    )


def main():
    try:
        return_outputs(*say_hello_command(demisto.args()))
    except Exception as ex:
        return_error("Failed to execute HelloWorldScript. Error: {}".format(str(ex)))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
