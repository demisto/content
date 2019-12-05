import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def say_hello(name):
    return f'Hello {name}'


def say_hello_command(args):
    name = args.get('name')

    original_result = say_hello(name)

    markdown = f'## {original_result}'
    outputs = {
        'HelloWorld': {
            'hello': original_result
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
        return_error(f'Failed to execute HelloWorldScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
