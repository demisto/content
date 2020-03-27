from HelloWorldScript import say_hello, say_hello_command


def test_say_hello():
    result = say_hello('DBot')

    assert result == 'Hello DBot'


def test_say_hello_command():
    args = {
        'name': 'DBot'
    }

    readable_output, outputs, raw_response = say_hello_command(args)

    assert readable_output == '## Hello DBot'
    assert outputs['HelloWorld']['hello'] == 'Hello DBot'
    assert raw_response == 'Hello DBot'
