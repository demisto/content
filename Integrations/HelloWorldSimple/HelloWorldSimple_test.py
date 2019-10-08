from HelloWorldSimple import say_hello_command


def test_say_hello():
    args = {
        'name': 'Dbot'
    }
    result = say_hello_command(args)

    assert result == '## Hello Dbot'
