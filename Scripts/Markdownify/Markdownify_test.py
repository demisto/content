from Markdownify import markdownify_command


def test_markdownify_command():
    args = {
        'html': '<a href="http://demisto.com">Demisto</a>'
    }

    readable_output, outputs, raw_response = markdownify_command(args)

    assert readable_output == '[Demisto](http://demisto.com)'
    assert raw_response == '[Demisto](http://demisto.com)'
