def main():
    # Call the main execution of the HTTP API module.
    # This function also allows to add to or override that execution,
    feed_main('Spamhaus')


from HTTPFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
