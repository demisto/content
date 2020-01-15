def main():
    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    params = {k: v for k, v in demisto.params().items() if v is not None}
    feed_main('Bambenek Consulting Feed', params)


from CSVFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
