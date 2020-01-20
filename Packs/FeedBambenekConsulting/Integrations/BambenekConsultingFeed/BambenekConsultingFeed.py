def main():

    url_to_fieldnames = {
        'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt': ['indicator', 'bambenekconsulting_description',
                                                                          'bambenekconsulting_date',
                                                                          'bambenekconsulting_info'],
        'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt': ['indicator',
                                                                           'bambenekconsulting_description',
                                                                           'bambenekconsulting_date',
                                                                           'bambenekconsulting_info'],
        'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt': ['indicator',
                                                                               'bambenekconsulting_description',
                                                                               'bambenekconsulting_date',
                                                                               'bambenekconsulting_info'],
        'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt': ['indicator',
                                                                                'bambenekconsulting_description',
                                                                                'bambenekconsulting_date',
                                                                                'bambenekconsulting_info']
    }

    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['url_to_fieldnames'] = url_to_fieldnames
    params['ignore_regex'] = r'^#'
    params['delimiter'] = ','

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('Bambenek Consulting Feed', params)


from CSVFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
