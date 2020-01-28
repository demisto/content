from CommonServerPython import *


def main():
    feed_url_to_config = {
        'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt': {
            'fieldnames': ['indicator', 'bambenekconsulting_description',
                           'bambenekconsulting_date',
                           'bambenekconsulting_info'],
            'indicator_type': FeedIndicatorType.IP
        },

        'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt': {
            'fieldnames': ['indicator', 'bambenekconsulting_description',
                           'bambenekconsulting_date',
                           'bambenekconsulting_info'],
            'indicator_type': FeedIndicatorType.Domain
        },
        'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt': {
            'fieldnames': ['indicator', 'bambenekconsulting_description',
                           'bambenekconsulting_date',
                           'bambenekconsulting_info'],
            'indicator_type': FeedIndicatorType.IP
        },
        'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt': {
            'fieldnames': ['indicator', 'bambenekconsulting_description',
                           'bambenekconsulting_date',
                           'bambenekconsulting_info'],
            'indicator_type': FeedIndicatorType.Domain
        }
    }

    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_url_to_config'] = feed_url_to_config
    params['ignore_regex'] = r'^#'
    params['delimiter'] = ','

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main('Bambenek Consulting Feed', params, 'bambenek')


from CSVFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
