import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    args = demisto.args()
    the_val = args.get('value')
    try:
        the_csv = ','.join(the_val)
        return_results(the_csv)
    except Exception as ex:
        demisto.debug('Ooops, Something aint working!')
        LOG.print_log()
        demisto.debug(ex)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
