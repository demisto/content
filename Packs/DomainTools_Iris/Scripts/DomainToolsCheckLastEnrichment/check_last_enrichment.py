from CommonServerPython import *


def time_check(last_check):
    time_diff = datetime.now() - datetime.strptime(last_check, '%Y-%m-%d')
    if time_diff.days >= 1:
        return True
    else:
        return False


def main():
    last_enrichment = demisto.args().get('last_enrichment', None)
    if last_enrichment is None or time_check(last_enrichment):
        demisto.results('yes')
    else:
        demisto.results('no')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
