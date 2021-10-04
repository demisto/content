import demistomock as demisto
from datetime import datetime, timezone


def date_to_epoch(date, formatter):
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    date_obj = datetime.strptime(date, formatter)
    return int(date_obj.strftime('%s') if date_obj.tzinfo is None else (date_obj - epoch).total_seconds())


def main():
    args = demisto.args()
    date_value = args['value']
    formatter = args['formatter']
    demisto.results(date_to_epoch(date_value, formatter))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
