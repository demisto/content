import demistomock as demisto  # noqa: F401
import dateparser


def date_to_time_stamp(date: str) -> int:
    date_obj = dateparser.parse(date)
    return int(date_obj.timestamp())  # type: ignore


def main():
    args = demisto.args()
    date_value = str(args['value'])
    demisto.results(date_to_time_stamp(date_value))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
