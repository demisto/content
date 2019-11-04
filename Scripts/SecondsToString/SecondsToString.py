import demistomock as demisto
# Taken from https://stackoverflow.com/questions/4048651/python-function-to-convert-seconds-into-minutes-hours-and-days


intervals = (
    ('d', 86400),    # 60 * 60 * 24
    ('h', 3600),    # 60 * 60
    ('m', 60),
    ('s', 1)
)


def display_time(seconds):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result)


def main(value):
    unformatted_time = int(value)
    formatted_time = display_time(unformatted_time)
    return formatted_time


if __name__ == "__builtin__" or __name__ == "builtins":
    demisto.results(main(**demisto.args()))
