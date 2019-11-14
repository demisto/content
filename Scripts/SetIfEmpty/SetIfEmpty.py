import demistomock as demisto


def get_value_to_set(args):
    value = args.get('value')
    apply_if_empty = True if args.get('applyIfEmpty', '').lower() == 'true' else False

    if value is None or (apply_if_empty and len(value) < 1):
        value = args.get('defaultValue')

    return value


def main(args):
    demisto.results(get_value_to_set(args))


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())
